//! Gzip streams. A stream holding a tar is walked as that tar, one nesting
//! level with the gzip around it (`backup.tar.gz!/config/app.ini`); any other
//! stream is one member, named by the name stored in its header or else after
//! the file (`app.log.gz!/app.log`).
//!
//! The stream is inflated into memory first, counted as it goes and stopped at
//! the walk's budget, so a bomb never gets further than that. Every gzip member
//! of a multi-member file is read as one stream, as `gunzip` does. Bytes after
//! the last one count as not read unless they are zero padding.

use super::tar::{is_tar, outside, TAR};
use super::{ContainerError, Extractor, Hidden, MemberMeta, StreamLimits, Walk, RATIO_FLOOR};
use crate::classify::{ends_with_ignore_case, Budgeted, Source};
use std::cell::Cell;
use std::io::{BufRead, BufReader, Read};

/// Bytes a stored name or comment may take, as other gzip readers bound them.
const FIELD_MAX: u64 = 65535;

const DAMAGED: &str = "gzip stream ends early or is corrupt";

pub struct Gzip;

pub static GZIP: Gzip = Gzip;

/// How inflating ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Whole,
    Damaged,
    /// Stopped at this limit, by its configuration key.
    Over(&'static str),
}

/// A gzip member's header.
struct Header {
    extra: Vec<u8>,
    name: Option<Vec<u8>>,
    comment: Vec<u8>,
    /// Bytes it takes in the file.
    len: u64,
}

/// A zero-terminated header field, without its terminator.
fn field(r: &mut impl BufRead) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    r.take(FIELD_MAX + 1).read_until(0, &mut v).ok()?;
    (v.pop() == Some(0)).then_some(v)
}

fn header(r: &mut impl BufRead) -> Option<Header> {
    let mut fixed = [0u8; 10];
    r.read_exact(&mut fixed).ok()?;
    let flags = fixed[3];
    if fixed[..3] != [0x1F, 0x8B, 8] || flags & 0xE0 != 0 {
        return None;
    }
    let mut h = Header {
        extra: Vec::new(),
        name: None,
        comment: Vec::new(),
        len: 10,
    };
    if flags & 0x04 != 0 {
        let mut n = [0u8; 2];
        r.read_exact(&mut n).ok()?;
        h.extra = vec![0; usize::from(u16::from_le_bytes(n))];
        r.read_exact(&mut h.extra).ok()?;
        h.len += 2 + h.extra.len() as u64;
    }
    if flags & 0x08 != 0 {
        let name = field(r)?;
        h.len += name.len() as u64 + 1;
        h.name = Some(name);
    }
    if flags & 0x10 != 0 {
        h.comment = field(r)?;
        h.len += h.comment.len() as u64 + 1;
    }
    if flags & 0x02 != 0 {
        r.read_exact(&mut [0u8; 2]).ok()?;
        h.len += 2;
    }
    Some(h)
}

/// A stream inflated into memory.
struct Inflated {
    bytes: Vec<u8>,
    /// The name stored in the first header.
    name: Option<String>,
    /// Header fields that are not the member's name: comments, extra fields,
    /// and later members' names, one per line.
    fields: Vec<u8>,
    /// Compressed bytes read.
    consumed: u64,
    end: End,
    /// Bytes after the last gzip member that are not zero padding.
    after: u64,
}

/// The inflate state and output buffer, kept across gzip members: a file can
/// hold a great many small ones.
struct Inflater {
    state: flate2::Decompress,
    chunk: Vec<u8>,
}

/// Inflate one gzip member's data onto `out` up to the limits; its trailer is
/// checked when its data ended.
fn member_data(
    r: &mut impl BufRead,
    out: &mut Vec<u8>,
    consumed: &mut u64,
    limits: StreamLimits,
    expired: &dyn Fn() -> bool,
    inflater: &mut Inflater,
) -> End {
    let Inflater {
        state: inflate,
        chunk,
    } = inflater;
    inflate.reset(false);
    let mut crc = flate2::Crc::new();
    loop {
        if expired() {
            return End::Over("limits.time_budget_ms");
        }
        let Ok(input) = r.fill_buf() else {
            return End::Damaged;
        };
        let (was_in, was_out) = (inflate.total_in(), inflate.total_out());
        let flush = flate2::FlushDecompress::None;
        let Ok(status) = inflate.decompress(input, chunk, flush) else {
            return End::Damaged;
        };
        let used = (inflate.total_in() - was_in) as usize;
        let made = (inflate.total_out() - was_out) as usize;
        r.consume(used);
        *consumed += used as u64;
        crc.update(&chunk[..made]);
        let room = limits.bytes.saturating_sub(out.len() as u64);
        out.extend_from_slice(&chunk[..made.min(room as usize)]);
        if made as u64 > room {
            return End::Over("limits.container_bytes");
        }
        let total = out.len() as u64;
        if total > RATIO_FLOOR && total > consumed.saturating_mul(limits.ratio) {
            return End::Over("limits.container_ratio");
        }
        if status == flate2::Status::StreamEnd {
            break;
        }
        if used == 0 && made == 0 {
            return End::Damaged;
        }
    }
    let mut trailer = [0u8; 8];
    if r.read_exact(&mut trailer).is_err() {
        return End::Damaged;
    }
    *consumed += 8;
    let (sum, len) = trailer.split_at(4);
    if sum != crc.sum().to_le_bytes() || len != crc.amount().to_le_bytes() {
        return End::Damaged;
    }
    End::Whole
}

fn inflate(
    src: &dyn Source,
    size: u64,
    limits: StreamLimits,
    expired: &dyn Fn() -> bool,
) -> Result<Inflated, ContainerError> {
    let left = Cell::new(u64::MAX);
    let over = Cell::new(false);
    let mut r = BufReader::with_capacity(65536, Budgeted::new(src, size, &left, &over));
    let first = header(&mut r).ok_or_else(|| ContainerError("gzip header unreadable".into()))?;
    let mut out = Inflated {
        bytes: Vec::new(),
        name: first
            .name
            .as_deref()
            .filter(|n| !n.is_empty())
            .map(|n| String::from_utf8_lossy(n).into_owned()),
        fields: Vec::new(),
        consumed: first.len,
        end: End::Whole,
        after: 0,
    };
    let first_name = first.name.clone();
    let mut h = first;
    let mut inflater = Inflater {
        state: flate2::Decompress::new(false),
        chunk: vec![0u8; 65536],
    };
    loop {
        // The first name is the member's, and a later name that repeats it (as
        // concatenating a file with itself does) says nothing new.
        let name = h.name.as_ref().filter(|n| Some(*n) != first_name.as_ref());
        for part in [&h.extra, &h.comment, name.unwrap_or(&Vec::new())] {
            // Counted with the stream, so a file of many small members holding
            // long fields stops at the same budget.
            if !part.is_empty() {
                out.fields.extend_from_slice(part);
                out.fields.push(b'\n');
            }
        }
        if out.fields.len() as u64 > limits.bytes {
            out.fields.truncate(limits.bytes as usize);
            out.end = End::Over("limits.container_bytes");
            return Ok(out);
        }
        out.end = member_data(
            &mut r,
            &mut out.bytes,
            &mut out.consumed,
            limits,
            expired,
            &mut inflater,
        );
        if out.end != End::Whole {
            return Ok(out);
        }
        let at = out.consumed;
        match r.fill_buf() {
            Ok([]) => return Ok(out),
            Ok(_) => {}
            Err(_) => {
                out.end = End::Damaged;
                return Ok(out);
            }
        }
        match header(&mut r) {
            Some(next) => {
                out.consumed += next.len;
                h = next;
            }
            None => {
                out.after = outside(src, size, at);
                return Ok(out);
            }
        }
    }
}

/// The member name for a stream with no stored name, from the container's own:
/// `app.log.gz` holds `app.log`, `x.tgz` holds `x.tar`, as `gunzip` names them.
fn name_from(container: &str) -> String {
    let base = container.rsplit('/').next().unwrap_or(container);
    let named = if ends_with_ignore_case(base, ".tgz") {
        format!("{}.tar", &base[..base.len() - 4])
    } else if ends_with_ignore_case(base, ".gz") {
        base[..base.len() - 3].to_string()
    } else {
        base.to_string()
    };
    if named.is_empty() {
        "data".into()
    } else {
        named
    }
}

impl Extractor for Gzip {
    fn id(&self) -> &'static str {
        "gzip"
    }

    fn version(&self) -> u32 {
        1
    }

    fn extract(
        &self,
        src: &dyn Source,
        size: u64,
        walk: &mut dyn Walk,
    ) -> Result<(), ContainerError> {
        let limits = walk.stream_limits();
        let s = {
            let w: &dyn Walk = walk;
            inflate(src, size, limits, &|| w.expired())?
        };
        // The stream's end explains whatever a tar in it then lacked.
        let ended = match s.end {
            End::Whole => None,
            End::Damaged => Some(ContainerError(DAMAGED.into())),
            End::Over(key) => Some(ContainerError(format!("gzip stream not read past {key}"))),
        };
        if let (true, Some(e)) = (s.bytes.is_empty(), &ended) {
            return Err(e.clone());
        }
        walk.unaccounted(s.after);
        let result = if is_tar(&s.bytes) {
            let walked = TAR.extract(&&s.bytes[..], s.bytes.len() as u64, walk);
            ended.map_or(walked, Err)
        } else {
            let name = s.name.unwrap_or_else(|| name_from(walk.own_name()));
            let meta = MemberMeta {
                name,
                declared_size: None,
                compressed_size: Some(s.consumed),
            };
            walk.member(meta, &mut &s.bytes[..]);
            // Past a limit the walk has already seen the bytes run over it; this
            // holds whatever the limits were.
            if ended.is_some() && walk.read_to_end() {
                walk.hidden(Hidden::Damaged);
            }
            Ok(())
        };
        if !s.fields.is_empty() {
            walk.comment(None, &mut &s.fields[..]);
        }
        result
    }
}
