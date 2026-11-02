//! Zip archives, and the formats built on them (jar, docx, xlsx, wheels).
//! Every use of the `zip` crate's API is in this module.

use super::{ContainerError, Extractor, Flow, MemberMeta, NotRead, Walk};
use crate::classify::{Budgeted, Source};
use std::cell::Cell;
use std::io::BufReader;

/// Bytes the central directory may take to find and parse (the end record
/// is searched for backwards from the end of the file).
const DIRECTORY_MAX: u64 = 8_388_608;

/// Longest deflate stream a directory entry may hold and still count as
/// empty. Encoders write 2 bytes (a fixed block) or 5 (an empty stored block).
const EMPTY_DEFLATE_MAX: u64 = 64;

pub struct Zip;

/// Entry `i`'s stored name; empty when it is missing or cannot be decoded.
fn entry_name<R: std::io::Read + std::io::Seek>(zip: &zip::ZipArchive<R>, i: usize) -> String {
    zip.name_for_index(i)
        .and_then(Result::ok)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

/// An entry as the central directory and its local header describe it.
struct Entry {
    name: String,
    is_dir: bool,
    /// Offset of the local header, and of the byte after the entry's data.
    start: u64,
    data_end: u64,
    crc: u32,
    size: u64,
    compressed: u64,
    encrypted: bool,
    /// Bytes a directory entry holds that are not an empty stream: no member
    /// is offered for it, so they are not read.
    stray: u64,
    /// The entry's comment; empty when it has none.
    comment: Vec<u8>,
}

/// The comment bytes stored in the central header at `at`, undecoded, so a
/// comment is read like an archive comment whatever encoding it claims.
fn stored_comment(src: &dyn Source, at: u64) -> Option<Vec<u8>> {
    let head = src.range(at, 46).ok()?;
    if !head.starts_with(b"PK\x01\x02") {
        return None;
    }
    let le16 = |i: usize| u64::from(u16::from_le_bytes([head[i], head[i + 1]]));
    src.range(at + 46 + le16(28) + le16(30), le16(32)).ok()
}

/// Whether the `compressed` bytes at `start` hold nothing: there are none, or
/// they are one deflate stream that inflates to nothing and ends with them.
/// Some encoders deflate directory entries too (`JarOutputStream`).
fn holds_nothing(src: &dyn Source, deflated: bool, start: u64, compressed: u64) -> bool {
    if compressed == 0 {
        return true;
    }
    if !deflated || compressed > EMPTY_DEFLATE_MAX {
        return false;
    }
    let Ok(data) = src.range(start, compressed) else {
        return false;
    };
    let mut inflate = flate2::Decompress::new(false);
    let ended = inflate.decompress(&data, &mut [0u8; 1], flate2::FlushDecompress::Finish);
    matches!(ended, Ok(flate2::Status::StreamEnd))
        && inflate.total_out() == 0
        && inflate.total_in() == compressed
}

/// Whether `gap`, the bytes right after `e`'s data, is `e`'s data
/// descriptor: an optional signature, then its CRC-32 and sizes (4 bytes
/// each, or 8 for zip64).
fn is_descriptor(gap: &[u8], e: &Entry) -> bool {
    let body = gap.strip_prefix(b"PK\x07\x08").unwrap_or(gap);
    let le = |b: &[u8]| b.iter().rev().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let fits = |w: usize| {
        body.len() == 4 + 2 * w
            && le(&body[..4]) == u64::from(e.crc)
            && le(&body[4..4 + w]) == e.compressed
            && le(&body[4 + w..]) == e.size
    };
    fits(4) || fits(8)
}

/// Bytes before the central directory that no entry covers (data ahead of
/// the first entry, an entry the central directory does not list, such as
/// one hidden by a later entry of the same name, anything between entries
/// other than a data descriptor, or bytes held by a directory entry).
fn unaccounted(src: &dyn Source, entries: &[Option<Entry>], directory: u64) -> u64 {
    let mut spans: Vec<&Entry> = entries.iter().flatten().collect();
    spans.sort_by_key(|e| e.start);
    let mut missing = spans.iter().fold(0u64, |n, e| n.saturating_add(e.stray));
    let mut cursor = 0u64;
    let mut prev: Option<&Entry> = None;
    let gap = |from: u64, to: u64, prev: Option<&Entry>| {
        if to <= from {
            return 0;
        }
        let described = to - from <= 28
            && prev.is_some_and(|p| {
                src.range(from, to - from)
                    .is_ok_and(|g| is_descriptor(&g, p))
            });
        if described {
            0
        } else {
            to - from
        }
    };
    for e in spans {
        missing += gap(cursor, e.start, prev);
        if e.data_end > cursor {
            cursor = e.data_end;
            prev = Some(e);
        }
    }
    missing + gap(cursor, directory, prev)
}

/// Bytes from the central directory on that are not its `listed` entries,
/// a fixed-size zip64 end record and locator, or the end record and its
/// comment. The entries are walked rather than trusting the end record's
/// directory size, and zip64 extensible data is not read, so hidden bytes
/// cannot be claimed as directory. Only a directory that fits the budget can
/// have opened, so bytes past [`DIRECTORY_MAX`] are not read and count as
/// outside.
fn after_directory(src: &dyn Source, size: u64, directory: u64, listed: usize) -> u64 {
    let total = size.saturating_sub(directory);
    let Ok(buf) = src.range(directory, total.min(DIRECTORY_MAX)) else {
        return total;
    };
    let le16 = |at: usize| usize::from(u16::from_le_bytes([buf[at], buf[at + 1]]));
    let at_sig = |at: usize, sig: &[u8]| buf.get(at..).is_some_and(|b| b.starts_with(sig));
    let mut pos = 0;
    for _ in 0..listed {
        if !at_sig(pos, b"PK\x01\x02") || pos + 46 > buf.len() {
            break;
        }
        pos += 46 + le16(pos + 28) + le16(pos + 30) + le16(pos + 32);
    }
    if at_sig(pos, b"PK\x06\x06") && at_sig(pos + 56, b"PK\x06\x07") {
        pos += 56;
    }
    if at_sig(pos, b"PK\x06\x07") {
        pos += 20;
    }
    let walked = pos.min(buf.len());
    // What follows the walk, less the end record: right there, or else the
    // last one in it.
    let rest = &buf[walked..];
    let sig = b"PK\x05\x06";
    let at = if rest.starts_with(sig) {
        Some(0)
    } else {
        rest.windows(4).rposition(|w| w == sig)
    };
    let end = at.filter(|at| at + 22 <= rest.len()).map_or(0, |at| {
        let comment = usize::from(u16::from_le_bytes([rest[at + 20], rest[at + 21]]));
        (22 + comment).min(rest.len() - at)
    });
    total - walked as u64 - end as u64
}

pub static ZIP: Zip = Zip;

impl Extractor for Zip {
    fn id(&self) -> &'static str {
        "zip"
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
        let left = Cell::new(DIRECTORY_MAX);
        let over = Cell::new(false);
        let open = |offset| {
            let reader = BufReader::with_capacity(8192, Budgeted::new(src, size, &left, &over));
            zip::ZipArchive::with_config(
                zip::read::Config {
                    archive_offset: offset,
                },
                reader,
            )
        };
        // Detecting the offset reads every byte before the end record, so
        // it is tried only when the directory is not where the end record
        // says, and then within what is left of the same budget. Bytes
        // ahead of the archive are covered by no member, so such an archive
        // is never `scanned`.
        let opened = open(zip::read::ArchiveOffset::Known(0))
            .or_else(|_| open(zip::read::ArchiveOffset::Detect));
        let mut zip = match opened {
            Ok(z) if !over.get() => z,
            _ if over.get() => {
                return Err(ContainerError(format!(
                    "zip central directory not read within {DIRECTORY_MAX} bytes"
                )))
            }
            _ => return Err(ContainerError("zip central directory unreadable".into())),
        };
        // Member data is bounded by the walk (bytes produced, ratio,
        // deadline), not by this reader.
        left.set(u64::MAX);
        let n = zip.len();
        // Headers are read up front for the coverage check; past the
        // deadline the walk stops at its first member anyway, so the check
        // is skipped rather than allowed to overrun.
        let mut complete = true;
        let entries: Vec<Option<Entry>> = (0..n)
            .map(|i| {
                if !complete || (i % 256 == 0 && walk.expired()) {
                    complete = false;
                    return None;
                }
                let name = entry_name(&zip, i);
                let f = zip.by_index_raw(i).ok()?;
                let data_start = f.data_start()?;
                let compressed = f.compressed_size();
                let is_dir = name.ends_with('/') && f.size() == 0;
                let deflated =
                    f.compression() == zip::CompressionMethod::Deflated && !f.encrypted();
                let stray = if is_dir && !holds_nothing(src, deflated, data_start, compressed) {
                    compressed.min(size.saturating_sub(data_start))
                } else {
                    0
                };
                let comment = match f.comment() {
                    "" => Vec::new(),
                    decoded => stored_comment(src, f.central_header_start())
                        .unwrap_or_else(|| decoded.as_bytes().to_vec()),
                };
                Some(Entry {
                    is_dir,
                    name,
                    start: f.header_start(),
                    data_end: data_start.checked_add(compressed)?,
                    crc: f.crc32(),
                    size: f.size(),
                    compressed,
                    encrypted: f.encrypted(),
                    stray,
                    comment,
                })
            })
            .collect();
        let archive_comment = u64::from(!zip.comment().is_empty());
        let comments = entries
            .iter()
            .flatten()
            .filter(|e| !e.comment.is_empty())
            .count() as u64;
        if !complete {
            // A directory entry not examined may hold a comment, like a
            // file: both count, so the archive is not reported whole.
            let unknown = (0..n)
                .filter(|&i| !entry_name(&zip, i).ends_with('/') || entries[i].is_none())
                .count() as u64;
            walk.rest(unknown + comments + archive_comment);
            return Ok(());
        }
        let directory = zip.central_directory_start();
        walk.unaccounted(
            unaccounted(src, &entries, directory) + after_directory(src, size, directory, n),
        );
        let comment = zip.comment().to_vec();
        let is_member = |e: &Option<Entry>| !e.as_ref().is_some_and(|e| e.is_dir);
        // Members and comments not offered yet.
        let mut left =
            entries.iter().filter(|e| is_member(e)).count() as u64 + comments + archive_comment;
        for (i, entry) in entries.iter().enumerate() {
            if is_member(entry) {
                left -= 1;
                let flow = match entry {
                    None => walk.not_read(
                        MemberMeta {
                            name: entry_name(&zip, i),
                            declared_size: None,
                            compressed_size: None,
                        },
                        NotRead::Corrupt,
                    ),
                    Some(e) => {
                        let meta = MemberMeta {
                            name: e.name.clone(),
                            declared_size: Some(e.size),
                            compressed_size: Some(e.compressed),
                        };
                        if e.encrypted {
                            walk.not_read(meta, NotRead::Encrypted)
                        } else {
                            match zip.by_index(i) {
                                Ok(mut f) => walk.member(meta, &mut f),
                                Err(zip::result::ZipError::UnsupportedArchive(m))
                                    if m == zip::result::ZipError::PASSWORD_REQUIRED =>
                                {
                                    walk.not_read(meta, NotRead::Encrypted)
                                }
                                Err(zip::result::ZipError::UnsupportedArchive(_)) => {
                                    walk.not_read(meta, NotRead::Unsupported)
                                }
                                Err(_) => walk.not_read(meta, NotRead::Corrupt),
                            }
                        }
                    }
                };
                if flow == Flow::Stop {
                    walk.rest(left);
                    return Ok(());
                }
            }
            if let Some(e) = entry.as_ref().filter(|e| !e.comment.is_empty()) {
                left -= 1;
                if walk.comment(Some(&e.name), &mut &e.comment[..]) == Flow::Stop {
                    walk.rest(left);
                    return Ok(());
                }
            }
        }
        if !comment.is_empty() {
            walk.comment(None, &mut &comment[..]);
        }
        Ok(())
    }
}
