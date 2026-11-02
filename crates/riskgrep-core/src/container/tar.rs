//! Tar archives: ustar, GNU, PAX, and old-style headers. Every use of the
//! `tar` crate's API is in this module.
//!
//! A tar has no directory, so the walk reads each header in turn and seeks over
//! data it does not need. Links and device entries hold nothing to read: they
//! are never followed, and take a position counted as skipped. Directories are
//! not members, as in a zip. Member names are only names: nothing is unpacked.

use super::{ContainerError, Extractor, Flow, Hidden, MemberMeta, Walk};
use crate::classify::{Budgeted, Source};
use std::cell::Cell;
use std::io::{Read, Seek, SeekFrom};

const BLOCK: u64 = 512;

/// Bytes one entry's GNU long names and PAX records may take to read.
const EXTENDED_MAX: u64 = 1 << 20;

/// Bytes of PAX comment and vendor records kept to scan; past this they count
/// as not read.
const RECORDS_MAX: usize = 1 << 20;

/// Bytes after the end of an archive checked for being zero padding (a blocking
/// factor pads to 10 KiB by default). Past this they count as not read.
const TAIL_MAX: u64 = 1 << 20;

/// PAX records that describe a file rather than hold anything of their own.
const METADATA: [&[u8]; 12] = [
    b"path",
    b"linkpath",
    b"size",
    b"uid",
    b"gid",
    b"uname",
    b"gname",
    b"mtime",
    b"atime",
    b"ctime",
    b"charset",
    b"hdrcharset",
];

pub struct Tar;

pub static TAR: Tar = Tar;

/// Whether `head`, a file's first bytes, is a tar header: the `ustar` magic, or
/// an old-style header, which has no magic but whose checksum holds.
pub fn is_tar(head: &[u8]) -> bool {
    head.get(257..262) == Some(b"ustar") || is_old_style(head)
}

fn is_old_style(head: &[u8]) -> bool {
    let Some(block) = head.get(..BLOCK as usize) else {
        return false;
    };
    if block[0] == 0 {
        return false;
    }
    let field = block[148..156].trim_ascii_start();
    let field = &field[..field
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(field.len())];
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let declared = field.iter().fold(0u32, |n, &b| n * 8 + u32::from(b - b'0'));
    let sum: u32 = block[..148]
        .iter()
        .chain(&block[156..])
        .map(|&b| u32::from(b))
        .sum();
    declared == sum + 8 * u32::from(b' ')
}

/// Bytes of `src` from `from` on that are not zero padding: all of them, when
/// any is not zero or there are too many to check.
pub(super) fn outside(src: &dyn Source, size: u64, from: u64) -> u64 {
    let rest = size.saturating_sub(from);
    if rest == 0 {
        return 0;
    }
    let zero = rest <= TAIL_MAX
        && src
            .range(from, rest)
            .is_ok_and(|b| b.iter().all(|&x| x == 0));
    if zero {
        0
    } else {
        rest
    }
}

/// A [`Budgeted`] reader that notes reaching the end of the file. A walk that
/// ends at its end marker never does.
struct Tracked<'a> {
    inner: Budgeted<'a, dyn Source + 'a>,
    ended: &'a Cell<bool>,
}

impl Read for Tracked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && !buf.is_empty() {
            self.ended.set(true);
        }
        Ok(n)
    }
}

impl Seek for Tracked<'_> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// The PAX comment and vendor records of an archive, scanned together as its
/// comment.
#[derive(Default)]
struct Records {
    text: Vec<u8>,
    /// Bytes not kept, or that could not be parsed.
    not_kept: u64,
}

impl Records {
    fn add(&mut self, records: tar::PaxExtensions<'_>) {
        for record in records {
            let Ok(r) = record else {
                self.not_kept += 1;
                continue;
            };
            let (key, value) = (r.key_bytes(), r.value_bytes());
            if METADATA.contains(&key) || key.starts_with(b"GNU.sparse.") {
                continue;
            }
            let len = key.len() + value.len() + 2;
            if self.text.len() + len > RECORDS_MAX {
                self.not_kept += len as u64;
                continue;
            }
            self.text.extend_from_slice(key);
            self.text.push(b'=');
            self.text.extend_from_slice(value);
            self.text.push(b'\n');
        }
    }

    fn offer(self, walk: &mut dyn Walk) {
        walk.unaccounted(self.not_kept);
        if !self.text.is_empty() {
            walk.comment(None, &mut &self.text[..]);
        }
    }
}

impl Extractor for Tar {
    fn id(&self) -> &'static str {
        "tar"
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
        let unreadable = || ContainerError("tar header unreadable".into());
        let left = Cell::new(EXTENDED_MAX);
        let over = Cell::new(false);
        let ended = Cell::new(false);
        let reader = Tracked {
            inner: Budgeted::new(src, size, &left, &over),
            ended: &ended,
        };
        let mut archive = tar::Archive::new(reader);
        let mut records = Records::default();
        // Where the walk stopped offering members, and why it could not go on.
        let mut stopped: Option<u64> = None;
        let mut broken: Option<ContainerError> = None;
        {
            let mut entries = archive.entries_with_seek().map_err(|_| unreadable())?;
            loop {
                if walk.expired() {
                    records.offer(walk);
                    return Err(ContainerError("timeout".into()));
                }
                left.set(EXTENDED_MAX);
                let mut entry = match entries.next() {
                    None => break,
                    Some(Ok(e)) => e,
                    Some(Err(_)) => {
                        broken = Some(if over.get() {
                            ContainerError(format!("tar extended header over {EXTENDED_MAX} bytes"))
                        } else {
                            unreadable()
                        });
                        break;
                    }
                };
                // Member data is bounded by the walk, not by this reader.
                left.set(u64::MAX);
                let kind = entry.header().entry_type();
                let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
                let sparse = kind.is_gnu_sparse();
                let stored = if sparse {
                    entry.header().entry_size().unwrap_or(0)
                } else {
                    entry.size()
                };
                let data_end = entry.raw_file_position().saturating_add(stored);
                let next = data_end.saturating_add(BLOCK - 1) & !(BLOCK - 1);
                // On an extended header itself this would read all its data, with
                // no budget; those are handled below.
                if !kind.is_pax_global_extensions() && !kind.is_pax_local_extensions() {
                    if let Ok(Some(local)) = entry.pax_extensions() {
                        records.add(local);
                    }
                }
                let flow = if kind.is_pax_global_extensions() {
                    let mut data = Vec::new();
                    let read = (&mut entry).take(EXTENDED_MAX).read_to_end(&mut data);
                    if read.is_err() || stored > EXTENDED_MAX {
                        walk.unaccounted(stored.saturating_sub(data.len() as u64));
                    }
                    records.add(tar::PaxExtensions::new(&data));
                    Flow::Continue
                } else if kind.is_dir() || (kind.is_file() && name.ends_with('/') && stored == 0) {
                    walk.unaccounted(stored);
                    Flow::Continue
                } else if kind.is_symlink()
                    || kind.is_hard_link()
                    || kind.is_character_special()
                    || kind.is_block_special()
                    || kind.is_fifo()
                {
                    walk.unaccounted(stored);
                    walk.without_data()
                } else if kind.is_pax_local_extensions()
                    || kind.is_gnu_longname()
                    || kind.is_gnu_longlink()
                {
                    // Reached only under a header the crate does not treat as
                    // one of these: its names and records were not used.
                    walk.unaccounted(stored);
                    Flow::Continue
                } else {
                    let declared_size = Some(entry.size());
                    let meta = MemberMeta {
                        name,
                        declared_size,
                        compressed_size: None,
                    };
                    let flow = walk.member(meta, &mut entry);
                    if walk.read_to_end() {
                        if data_end > size {
                            walk.hidden(Hidden::Damaged);
                        } else if !sparse {
                            match outside(src, next, data_end) {
                                0 => {}
                                pad => walk.hidden(Hidden::PastData(pad)),
                            }
                        }
                    }
                    flow
                };
                if flow == Flow::Stop {
                    stopped = Some(next);
                    break;
                }
            }
        }
        let mut reader = archive.into_inner();
        let end = match stopped {
            Some(next) => Some(next),
            None if broken.is_some() => None,
            None if ended.get() => {
                broken = Some(ContainerError("tar ended before its end marker".into()));
                None
            }
            None => reader.stream_position().ok(),
        };
        if let Some(from) = end {
            walk.unaccounted(outside(src, size, from));
        }
        records.offer(walk);
        broken.map_or(Ok(()), Err)
    }
}
