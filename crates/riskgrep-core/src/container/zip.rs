//! Zip archives, and the formats built on them (jar, docx, xlsx, wheels).
//! Every use of the `zip` crate's API is in this module.

use super::{ContainerError, Extractor, Flow, MemberMeta, NotRead, Walk};
use crate::classify::{Budgeted, Source};
use std::cell::Cell;
use std::io::BufReader;

/// Bytes the central directory may take to find and parse (the end record
/// is searched for backwards from the end of the file).
const DIRECTORY_MAX: u64 = 8_388_608;

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
/// one hidden by a later entry of the same name, or anything between
/// entries other than a data descriptor). The archive comment is scanned
/// on its own.
fn unaccounted(src: &dyn Source, entries: &[Option<Entry>], directory: u64) -> u64 {
    let mut spans: Vec<&Entry> = entries.iter().flatten().collect();
    spans.sort_by_key(|e| e.start);
    let mut missing = 0;
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
            let reader = BufReader::with_capacity(
                8192,
                Budgeted {
                    src,
                    size,
                    pos: 0,
                    left: &left,
                    over: &over,
                },
            );
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
                Some(Entry {
                    is_dir: name.ends_with('/') && f.size() == 0,
                    name,
                    start: f.header_start(),
                    data_end: f.data_start()?.checked_add(f.compressed_size())?,
                    crc: f.crc32(),
                    size: f.size(),
                    compressed: f.compressed_size(),
                    encrypted: f.encrypted(),
                })
            })
            .collect();
        if !complete {
            let files = (0..n)
                .filter(|&i| !entry_name(&zip, i).ends_with('/'))
                .count();
            walk.rest(files as u64 + u64::from(!zip.comment().is_empty()));
            return Ok(());
        }
        walk.unaccounted(unaccounted(src, &entries, zip.central_directory_start()));
        let comment = zip.comment().to_vec();
        let offered: Vec<usize> = (0..n)
            .filter(|&i| !entries[i].as_ref().is_some_and(|e| e.is_dir))
            .collect();
        for (k, &i) in offered.iter().enumerate() {
            let flow = match &entries[i] {
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
                let unread_comment = u64::from(!comment.is_empty());
                walk.rest((offered.len() - k - 1) as u64 + unread_comment);
                return Ok(());
            }
        }
        if !comment.is_empty() {
            walk.comment(&mut &comment[..]);
        }
        Ok(())
    }
}
