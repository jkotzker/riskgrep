//! File classification and bounded reading. Decides what a file is and how
//! much of it the scan engine sees; never interprets the content.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::time::Duration;

/// Binary formats whose structure is understood well enough to read selectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    Npy,
    Npz,
    Safetensors,
    KeyStore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileClass {
    Text,
    KnownBinary(Known),
    Archive(&'static str),
    Image(&'static str),
    UnknownBinary,
}

/// Scan limits. Defaults are the global constraints.
#[derive(Debug, Clone)]
pub struct Limits {
    pub text_max: u64,
    pub sample: u64,
    pub sniff: usize,
    pub walk_files: usize,
    pub time_budget: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            text_max: 8_388_608,
            sample: 1_048_576,
            sniff: 8192,
            walk_files: 10_000,
            time_budget: Duration::from_secs(2),
        }
    }
}

/// Bytes handed to the scan engine, plus a note when part of the file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub bytes: Vec<u8>,
    pub partial: Option<String>,
}

const SAFETENSORS_CAP: u64 = 104_857_600;

fn le_u64(head: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(head.get(..8)?.try_into().ok()?))
}

/// Safetensors prefix check. The caller confirms the header fits with
/// [`safetensors_header_fits`] once the file size is known.
fn is_safetensors(head: &[u8]) -> bool {
    match le_u64(head) {
        Some(n) => n > 1 && n >> 32 == 0 && head.get(8) == Some(&b'{'),
        None => false,
    }
}

/// True when the declared safetensors header length fits inside the file.
pub fn safetensors_header_fits(head: &[u8], size: u64) -> bool {
    match le_u64(head) {
        Some(n) => n.checked_add(8).is_some_and(|end| end <= size),
        None => false,
    }
}

fn ends_with_ignore_case(name: &str, suffix: &str) -> bool {
    name.len() >= suffix.len()
        && name.as_bytes()[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

fn image_kind(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        Some("png")
    } else if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else if head.starts_with(b"GIF8") {
        Some("gif")
    } else if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        Some("webp")
    } else if head.len() >= 12 && matches!(&head[4..12], b"ftypheic" | b"ftypheix" | b"ftypmif1") {
        Some("heic")
    } else if head.starts_with(b"II*\0") || head.starts_with(b"MM\0*") {
        Some("tiff")
    } else {
        None
    }
}

/// Classify a file from its name and first bytes (the sniff window).
pub fn classify(name: &str, head: &[u8]) -> FileClass {
    if head.starts_with(&[0x93, b'N', b'U', b'M', b'P', b'Y']) {
        return FileClass::KnownBinary(Known::Npy);
    }
    if head.starts_with(b"PK\x03\x04") {
        return if ends_with_ignore_case(name, ".npz") {
            FileClass::KnownBinary(Known::Npz)
        } else {
            FileClass::Archive("zip")
        };
    }
    if is_safetensors(head) {
        return FileClass::KnownBinary(Known::Safetensors);
    }
    if head.starts_with(&[0x30, 0x82])
        && [".p12", ".pfx", ".der", ".key"]
            .iter()
            .any(|ext| ends_with_ignore_case(name, ext))
    {
        return FileClass::KnownBinary(Known::KeyStore);
    }
    if head.starts_with(b"%PDF-") {
        return FileClass::Archive("pdf");
    }
    if head.starts_with(b"SQLite format 3\0") {
        return FileClass::Archive("sqlite");
    }
    if head.starts_with(&[0x1F, 0x8B]) {
        return FileClass::Archive("gzip");
    }
    if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return FileClass::Archive("7z");
    }
    if head.get(257..262) == Some(b"ustar") {
        return FileClass::Archive("tar");
    }
    if let Some(kind) = image_kind(head) {
        return FileClass::Image(kind);
    }
    if head.contains(&0) {
        FileClass::UnknownBinary
    } else {
        FileClass::Text
    }
}

fn read_range(file: &File, offset: u64, len: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; usize::try_from(len).map_err(io::Error::other)?];
    file.read_exact_at(&mut buf, offset)?;
    Ok(buf)
}

/// Read the first `want` bytes (bounded by `size`), noting what was skipped
/// when `want` is below the file size and `note_skip` is set.
fn read_prefix(file: &File, size: u64, want: u64, note_skip: bool) -> io::Result<Content> {
    let n = want.min(size);
    let partial = (note_skip && n < size).then(|| format!("bytes {n}..{size} not read"));
    Ok(Content {
        bytes: read_range(file, 0, n)?,
        partial,
    })
}

/// Length of an npy header section (magic, version, length field, header text).
fn npy_header_end(file: &File, size: u64, cap: u64) -> io::Result<u64> {
    let prefix = read_range(file, 0, size.min(12))?;
    let end = match prefix.get(6) {
        Some(1) if prefix.len() >= 10 => 10 + u64::from(u16::from_le_bytes([prefix[8], prefix[9]])),
        Some(2 | 3) if prefix.len() >= 12 => {
            12 + u64::from(u32::from_le_bytes([
                prefix[8], prefix[9], prefix[10], prefix[11],
            ]))
        }
        _ => prefix.len() as u64,
    };
    Ok(end.min(cap))
}

/// Read the bytes of `file` that the scan engine should see for `class`.
/// Positions explicitly; the file cursor is neither used nor moved.
pub fn read_for_scan(
    file: &File,
    size: u64,
    class: &FileClass,
    limits: &Limits,
) -> io::Result<Content> {
    match class {
        FileClass::Text => {
            if size <= limits.text_max {
                return read_prefix(file, size, size, false);
            }
            let s = limits.sample.min(size / 2);
            let mut bytes = read_range(file, 0, s)?;
            bytes.push(b'\n');
            bytes.extend(read_range(file, size - s, s)?);
            Ok(Content {
                bytes,
                partial: Some(format!("bytes {s}..{} not read", size - s)),
            })
        }
        FileClass::KnownBinary(Known::Npy) => {
            let end = npy_header_end(file, size, limits.text_max)?;
            read_prefix(file, size, end, false)
        }
        FileClass::KnownBinary(Known::Safetensors) => {
            let head = read_range(file, 0, size.min(8))?;
            let total = le_u64(&head).map_or(8, |n| n.saturating_add(8)).min(size);
            read_prefix(file, size.min(total), SAFETENSORS_CAP, true)
        }
        FileClass::KnownBinary(Known::Npz | Known::KeyStore) => {
            read_prefix(file, size, limits.text_max, true)
        }
        FileClass::Archive(_) | FileClass::Image(_) | FileClass::UnknownBinary => Ok(Content {
            bytes: Vec::new(),
            partial: None,
        }),
    }
}
