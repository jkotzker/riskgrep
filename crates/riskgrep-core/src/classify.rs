//! File classification and bounded reading. Decides what a file is and how
//! much of it the scan engine sees. Reads container structure (an `.npz`
//! archive's directory) only to choose what to read; never judges content.

use crate::post::{NPZ_MAX_MEMBERS, NPZ_MEMBER_BYTES};
use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
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
    /// Set for a sampled text file: where its last bytes sit in `bytes`.
    pub tail: Option<Tail>,
    /// Set when the file could not be read well enough to scan; `bytes` is
    /// then empty and the target is reported unscanned with this reason.
    pub unscanned: Option<String>,
}

/// Content offsets from `at` onward hold the file's last bytes, which start
/// at file offset `file_offset`. Content before `at - 1` is the file's first
/// bytes at their own offsets; the byte at `at - 1` is an added newline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    pub at: u64,
    pub file_offset: u64,
}

impl Content {
    fn whole(bytes: Vec<u8>, partial: Option<String>) -> Content {
        Content {
            bytes,
            partial,
            tail: None,
            unscanned: None,
        }
    }

    fn unscanned(reason: String) -> Content {
        Content {
            bytes: Vec::new(),
            partial: None,
            tail: None,
            unscanned: Some(reason),
        }
    }
}

const SAFETENSORS_CAP: u64 = 104_857_600;
/// Bytes an `.npz` over the text limit may read to find and parse its
/// central directory (the end record is searched for backwards from the end).
const NPZ_DIRECTORY_MAX: u64 = 8_388_608;
/// Bytes read per `.npz` member: its local header and the first compressed
/// bytes of its data (a deflate reader buffers 32 KiB).
const NPZ_MEMBER_READ_MAX: u64 = 131_072;

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
    let has_ext = |exts: &[&str]| exts.iter().any(|ext| ends_with_ignore_case(name, ext));
    // DER SEQUENCE: `30 82` (two-byte length) for PKCS #12 and most keys;
    // `30 77` / `30 81` (short or one-byte length) for SEC1 EC private keys.
    if (head.starts_with(&[0x30, 0x82]) && has_ext(&[".p12", ".pfx", ".der", ".key"]))
        || ((head.starts_with(&[0x30, 0x77]) || head.starts_with(&[0x30, 0x81]))
            && has_ext(&[".der", ".key"]))
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

/// Something bytes can be read from at explicit offsets: an open file or an
/// in-memory buffer (a git blob, raw text).
trait Source {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>>;
}

impl Source for File {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; usize::try_from(len).map_err(io::Error::other)?];
        self.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }
}

impl Source for [u8] {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let start = usize::try_from(offset).map_err(io::Error::other)?;
        let len = usize::try_from(len).map_err(io::Error::other)?;
        start
            .checked_add(len)
            .and_then(|end| self.get(start..end))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
    }
}

/// Read the first `want` bytes (bounded by `size`), noting what was skipped
/// when `want` is below the file size and `note_skip` is set.
fn read_prefix<S: Source + ?Sized>(
    src: &S,
    size: u64,
    want: u64,
    note_skip: bool,
) -> io::Result<Content> {
    let n = want.min(size);
    let partial = (note_skip && n < size).then(|| format!("bytes {n}..{size} not read"));
    Ok(Content::whole(src.range(0, n)?, partial))
}

/// A seekable reader over a [`Source`] that reads at most `left` more bytes
/// in total; past that every read fails and `over` is set.
struct Budgeted<'a, S: ?Sized> {
    src: &'a S,
    size: u64,
    pos: u64,
    left: &'a Cell<u64>,
    over: &'a Cell<bool>,
}

impl<S: Source + ?Sized> Read for Budgeted<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = (buf.len() as u64).min(self.size.saturating_sub(self.pos));
        if want == 0 {
            return Ok(0);
        }
        let n = want.min(self.left.get());
        if n == 0 {
            self.over.set(true);
            return Err(io::Error::other("read budget exhausted"));
        }
        let bytes = self.src.range(self.pos, n)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        self.left.set(self.left.get() - n);
        self.pos += n;
        Ok(bytes.len())
    }
}

impl<S: ?Sized> Seek for Budgeted<'_, S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = pos.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}

/// An `.npz` too large to read whole: its central directory (located from
/// the end), then for each of the first [`NPZ_MAX_MEMBERS`] entries named
/// `*.npy` its first [`NPZ_MEMBER_BYTES`] uncompressed bytes, each read by
/// offset under a byte budget. The result is a stored zip of those member
/// prefixes in archive order: everything the `.npz` post-processor reads.
/// Members whose data cannot be read are left out, as the post-processor
/// skips them; a directory or member over its budget, or a directory that
/// does not parse, makes the file unscanned. No member name is ever put in
/// a reason (names may be personal data).
fn npz_member_headers<S: Source + ?Sized>(src: &S, size: u64) -> Content {
    let left = Cell::new(NPZ_DIRECTORY_MAX);
    let over = Cell::new(false);
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
    let mut zip = match zip::ZipArchive::new(reader) {
        Ok(z) if !over.get() => z,
        _ if over.get() => {
            return Content::unscanned(format!(
                "npz central directory not read within {NPZ_DIRECTORY_MAX} bytes"
            ))
        }
        _ => return Content::unscanned("npz central directory unreadable".into()),
    };
    let mut out = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for i in 0..zip.len().min(NPZ_MAX_MEMBERS) {
        let Some(name) = zip
            .name_for_index(i)
            .filter(|n| n.ends_with(".npy"))
            .map(str::to_string)
        else {
            continue;
        };
        left.set(NPZ_MEMBER_READ_MAX);
        let head = zip.by_index(i).ok().and_then(|member| {
            let mut head = Vec::new();
            member
                .take(NPZ_MEMBER_BYTES)
                .read_to_end(&mut head)
                .ok()
                .map(|_| head)
        });
        if over.get() {
            return Content::unscanned(format!(
                "npz member {i} not read within {NPZ_MEMBER_READ_MAX} bytes"
            ));
        }
        let Some(head) = head else { continue };
        let written = out
            .start_file(name, stored)
            .map_err(io::Error::other)
            .and_then(|()| out.write_all(&head));
        if written.is_err() {
            return Content::unscanned("npz member headers could not be re-encoded".into());
        }
    }
    match out.finish() {
        Ok(c) => Content::whole(c.into_inner(), None),
        Err(_) => Content::unscanned("npz member headers could not be re-encoded".into()),
    }
}

/// Length of an npy header section (magic, version, length field, header text).
fn npy_header_end<S: Source + ?Sized>(src: &S, size: u64, cap: u64) -> io::Result<u64> {
    let prefix = src.range(0, size.min(12))?;
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
    read_from(file, size, class, limits)
}

/// [`read_for_scan`] over an in-memory buffer, under the same limits.
pub fn slice_for_scan(bytes: &[u8], class: &FileClass, limits: &Limits) -> io::Result<Content> {
    read_from(bytes, bytes.len() as u64, class, limits)
}

fn read_from<S: Source + ?Sized>(
    src: &S,
    size: u64,
    class: &FileClass,
    limits: &Limits,
) -> io::Result<Content> {
    match class {
        FileClass::Text => {
            if size <= limits.text_max {
                return read_prefix(src, size, size, false);
            }
            let s = limits.sample.min(size / 2);
            let mut bytes = src.range(0, s)?;
            bytes.push(b'\n');
            bytes.extend(src.range(size - s, s)?);
            Ok(Content {
                bytes,
                partial: Some(format!("bytes {s}..{} not read", size - s)),
                tail: Some(Tail {
                    at: s + 1,
                    file_offset: size - s,
                }),
                unscanned: None,
            })
        }
        FileClass::KnownBinary(Known::Npy) => {
            let end = npy_header_end(src, size, limits.text_max)?;
            read_prefix(src, size, end, false)
        }
        FileClass::KnownBinary(Known::Safetensors) => {
            let head = src.range(0, size.min(8))?;
            let total = le_u64(&head).map_or(8, |n| n.saturating_add(8)).min(size);
            read_prefix(src, size.min(total), SAFETENSORS_CAP, true)
        }
        FileClass::KnownBinary(Known::Npz) if size > limits.text_max => {
            Ok(npz_member_headers(src, size))
        }
        FileClass::KnownBinary(Known::Npz | Known::KeyStore) => {
            read_prefix(src, size, limits.text_max, true)
        }
        FileClass::Archive(_) | FileClass::Image(_) | FileClass::UnknownBinary => {
            Ok(Content::whole(Vec::new(), None))
        }
    }
}
