//! File classification and bounded reading. Decides what a file is and how
//! much of it the scan engine sees. Reads container structure (an `.npz`
//! archive's directory) only to choose what to read; never judges content.

use crate::container::ContainerKind;
use crate::encoding::{self, Decoded, Encoding, Utf};
use crate::post::{npz_past_the_cap, NPZ_MAX_MEMBERS, NPZ_MEMBER_BYTES};
use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::time::Duration;

/// Binary formats whose structure is understood well enough to read selectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Known {
    Npy,
    Npz,
    Safetensors,
    KeyStore,
    /// Password-vault and keychain files, read for their header only.
    Vault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileClass {
    Text,
    /// UTF-16 or UTF-32 text, transcoded to UTF-8 for the scan engine.
    EncodedText(Encoding),
    KnownBinary(Known),
    /// An archive, document, or database whose members may be read through
    /// a [`crate::container::Extractor`].
    Container(ContainerKind),
    Image(&'static str),
    UnknownBinary,
}

impl FileClass {
    /// Text whose evidence line numbers are the lines other tools number
    /// (see [`crate::model::TargetReport::text`]): UTF-8 text, and UTF-16 LE
    /// text with a byte-order mark, which Claude Code's `Read` decodes
    /// (2.1.309). It reads other UTF-16 and UTF-32 text as bytes and splits
    /// lines at 0x0A bytes, which a code unit other than LF can hold, so its
    /// line numbers may differ and no partial read may rely on them.
    pub fn is_text(&self) -> bool {
        match self {
            FileClass::Text => true,
            FileClass::EncodedText(e) => e.utf == Utf::Utf16Le && e.bom == 2,
            _ => false,
        }
    }
}

/// Scan limits. Defaults are the global constraints.
#[derive(Debug, Clone)]
pub struct Limits {
    pub text_max: u64,
    pub sample: u64,
    pub sniff: usize,
    pub walk_files: usize,
    pub time_budget: Duration,
    /// Uncompressed bytes read from all members of one container.
    pub container_bytes: u64,
    /// Bytes read from one container member.
    pub member_bytes: u64,
    /// Members examined in one container, nested members included.
    pub container_members: u32,
    /// Nesting depth; the top-level container is depth 1.
    pub container_depth: u32,
    /// Largest uncompressed-to-compressed ratio, per member and overall.
    pub container_ratio: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            text_max: 8_388_608,
            sample: 1_048_576,
            sniff: 8192,
            walk_files: 10_000,
            time_budget: Duration::from_secs(2),
            container_bytes: 8_388_608,
            member_bytes: 8_388_608,
            container_members: 1000,
            container_depth: 3,
            container_ratio: 100,
        }
    }
}

/// Bytes handed to the scan engine, plus a note when part of the file was not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Content {
    pub bytes: Vec<u8>,
    pub partial: Option<String>,
    /// `partial` is content that could not be read, not a part left unread
    /// by a read limit.
    pub read_failed: bool,
    /// Set for a sampled text file: where its last bytes sit in `bytes`.
    pub tail: Option<Tail>,
    /// Set when the file could not be read well enough to scan; `bytes` is
    /// then empty and the target is reported unscanned with this reason.
    pub unscanned: Option<String>,
    /// Set for UTF-16 or UTF-32 text: `bytes` is its UTF-8 transcoding, and
    /// this maps offsets in `bytes` back to the file (`tail` is then unset).
    pub decoded: Option<Decoded>,
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
            read_failed: false,
            tail: None,
            unscanned: None,
            decoded: None,
        }
    }

    fn unscanned(reason: String) -> Content {
        Content {
            bytes: Vec::new(),
            partial: None,
            read_failed: false,
            tail: None,
            unscanned: Some(reason),
            decoded: None,
        }
    }

    /// The bytes the evidence-cache key hashes: for transcoded text the
    /// file's bytes, whose offsets its evidence holds; else the bytes scanned.
    pub fn cache_bytes(&self) -> &[u8] {
        self.decoded.as_ref().map_or(&self.bytes, |d| &d.head)
    }
}

/// Bytes of a safetensors header read: past this the file is read in part.
pub(crate) const SAFETENSORS_CAP: u64 = 104_857_600;
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

pub(crate) fn ends_with_ignore_case(name: &str, suffix: &str) -> bool {
    name.len() >= suffix.len()
        && name.as_bytes()[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// The name of the compressed-stream format `head` starts with, among those
/// with no reader whose magic is distinctive. Such a file holds content that is
/// not read, so it must not pass as an unknown binary. `BZh` alone could start
/// text: bzip2 needs its level digit and the magic of its first block, or of the
/// end of the stream when it is empty. Formats with no magic of at least four
/// bytes are not here: raw LZMA and brotli have none, and Unix compress has two.
fn compressed_stream(head: &[u8]) -> Option<&'static str> {
    match head {
        [b'B', b'Z', b'h', b'1'..=b'9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, ..]
        | [b'B', b'Z', b'h', b'1'..=b'9', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, ..] => Some("bzip2"),
        [0xFD, b'7', b'z', b'X', b'Z', 0, ..] => Some("xz"),
        [0x28, 0xB5, 0x2F, 0xFD, ..] => Some("zstd"),
        [b'L', b'Z', b'I', b'P', 1, ..] => Some("lzip"),
        [0x04, 0x22, 0x4D, 0x18, ..] | [0x02, 0x21, 0x4C, 0x18, ..] => Some("lz4"),
        [0x89, b'L', b'Z', b'O', 0, b'\r', b'\n', 0x1A, b'\n', ..] => Some("lzop"),
        [0xFF, 0x06, 0, 0, b's', b'N', b'a', b'P', b'p', b'Y', ..] => Some("snappy"),
        _ => None,
    }
}

/// The kind of image `head` starts, when it starts with more of the format's
/// structure than its first bytes: the beginning of a file of that format
/// has them, and text or binary data that only starts like one does not (a
/// note that begins `GIF8` stays text). Each check reads only the bytes the
/// format fixes at its start, which the sniff window holds. `size` is the
/// length of the whole file, which a box size or an offset must fit.
fn image_kind(head: &[u8], size: u64) -> Option<&'static str> {
    if is_png(head) {
        Some("png")
    } else if is_jpeg(head) {
        Some("jpeg")
    } else if is_gif(head) {
        Some("gif")
    } else if is_webp(head) {
        Some("webp")
    } else if is_heic(head, size) {
        Some("heic")
    } else if is_tiff(head, size) {
        Some("tiff")
    } else {
        None
    }
}

fn be_u32(head: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(head.get(at..at + 4)?.try_into().ok()?))
}

fn le_u32(head: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(head.get(at..at + 4)?.try_into().ok()?))
}

/// The 8-byte PNG signature, then the `IHDR` chunk, which comes first and
/// holds 13 bytes. Apple's optimised PNG puts a 4-byte `CgBI` chunk (and its
/// checksum) before it.
fn is_png(head: &[u8]) -> bool {
    let chunk = |at: usize, len: u32, kind: &[u8; 4]| {
        be_u32(head, at) == Some(len) && head.get(at + 4..at + 8) == Some(kind)
    };
    head.starts_with(b"\x89PNG\r\n\x1a\n")
        && (chunk(8, 13, b"IHDR") || (chunk(8, 4, b"CgBI") && chunk(24, 13, b"IHDR")))
}

/// The start-of-image marker, then a marker segment: `FF` and a marker byte
/// that begins a segment (a frame header, table, application, or comment
/// segment, or the scan), then the segment's length, which counts its own two
/// bytes.
fn is_jpeg(head: &[u8]) -> bool {
    matches!(
        head,
        [0xFF, 0xD8, 0xFF, 0xC0..=0xC7 | 0xC9..=0xCF | 0xDA..=0xDF | 0xE0..=0xEF | 0xFE, hi, lo, ..]
            if u16::from_be_bytes([*hi, *lo]) >= 2
    )
}

/// `GIF87a` or `GIF89a`, the 7-byte logical screen descriptor, the global
/// color table it declares, and the first block, which is an extension
/// (`21`), an image (`2C`), or the trailer (`3B`).
fn is_gif(head: &[u8]) -> bool {
    if !(head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a")) {
        return false;
    }
    let Some(&packed) = head.get(10) else {
        return false;
    };
    let table = if packed & 0x80 != 0 {
        3 * (2usize << (packed & 7))
    } else {
        0
    };
    matches!(head.get(13 + table), Some(0x21 | 0x2C | 0x3B))
}

/// `RIFF`, the size of the rest of the file, `WEBP`, and the first chunk,
/// which is `VP8 `, `VP8L`, or `VP8X`. The size covers at least `WEBP` and
/// that chunk's header.
fn is_webp(head: &[u8]) -> bool {
    head.starts_with(b"RIFF")
        && head.get(8..12) == Some(b"WEBP")
        && le_u32(head, 4).is_some_and(|n| n >= 12)
        && matches!(head.get(12..16), Some(b"VP8 " | b"VP8L" | b"VP8X"))
}

/// An `ftyp` box with one of the brands that mark a HEIF image: its size
/// holds the 16 bytes of its fixed fields and whole 4-byte brands, and fits
/// the file.
fn is_heic(head: &[u8], size: u64) -> bool {
    matches!(
        head.get(4..12),
        Some(b"ftypheic" | b"ftypheix" | b"ftypmif1")
    ) && be_u32(head, 0).is_some_and(|n| n >= 16 && n % 4 == 0 && u64::from(n) <= size)
}

/// A TIFF byte order mark (`II` or `MM`), the number 42 in that order, and the
/// offset of the first directory: on a word boundary, past the 8-byte header,
/// and with room in the file for the directory's entry count.
fn is_tiff(head: &[u8], size: u64) -> bool {
    let offset = if head.starts_with(b"II*\0") {
        le_u32(head, 4)
    } else if head.starts_with(b"MM\0*") {
        be_u32(head, 4)
    } else {
        None
    };
    offset.is_some_and(|n| n >= 8 && n % 2 == 0 && u64::from(n) + 2 <= size)
}

/// Bytes read from a password-vault or keychain file: the header rules look at
/// the first bytes only, and the rest is encrypted.
const VAULT_HEADER_BYTES: u64 = 64;

/// Magic bytes of an encrypted password vault: KeePass (`03 D9 A2 9A`, then
/// `65 FB 4B B5` for KDB 1.x or `67 FB 4B B5` for KDBX), a macOS keychain
/// file (`kych`, version 1.0), or a Password Safe v3 database (`PWS3`, with
/// the `.psafe3` extension or the layout of the specification: four letters
/// alone are too common).
fn is_vault(name: &str, head: &[u8], size: u64) -> bool {
    matches!(
        head,
        [0x03, 0xD9, 0xA2, 0x9A, 0x65 | 0x67, 0xFB, 0x4B, 0xB5, ..]
    ) || head.starts_with(b"kych\0\x01\0\0")
        || (head.starts_with(b"PWS3")
            && (ends_with_ignore_case(name, ".psafe3") || is_password_safe_layout(head, size)))
}

/// Whether a file that starts with `PWS3` has the size and iteration count of
/// a Password Safe v3 database: the fixed fields (tag, salt, iteration
/// count, key check, four key blocks, and IV: 152 bytes), whole 16-byte
/// blocks of encrypted header and records, the EOF block, and the 32-byte
/// HMAC make 200 bytes plus a multiple of 16, and the iteration count (a
/// 32-bit little-endian integer after the 32-byte salt) is at least the
/// original minimum of 2,048 and below 2^28 (four printable characters read
/// as an integer above that). The random salt must also hold a byte that is
/// not printable text (below 0x09 or from 0x80), so a text file with a line
/// feed at offset 39 is not mistaken for a database.
fn is_password_safe_layout(head: &[u8], size: u64) -> bool {
    let salt_is_binary = head
        .get(4..36)
        .is_some_and(|salt| salt.iter().any(|&b| !(0x09..0x80).contains(&b)));
    let iterations = head
        .get(36..40)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    salt_is_binary
        && size >= 200
        && (size - 200).is_multiple_of(16)
        && iterations.is_some_and(|n| (2048..1 << 28).contains(&n))
}

/// Whether a file looks like a database encrypted from its first byte, as
/// SQLCipher lays one out: there is no magic to see, so this takes a database's
/// name, a size in whole pages of the smallest page size, and first bytes as
/// even as ciphertext.
fn is_encrypted_database(name: &str, head: &[u8], size: u64) -> bool {
    const NAMES: [&str; 5] = [".db", ".db3", ".sqlite", ".sqlite3", ".sqlcipher"];
    /// Bits per byte: ciphertext is about 7.95 over the shortest head allowed
    /// (1,024 bytes), and page-structured or text data is far below.
    const MIN_ENTROPY: f64 = 7.5;
    head.len() >= 1024
        && size.is_multiple_of(512)
        && NAMES.iter().any(|ext| ends_with_ignore_case(name, ext))
        && crate::post::shannon(head) >= MIN_ENTROPY
}

/// The largest `.der` or `.key` file read as a key store (1 MiB). Larger
/// files take the text or binary path, so a text file whose first bytes
/// happen to look like a DER header is scanned like any other text.
pub const KEY_STORE_MAX: u64 = 1 << 20;

/// Classify a file from its name and first bytes (the sniff window), taking
/// the file size to be the length of `head`.
pub fn classify(name: &str, head: &[u8]) -> FileClass {
    classify_sized(name, head, head.len() as u64)
}

/// Classify a file from its name, first bytes (the sniff window), and size.
pub fn classify_sized(name: &str, head: &[u8], size: u64) -> FileClass {
    // A non-empty file named as a database's write-ahead log is one, whatever
    // its content: the database reader reports it not read, unless it holds
    // a database's header, which is read as a database.
    if size > 0 && crate::container::sqlite::is_wal_name(name) {
        return FileClass::Container(ContainerKind::Sqlite);
    }
    if head.starts_with(&[0x93, b'N', b'U', b'M', b'P', b'Y']) {
        return FileClass::KnownBinary(Known::Npy);
    }
    if head.starts_with(b"PK\x03\x04") {
        return if ends_with_ignore_case(name, ".npz") {
            FileClass::KnownBinary(Known::Npz)
        } else {
            FileClass::Container(ContainerKind::Zip)
        };
    }
    if is_safetensors(head) {
        return FileClass::KnownBinary(Known::Safetensors);
    }
    if is_vault(name, head, size) {
        return FileClass::KnownBinary(Known::Vault);
    }
    let has_ext = |exts: &[&str]| exts.iter().any(|ext| ends_with_ignore_case(name, ext));
    // DER SEQUENCE: `30 82` (two-byte length) for PKCS #12 files; for
    // `.der`/`.key` of at most `KEY_STORE_MAX` bytes, any SEQUENCE whose
    // length byte is short form (below 0x80) or long form `81` or `82` (the
    // forms the key-store rules match), so every private-key layout reaches
    // the rules (PKCS#8 Ed25519 is `30 2e`, SEC1 P-224 `30 68`), which then
    // decide whether it is a key.
    let der_sequence = size <= KEY_STORE_MAX
        && head.first() == Some(&0x30)
        && head
            .get(1)
            .is_some_and(|&l| l < 0x80 || (0x81..=0x82).contains(&l));
    if (head.starts_with(&[0x30, 0x82]) && has_ext(&[".p12", ".pfx"]))
        || (der_sequence && has_ext(&[".der", ".key"]))
    {
        return FileClass::KnownBinary(Known::KeyStore);
    }
    if head.starts_with(b"%PDF-") {
        return FileClass::Container(ContainerKind::Pdf);
    }
    if head.starts_with(crate::container::sqlite::MAGIC)
        || crate::container::sqlite::is_log(head)
        || is_encrypted_database(name, head, size)
    {
        return FileClass::Container(ContainerKind::Sqlite);
    }
    if head.starts_with(&[0x1F, 0x8B]) {
        return FileClass::Container(ContainerKind::Gzip);
    }
    if head.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return FileClass::Container(ContainerKind::SevenZ);
    }
    if crate::container::tar::is_tar(head) {
        return FileClass::Container(ContainerKind::Tar);
    }
    if let Some(format) = compressed_stream(head) {
        return FileClass::Container(ContainerKind::Compressed(format));
    }
    if let Some(kind) = image_kind(head, size) {
        return FileClass::Image(kind);
    }
    if let Some(e) = encoding::detect(head) {
        return FileClass::EncodedText(e);
    }
    if head.contains(&0) {
        FileClass::UnknownBinary
    } else {
        FileClass::Text
    }
}

/// Something bytes can be read from at explicit offsets: an open file or an
/// in-memory buffer (a git blob, raw text, a container member).
pub trait Source {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>>;
}

impl Source for File {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; usize::try_from(len).map_err(io::Error::other)?];
        self.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }
}

impl<T: Source + ?Sized> Source for &T {
    fn range(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        (**self).range(offset, len)
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

/// A seekable reader over a [`Source`] that fetches at most `left` more bytes
/// in total; past that every read fails and `over` is set. The last fetch is
/// kept, and reads inside it cost nothing: a [`BufReader`] drops its buffer
/// on every seek, so a directory parser that seeks per entry would otherwise
/// pay for the same bytes again each time.
pub(crate) struct Budgeted<'a, S: ?Sized> {
    src: &'a S,
    size: u64,
    pos: u64,
    left: &'a Cell<u64>,
    over: &'a Cell<bool>,
    /// The bytes last fetched from `src`, starting at file offset `window_at`.
    window: Vec<u8>,
    window_at: u64,
}

impl<'a, S: ?Sized> Budgeted<'a, S> {
    pub(crate) fn new(src: &'a S, size: u64, left: &'a Cell<u64>, over: &'a Cell<bool>) -> Self {
        Budgeted {
            src,
            size,
            pos: 0,
            left,
            over,
            window: Vec::new(),
            window_at: 0,
        }
    }
}

impl<S: Source + ?Sized> Read for Budgeted<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = (buf.len() as u64).min(self.size.saturating_sub(self.pos));
        if want == 0 {
            return Ok(0);
        }
        let held = self
            .pos
            .checked_sub(self.window_at)
            .filter(|from| *from < self.window.len() as u64);
        if let Some(from) = held {
            let from = from as usize;
            let n = (want as usize).min(self.window.len() - from);
            buf[..n].copy_from_slice(&self.window[from..from + n]);
            self.pos += n as u64;
            return Ok(n);
        }
        let n = want.min(self.left.get());
        if n == 0 {
            self.over.set(true);
            return Err(io::Error::other("read budget exhausted"));
        }
        let bytes = self.src.range(self.pos, n)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        self.left.set(self.left.get() - bytes.len() as u64);
        self.window_at = self.pos;
        self.pos += bytes.len() as u64;
        self.window = bytes;
        Ok(self.window.len())
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
/// A directory or member over its budget, or a directory that does not parse,
/// makes the file unscanned. A `.npy` member whose data cannot be read is left
/// out and the first such member is noted (partial), as the post-processor
/// does for a file read whole. No member name is ever put in a reason (names
/// may be personal data).
fn npz_member_headers<S: Source + ?Sized>(src: &S, size: u64) -> Content {
    let left = Cell::new(NPZ_DIRECTORY_MAX);
    let over = Cell::new(false);
    let reader = BufReader::with_capacity(8192, Budgeted::new(src, size, &left, &over));
    // zip 9.0.5 scans every byte before the end record for a central directory
    // header when it detects the archive offset, which reads the whole file.
    // A fixed offset of 0 keeps the directory lookup at the end of the file.
    let config = zip::read::Config {
        archive_offset: zip::read::ArchiveOffset::Known(0),
    };
    let mut zip = match zip::ZipArchive::with_config(config, reader) {
        Ok(z) if !over.get() => z,
        _ if over.get() => {
            return Content::unscanned(format!(
                "npz central directory not read within {NPZ_DIRECTORY_MAX} bytes"
            ))
        }
        _ => return Content::unscanned("npz central directory unreadable".into()),
    };
    let mut unread: Option<usize> = None;
    let mut out = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for i in 0..zip.len().min(NPZ_MAX_MEMBERS) {
        let Some(name) = zip
            .name_for_index(i)
            .and_then(Result::ok)
            .filter(|n| n.ends_with(".npy"))
            .map(std::borrow::Cow::into_owned)
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
        // A `.npy` member that cannot be read (a wrong checksum, a size the
        // data runs past) is data the scan did not see: note the first one.
        let Some(head) = head else {
            unread.get_or_insert(i);
            continue;
        };
        let written = out
            .start_file(name, stored)
            .map_err(io::Error::other)
            .and_then(|()| out.write_all(&head));
        if written.is_err() {
            return Content::unscanned("npz member headers could not be re-encoded".into());
        }
    }
    // The first unreadable member, else the members past the cap, which the
    // post-processor cannot see: the re-encoded archive holds at most the cap.
    let note = unread
        .map(|i| format!("npz member {i} could not be read"))
        .or_else(|| npz_past_the_cap(zip.len()));
    match out.finish() {
        Ok(c) => Content {
            read_failed: note.is_some(),
            ..Content::whole(c.into_inner(), note)
        },
        Err(_) => Content::unscanned("npz member headers could not be re-encoded".into()),
    }
}

/// `class`, unless it is an `.npz` that the tensor path would not read in
/// full: one with a member not named `.npy`, with an archive or entry comment,
/// or whose directory does not parse from offset 0, is a zip like any other.
/// A directory over its budget stays as it is, as does an unparseable one over
/// the text limit, which is reported unscanned.
pub fn settle_npz<S: Source + ?Sized>(
    class: FileClass,
    src: &S,
    size: u64,
    limits: &Limits,
) -> FileClass {
    if class != FileClass::KnownBinary(Known::Npz) {
        return class;
    }
    let left = Cell::new(NPZ_DIRECTORY_MAX);
    let over = Cell::new(false);
    let reader = BufReader::with_capacity(8192, Budgeted::new(src, size, &left, &over));
    let config = zip::read::Config {
        archive_offset: zip::read::ArchiveOffset::Known(0),
    };
    let tensors = match zip::ZipArchive::with_config(config, reader) {
        // The comments come from the directory read above, so they cost no
        // more reads: the tensor path reads none of them.
        Ok(zip) if !over.get() => {
            zip.comment().is_empty()
                && (0..zip.len()).all(|i| {
                    let npy = zip
                        .name_for_index(i)
                        .and_then(Result::ok)
                        .is_some_and(|n| n.ends_with(".npy"));
                    npy && zip.by_index_data(i).is_ok_and(|e| e.comment().is_empty())
                })
        }
        _ => over.get() || size > limits.text_max,
    };
    if tensors {
        class
    } else {
        FileClass::Container(ContainerKind::Zip)
    }
}

/// Length of an npy header section (magic, version, length field, header text).
fn npy_header_end<S: Source + ?Sized>(src: &S, size: u64) -> io::Result<u64> {
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
    Ok(end)
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
                read_failed: false,
                tail: Some(Tail {
                    at: s + 1,
                    file_offset: size - s,
                }),
                unscanned: None,
                decoded: None,
            })
        }
        FileClass::EncodedText(e) => {
            // Limits apply to the file's bytes; samples hold whole code units.
            let unit = e.utf.unit() as u64;
            let (head, tail, partial) = if size <= limits.text_max {
                (src.range(0, size)?, None, None)
            } else {
                let s = limits.sample.min(size / 2) / unit * unit;
                let tail_start = ((size - s).div_ceil(unit) * unit).min(size);
                let tail = src.range(tail_start, size - tail_start)?;
                let note = format!("bytes {s}..{tail_start} not read");
                (src.range(0, s)?, Some((tail_start, tail)), Some(note))
            };
            let (decoded, bytes) = Decoded::new(*e, head, tail);
            Ok(Content {
                bytes,
                partial,
                read_failed: false,
                tail: None,
                unscanned: None,
                decoded: Some(decoded),
            })
        }
        FileClass::KnownBinary(Known::Npy) => {
            let end = npy_header_end(src, size)?;
            read_prefix(src, size.min(end), limits.text_max, true)
        }
        FileClass::KnownBinary(Known::Safetensors) => {
            let head = src.range(0, size.min(8))?;
            let total = le_u64(&head).map_or(8, |n| n.saturating_add(8)).min(size);
            read_prefix(src, size.min(total), SAFETENSORS_CAP, true)
        }
        FileClass::KnownBinary(Known::Npz) if size > limits.text_max => {
            Ok(npz_member_headers(src, size))
        }
        FileClass::KnownBinary(Known::Vault) => read_prefix(src, size, VAULT_HEADER_BYTES, false),
        FileClass::KnownBinary(Known::Npz | Known::KeyStore) => {
            read_prefix(src, size, limits.text_max, true)
        }
        FileClass::Container(_) | FileClass::Image(_) | FileClass::UnknownBinary => {
            Ok(Content::whole(Vec::new(), None))
        }
    }
}
