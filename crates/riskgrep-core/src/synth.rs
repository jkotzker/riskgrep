//! Deterministic synthetic data for tests, `rules test`, and the eval.
//! Everything derives from a seed; generators return bytes or text and never
//! print them. Float data is random noise, not biometric data.

use std::fmt::Write as _;
use std::io::Write as _;

/// Seeded generator over a BLAKE3 XOF stream.
pub struct Rng(blake3::OutputReader);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        let mut h = blake3::Hasher::new();
        h.update(b"riskgrep-synth");
        h.update(&seed.to_le_bytes());
        Rng(h.finalize_xof())
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// Uniform in [-1, 1).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 52) as f64 - 1.0
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

fn item_size(dtype: &str) -> usize {
    let digits: String = dtype.chars().filter(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(1)
}

fn is_float_dtype(dtype: &str) -> bool {
    dtype
        .trim_start_matches(['<', '>', '|', '='])
        .starts_with('f')
}

/// The header of a version 1.0 `.npy` file with no data after it, as a large
/// array's first bytes are (the scanner reads headers only).
pub fn npy_header(dtype: &str, shape: &[u64]) -> Vec<u8> {
    let dims = match shape {
        [d] => format!("({d},)"),
        _ => format!(
            "({})",
            shape
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let mut header = format!("{{'descr': '{dtype}', 'fortran_order': False, 'shape': {dims}, }}");
    // magic (6) + version (2) + length (2) + header + '\n' is a multiple of 64.
    while (10 + header.len() + 1) % 64 != 0 {
        header.push(' ');
    }
    header.push('\n');
    let mut out = b"\x93NUMPY\x01\x00".to_vec();
    out.extend_from_slice(&(header.len() as u16).to_le_bytes());
    out.extend_from_slice(header.as_bytes());
    out
}

/// A version 1.0 `.npy` file. Float dtypes (`<f4`, `<f8`, `<f2`) get random
/// finite values; other dtypes get random bytes.
pub fn npy(dtype: &str, shape: &[u64]) -> Vec<u8> {
    let mut out = npy_header(dtype, shape);
    let count: u64 = shape.iter().product();
    let size = item_size(dtype);
    let mut rng = Rng::new(count ^ ((size as u64) << 56));
    for _ in 0..count {
        match (is_float_dtype(dtype), size) {
            (true, 8) => out.extend_from_slice(&rng.next_f64().to_le_bytes()),
            (true, 4) => out.extend_from_slice(&(rng.next_f64() as f32).to_le_bytes()),
            (true, 2) => out.extend_from_slice(&[0, 0x3c]),
            _ => {
                let mut b = vec![0u8; size];
                rng.fill(&mut b);
                out.extend_from_slice(&b);
            }
        }
    }
    out
}

/// A zip archive of `(member name, bytes)` pairs, stored uncompressed. Names
/// carry their own extension (`.npy` members make an `.npz`).
pub fn npz(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in members {
        w.start_file(*name, opts).expect("zip member");
        w.write_all(data).expect("zip data");
    }
    w.finish().expect("zip finish").into_inner()
}

/// An `.npz` of one embedding-shaped `.npy` member whose checksum is wrong,
/// so the member cannot be read.
pub fn npz_with_unreadable_member() -> Vec<u8> {
    npz_with_unreadable_first(&[])
}

/// An `.npz` whose first member is as in [`npz_with_unreadable_member`],
/// followed by `rest`.
pub fn npz_with_unreadable_first(rest: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut members = vec![("bad.npy", npy("<f4", &[1, 128]))];
    members.extend_from_slice(rest);
    let mut z = npz(&members);
    // The end record is the last 22 bytes and gives the directory's offset.
    let end = z.len() - 22;
    let central = u32::from_le_bytes(z[end + 16..end + 20].try_into().unwrap()) as usize;
    z[14..18].fill(0);
    z[central + 16..central + 20].fill(0);
    z
}

/// A database with one row: `value` as text in `table`.`column`. SQLite writes
/// only to files here, so it is built in a scratch file and read back.
pub fn sqlite(table: &str, column: &str, value: &[u8]) -> Vec<u8> {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("random scratch name");
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let path = std::env::temp_dir().join(format!("riskgrep-synth-{id}.sqlite"));
    // Claimed first: a path someone else made, such as a symlink, is refused.
    std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("scratch database name");
    let conn = rusqlite::Connection::open(&path).expect("scratch database");
    let name = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    conn.execute_batch(&format!(
        "CREATE TABLE {}({} TEXT);",
        name(table),
        name(column)
    ))
    .expect("create table");
    conn.execute(
        &format!("INSERT INTO {} VALUES (?1)", name(table)),
        [String::from_utf8_lossy(value)],
    )
    .expect("insert");
    conn.close().expect("close");
    let out = std::fs::read(&path).expect("read back");
    std::fs::remove_file(&path).expect("remove scratch database");
    out
}

/// A zip archive of `(member name, bytes)` pairs, deflated.
pub fn zip(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in members {
        w.start_file(*name, opts).expect("zip member");
        w.write_all(data).expect("zip data");
    }
    w.finish().expect("zip finish").into_inner()
}

/// A ustar header block for an entry of `kind` (the type flag byte, `b'0'` for
/// a regular file) declaring `size` bytes. `name` fits the 100-byte name field.
pub fn tar_header(name: &str, kind: u8, size: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    tar_seal(&mut h);
    h
}

/// Write the checksum of a tar header block.
pub fn tar_seal(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// One tar entry: its header, `data`, and zero padding to a whole block.
pub fn tar_entry(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = tar_header(name, kind, data.len() as u64).to_vec();
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

/// A tar archive of `(member name, bytes)` pairs, with its end marker.
pub fn tar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out: Vec<u8> = members
        .iter()
        .flat_map(|(name, data)| tar_entry(name, b'0', data))
        .collect();
    out.resize(out.len() + 1024, 0);
    out
}

/// `data` as one gzip stream, with no name in its header.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut w = flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
    w.write_all(data).expect("gzip data");
    w.finish().expect("gzip finish")
}

/// A valid PNG image of one transparent pixel: the signature, then the
/// `IHDR`, `IDAT`, and `IEND` chunks, each with its checksum.
pub fn png_1x1() -> Vec<u8> {
    fn crc32(bytes: impl Iterator<Item = u8>) -> u32 {
        let mut crc = !0u32;
        for b in bytes {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let crc = crc32(kind.iter().chain(data).copied());
        out.extend_from_slice(&crc.to_be_bytes());
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    // Width 1, height 1, 8 bits per channel, RGBA, no interlacing.
    chunk(&mut out, b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
    // One scanline: filter type 0 and four zero bytes, in a stored zlib
    // block (the Adler-32 of five bytes 0, 0, 0, 0, 0 is 0x0005_0001).
    chunk(
        &mut out,
        b"IDAT",
        &[
            0x78, 0x01, 0x01, 0x05, 0x00, 0xFA, 0xFF, 0, 0, 0, 0, 0, 0x00, 0x05, 0x00, 0x01,
        ],
    );
    chunk(&mut out, b"IEND", &[]);
    out
}

/// A safetensors file from `(name, dtype, shape)` triples, with random data.
/// `dtype` uses safetensors names (`F32`, `I64`, ...).
pub fn safetensors(tensors: &[(&str, &str, &[u64])]) -> Vec<u8> {
    let (mut out, len) = safetensors_parts(tensors);
    let mut data = vec![0u8; len as usize];
    Rng::new(len).fill(&mut data);
    out.extend_from_slice(&data);
    out
}

/// The length prefix and JSON header of a safetensors file, with offsets but
/// no tensor data, as a checkpoint's first bytes are.
pub fn safetensors_header(tensors: &[(&str, &str, &[u64])]) -> Vec<u8> {
    safetensors_parts(tensors).0
}

/// Length prefix plus header, and the data length the header describes.
fn safetensors_parts(tensors: &[(&str, &str, &[u64])]) -> (Vec<u8>, u64) {
    let mut header = serde_json::Map::new();
    let mut offset = 0u64;
    for (name, dtype, shape) in tensors {
        let bytes = shape.iter().product::<u64>() * dtype_bytes(dtype);
        header.insert(
            (*name).to_string(),
            serde_json::json!({
                "dtype": dtype,
                "shape": shape,
                "data_offsets": [offset, offset + bytes],
            }),
        );
        offset += bytes;
    }
    let json = serde_json::to_vec(&header).expect("header json");
    let mut out = (json.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(&json);
    (out, offset)
}

fn dtype_bytes(dtype: &str) -> u64 {
    match dtype {
        "F64" | "I64" | "U64" => 8,
        "F32" | "I32" | "U32" => 4,
        "F16" | "BF16" | "I16" | "U16" => 2,
        _ => 1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FloatStyle {
    /// `[0.123456, -0.234567, ...]`
    PythonList,
    /// numpy repr: `array([ 0.12345678, -0.23456789, ...,\n       ...])`
    NumpyRepr,
    /// `{"values": [0.123456, ...]}` pretty-printed one value per line
    JsonArray,
}

/// `n` random floats printed in the given style.
pub fn printed_floats(n: usize, style: FloatStyle) -> String {
    let mut rng = Rng::new(n as u64 + 0x5eed);
    let mut out = String::new();
    match style {
        FloatStyle::PythonList => {
            out.push('[');
            for i in 0..n {
                if i > 0 {
                    out.push_str(", ");
                }
                write!(out, "{:.6}", rng.next_f64()).unwrap();
            }
            out.push(']');
        }
        FloatStyle::NumpyRepr => {
            out.push_str("array([");
            for i in 0..n {
                if i > 0 {
                    out.push(',');
                    out.push_str(if i % 6 == 0 { "\n       " } else { " " });
                }
                write!(out, "{:>11.8}", rng.next_f64()).unwrap();
            }
            out.push_str("])");
        }
        FloatStyle::JsonArray => {
            out.push_str("{\n  \"values\": [\n");
            for i in 0..n {
                write!(out, "    {:.6}", rng.next_f64()).unwrap();
                out.push_str(if i + 1 < n { ",\n" } else { "\n" });
            }
            out.push_str("  ]\n}\n");
        }
    }
    out
}

/// A CSV of `rows` x `cols` random floats, one row per line.
pub fn csv_rows(rows: usize, cols: usize) -> String {
    let mut rng = Rng::new((rows * 1000 + cols) as u64);
    let mut out = String::new();
    for _ in 0..rows {
        for c in 0..cols {
            if c > 0 {
                out.push(',');
            }
            write!(out, "{:.4}", rng.next_f64()).unwrap();
        }
        out.push('\n');
    }
    out
}

const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const URLSAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const LOWER36: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn pick(&mut self, alphabet: &[u8], n: usize) -> String {
        (0..n)
            .map(|_| alphabet[self.below(alphabet.len())] as char)
            .collect()
    }
}

fn base64(data: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            if k <= c.len() {
                out.push(B64[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Kinds accepted by [`fake_secret`].
pub const FAKE_SECRET_KINDS: &[&str] = &[
    "aws_access_key",
    "aws_example_key",
    "github_pat",
    "anthropic_key",
    "pem_private_key",
    "generic_api_key_assignment",
    "low_entropy_generic",
    "stripe_key",
    "slack_bot_token",
    "npm_token",
    "openai_key",
];

/// A fake credential in a provider's format, derived from `seed`. Kinds
/// ending in `generic` or `assignment` return a whole `api_key = "..."` line;
/// the others return the token alone. Panics on an unknown kind.
pub fn fake_secret(kind: &str, seed: u64) -> String {
    let mut h = blake3::Hasher::new();
    h.update(kind.as_bytes());
    h.update(&seed.to_le_bytes());
    let mut r = Rng(h.finalize_xof());
    match kind {
        "aws_access_key" => format!("AKIA{}", r.pick(BASE32, 16)),
        "aws_example_key" => format!("AKIA{}EXAMPLE", r.pick(BASE32, 9)),
        "github_pat" => format!("ghp_{}", r.pick(BASE62, 36)),
        "anthropic_key" => format!("sk-ant-api03-{}AA", r.pick(URLSAFE, 93)),
        "pem_private_key" => {
            let mut der = vec![0u8; 600];
            r.fill(&mut der);
            let body = base64(&der);
            let lines: Vec<&str> = body
                .as_bytes()
                .chunks(64)
                .map(|l| std::str::from_utf8(l).expect("ascii"))
                .collect();
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
                lines.join("\n")
            )
        }
        "generic_api_key_assignment" => format!("api_key = \"{}\"", r.pick(BASE62, 32)),
        "low_entropy_generic" => format!("api_key = \"{}\"", "a".repeat(24)),
        "stripe_key" => format!("sk_live_{}", r.pick(BASE62, 24)),
        "slack_bot_token" => format!(
            "xoxb-{}-{}-{}",
            r.pick(b"0123456789", 12),
            r.pick(b"0123456789", 12),
            r.pick(BASE62, 24)
        ),
        "npm_token" => format!("npm_{}", r.pick(LOWER36, 36)),
        "openai_key" => format!(
            "sk-proj-{}T3BlbkFJ{}",
            r.pick(URLSAFE, 74),
            r.pick(URLSAFE, 74)
        ),
        other => panic!("unknown fake secret kind `{other}`"),
    }
}

const WORDS: &[&str] = &[
    "value", "count", "index", "buffer", "result", "config", "item", "name", "path", "size",
    "total", "offset", "handler", "request", "response", "user", "data", "list", "node", "width",
    "height", "cursor", "session", "token", "key", "cache", "retry", "limit",
];

/// Source-code-like ASCII text of exactly `len` bytes: functions,
/// assignments, calls, and comments built from common identifiers.
pub fn source_text(len: usize, seed: u64) -> String {
    let mut r = Rng::new(seed ^ 0x736f_7572_6365);
    let mut out = String::with_capacity(len + 128);
    while out.len() < len {
        let a = WORDS[r.below(WORDS.len())];
        let b = WORDS[r.below(WORDS.len())];
        let n = r.below(10_000);
        match r.below(8) {
            0 => writeln!(out, "fn {a}_{b}({a}: u32, {b}: &str) -> u32 {{").unwrap(),
            1 => writeln!(out, "    let {a}_{b} = {n};").unwrap(),
            2 => writeln!(out, "    // update the {a} before the {b} is read").unwrap(),
            3 => writeln!(out, "    if {a} > {n} {{ return {b}.len() as u32; }}").unwrap(),
            4 => writeln!(out, "    {a}.{b}(&{a}_{b}, \"{b}\");").unwrap(),
            5 => writeln!(out, "    let {a}_key = {b}.get(\"{a}\").unwrap_or({n});").unwrap(),
            6 => writeln!(out, "}}\n").unwrap(),
            _ => writeln!(out, "use crate::{a}::{{{b}, {a}_{b}}};").unwrap(),
        }
    }
    out.truncate(len);
    out
}

/// A fake PEM private key: `der_len` random bytes in base64, 64 characters
/// per line, between `-----BEGIN <label>-----` and `-----END <label>-----`.
/// No trailing newline.
pub fn fake_pem(label: &str, der_len: usize, seed: u64) -> String {
    let mut der = vec![0u8; der_len];
    Rng::new(seed ^ 0x7065_6d00).fill(&mut der);
    let body = base64(&der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).expect("ascii"))
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----",
        lines.join("\n")
    )
}

/// A file holding two private keys: `head` holds the first, `tail` appends
/// the second. `keys` are the 1-based inclusive line ranges of both keys in
/// `head + tail`.
pub struct TwoKeys {
    pub name: &'static str,
    pub head: String,
    pub tail: String,
    pub keys: [(u32, u32); 2],
}

impl TwoKeys {
    pub fn whole(&self) -> String {
        format!("{}{}", self.head, self.tail)
    }
}

/// Files with two private keys each, for tests that every key gets its own
/// location: an RSA key then a short (Ed25519-sized) PKCS#8 key, the same in
/// reverse order, two RSA-4096-sized keys back to back, and two JSON lines
/// holding service-account-style keys with escaped newlines.
pub fn two_key_files(seed: u64) -> Vec<TwoKeys> {
    let lines = |s: &str| s.matches('\n').count() as u32;
    let rsa = fake_pem("RSA PRIVATE KEY", 600, seed);
    let ed = fake_pem("PRIVATE KEY", 48, seed + 1);
    let big1 = fake_pem("RSA PRIVATE KEY", 2350, seed + 2);
    let big2 = fake_pem("RSA PRIVATE KEY", 2350, seed + 3);
    let pair = |name, a: &str, b: &str| {
        let head = format!("config = 1\n{a}\nx = 1\ny = 2\nz = 3\n");
        let tail = format!("{b}\nend = 1\n");
        let a_start = 2;
        let a_end = a_start + lines(a);
        let b_start = lines(&head) + 1;
        TwoKeys {
            name,
            keys: [(a_start, a_end), (b_start, b_start + lines(b))],
            head,
            tail,
        }
    };
    let big_head = format!("{big1}\n");
    let big = TwoKeys {
        name: "two_rsa4096.txt",
        keys: [
            (1, 1 + lines(&big1)),
            (lines(&big_head) + 1, lines(&big_head) + 1 + lines(&big2)),
        ],
        tail: format!("{big2}\n"),
        head: big_head,
    };
    let sa = |pem: &str| {
        format!(
            "{{\"type\": \"service_account\", \"private_key\": \"{}\\n\", \"client_email\": \"a@b.example\"}}",
            pem.replace('\n', "\\n")
        )
    };
    let jsonl = TwoKeys {
        name: "service_accounts.jsonl",
        head: format!("{}\n{{\"note\": 1}}\n", sa(&ed)),
        tail: format!("{}\n", sa(&rsa)),
        keys: [(1, 1), (3, 3)],
    };
    vec![
        pair("rsa_then_short.txt", &rsa, &ed),
        pair("short_then_rsa.txt", &ed, &rsa),
        big,
        jsonl,
    ]
}

// ---- credential files ------------------------------------------------------
// Whole-file text for the credential-file rules (TOTP URIs, password-manager
// exports, two-factor recovery codes). Credentials are random; header rows are
// joined from their columns so no source line spells a complete export header.

/// Kinds accepted by [`credential_file`]: positives first, then hard negatives.
pub const CREDENTIAL_FILE_KINDS: &[&str] = &[
    "otpauth_totp",
    "otpauth_hotp",
    "otpauth_list_text",
    "otpauth_list_json",
    "otpauth_migration",
    "bitwarden_json",
    "onepassword_json",
    "lastpass_csv",
    "chrome_csv",
    "apple_csv",
    "bitwarden_csv",
    "onepassword_1pif",
    "firefox_csv",
    "keepass_xml",
    "keepass_csv",
    "keepassxc_csv",
    "keepassxc_csv_six",
    "dashlane_csv",
    "dashlane_json",
    "keeper_json",
    "protonpass_csv",
    "protonpass_json",
    "keepass_key_file_v1",
    "keepass_key_file_v2",
    "password_safe_structural",
    "otpauth_encoded",
    "recovery_github",
    "recovery_google",
    "recovery_alnum",
    "config_xml_credential",
    "config_json_credential_object",
    "config_yaml_credential_mapping",
    "config_dotnet_app_settings",
    "config_key_hex_low_entropy",
    "config_yaml_credential_named_member",
    "otpauth_no_secret",
    "otpauth_short_secret",
    "otpauth_example_secret",
    "base32_outside_uri",
    "bitwarden_encrypted_json",
    "users_csv",
    "lastpass_header_only",
    "recovery_prose",
    "hex_pairs_unlabelled",
    "recovery_few_codes",
    "recovery_large_document",
    "recovery_source_like",
    "recovery_digit_at_ends",
    "otpauth_lowercase_secret",
    "config_xml_non_secret",
    "config_json_non_secret",
    "config_yaml_non_secret",
    "config_dotnet_non_secret",
    "config_key_hex_non_secret",
    "lastpass_csv_bom_crlf",
    "chrome_csv_bom_crlf",
    "apple_csv_bom_crlf",
    "bitwarden_csv_bom_crlf",
    "onepassword_1pif_no_password",
    "firefox_csv_header_only",
    "keepass_xml_no_password",
    "keepass_csv_header_only",
    "keepassxc_csv_six_header_only",
    "dashlane_json_no_password",
    "keeper_json_unrelated",
    "protonpass_csv_header_only",
    "protonpass_json_encrypted",
    "keepass_key_file_lookalike",
    "password_safe_wrong_size",
    "password_safe_low_iterations",
    "otpauth_encoded_example_secret",
    "otpauth_encoded_no_secret",
    "firefox_csv_bom_crlf",
    "keepassxc_csv_bom_crlf",
    "keepassxc_csv_six_bom_crlf",
    "protonpass_csv_bom_crlf",
    "dashlane_json_bom_crlf",
];

const PASSWORD_CHARS: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";
const LOWER_HEX: &[u8] = b"0123456789abcdef";

/// One saved login with a random password that includes symbols.
struct Login {
    name: String,
    url: String,
    user: String,
    password: String,
}

fn logins(r: &mut Rng, n: usize) -> Vec<Login> {
    (0..n)
        .map(|i| Login {
            name: format!("Example Shop {i}"),
            url: format!("https://shop{i}.example.test/login"),
            user: format!("user{i}@example.test"),
            password: r.pick(PASSWORD_CHARS, 18),
        })
        .collect()
}

fn uuid_text(r: &mut Rng) -> String {
    let h = r.pick(LOWER_HEX, 32);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

fn otpauth_uri(r: &mut Rng, kind: &str, i: usize) -> String {
    let secret = r.pick(BASE32, 32);
    format!(
        "otpauth://{kind}/Example%20Co:user{i}@example.test?secret={secret}&issuer=Example%20Co"
    )
}

fn csv_row(cols: &[&str]) -> String {
    cols.join(",")
}

fn hex_pair_lines(r: &mut Rng, n: usize) -> String {
    (0..n)
        .map(|_| format!("{}-{}\n", r.pick(LOWER_HEX, 5), r.pick(LOWER_HEX, 5)))
        .collect()
}

/// A random hex credential of `n` characters, upper case when `upper`.
fn hex_value(r: &mut Rng, n: usize, upper: bool) -> String {
    let h = r.pick(LOWER_HEX, n);
    if upper {
        h.to_uppercase()
    } else {
        h
    }
}

/// Shannon entropy in bits per character.
fn shannon(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in text.bytes() {
        counts[b as usize] += 1;
    }
    let n = text.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// A random 32-character hex value whose entropy is at least 3.0 and below
/// 3.5, the band `generic_api_key` (minimum 3.5) drops: about one random
/// value in five falls in it.
fn hex_value_low_entropy(r: &mut Rng) -> String {
    loop {
        let v = hex_value(r, 32, false);
        let e = shannon(&v);
        if (3.0..3.5).contains(&e) {
            return v;
        }
    }
}

/// XML element names that hold a credential, as configuration files spell
/// them (the *arr apps use `ApiKey`).
const XML_CREDENTIAL_ELEMENTS: &[&str] = &[
    "ApiKey",
    "api_key",
    "AccessToken",
    "ClientSecret",
    "Password",
    "Psk",
    "EncryptionKey",
    "SecretKey",
];

/// Object and mapping names whose members are credentials (Z-Wave JS UI keeps
/// a network's keys under `securityKeys`), with member names for each.
const CREDENTIAL_OBJECTS: &[(&str, &[&str])] = &[
    (
        "securityKeys",
        &[
            "S2_Unauthenticated",
            "S2_Authenticated",
            "S2_AccessControl",
            "S0_Legacy",
        ],
    ),
    ("credentials", &["primary", "fallback"]),
    ("secrets", &["webhook", "session"]),
    ("apiKeys", &["billing", "search"]),
    ("encryption_keys", &["current", "previous"]),
];

/// A Password Safe v3 database shaped by the format specification
/// (`TAG|SALT|ITER|H(P')|B1|B2|B3|B4|IV|records|EOF|HMAC`), with random bytes
/// for the encrypted parts. `shape` is `structural` (a valid layout),
/// `wrong_size` (a length that is not 200 plus a whole number of 16-byte
/// blocks), or `low_iterations` (an iteration count below the 2,048 minimum).
fn password_safe_file(r: &mut Rng, shape: &str) -> Vec<u8> {
    let mut out = b"PWS3".to_vec();
    let mut salt = [0u8; 32];
    r.fill(&mut salt);
    out.extend_from_slice(&salt);
    let iterations: u32 = if shape == "low_iterations" {
        17
    } else {
        262_144
    };
    out.extend_from_slice(&iterations.to_le_bytes());
    // H(P'), B1 to B4, IV, and the encrypted header and records.
    let mut body = vec![0u8; 32 + 64 + 16 + 16 * 6];
    r.fill(&mut body);
    out.extend_from_slice(&body);
    out.extend_from_slice(b"PWS3-EOFPWS3-EOF");
    let mut hmac = [0u8; 32];
    r.fill(&mut hmac);
    out.extend_from_slice(&hmac);
    if shape == "wrong_size" {
        out.extend_from_slice(&[0u8; 5]);
    }
    assert!(matches!(
        shape,
        "structural" | "wrong_size" | "low_iterations"
    ));
    out
}

/// The text of a credential file (or a hard negative for its rule) of the
/// given kind, derived from `seed`. Panics on an unknown kind.
pub fn credential_file(kind: &str, seed: u64) -> Vec<u8> {
    // Spreadsheet re-saves add a UTF-8 byte order mark and CRLF line endings.
    if let Some(base) = kind.strip_suffix("_bom_crlf") {
        let text = String::from_utf8(credential_file(base, seed)).expect("text kind");
        let mut out = vec![0xEF, 0xBB, 0xBF];
        out.extend(
            text.replace("\r\n", "\n")
                .replace('\n', "\r\n")
                .into_bytes(),
        );
        return out;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"credential-file");
    h.update(kind.as_bytes());
    h.update(&seed.to_le_bytes());
    let mut r = Rng(h.finalize_xof());
    if let Some(shape) = kind.strip_prefix("password_safe_") {
        return password_safe_file(&mut r, shape);
    }
    let mut out = String::new();
    match kind {
        "otpauth_totp" => {
            writeln!(out, "# two-factor seeds, exported 2026-10-01").unwrap();
            writeln!(out, "{}", otpauth_uri(&mut r, "totp", 1)).unwrap();
        }
        "otpauth_hotp" => {
            let uri = otpauth_uri(&mut r, "hotp", 1);
            writeln!(out, "{uri}&counter=0").unwrap();
        }
        "otpauth_list_text" => {
            for i in 0..6 {
                writeln!(out, "{}", otpauth_uri(&mut r, "totp", i)).unwrap();
            }
        }
        "otpauth_list_json" => {
            out.push_str("[\n");
            for i in 0..4 {
                let sep = if i < 3 { "," } else { "" };
                let uri = otpauth_uri(&mut r, "totp", i);
                writeln!(
                    out,
                    "  {{\"name\": \"account {i}\", \"uri\": \"{uri}\"}}{sep}"
                )
                .unwrap();
            }
            out.push_str("]\n");
        }
        "otpauth_migration" => {
            let mut blob = vec![0u8; 96];
            r.fill(&mut blob);
            let data = base64(&blob)
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D");
            writeln!(out, "otpauth-migration://offline?data={data}").unwrap();
        }
        "bitwarden_json" => {
            out.push_str("{\n  \"encrypted\": false,\n  \"folders\": [],\n  \"items\": [\n");
            let list = logins(&mut r, 4);
            for (i, l) in list.iter().enumerate() {
                let totp = if i == 0 {
                    format!("\"{}\"", r.pick(BASE32, 32))
                } else {
                    "null".into()
                };
                let sep = if i + 1 < list.len() { "," } else { "" };
                let id = uuid_text(&mut r);
                write!(
                    out,
                    "    {{\n      \"id\": \"{id}\",\n      \"folderId\": null,\n      \"type\": 1,\n      \
                     \"name\": \"{}\",\n      \"notes\": null,\n      \"favorite\": false,\n      \
                     \"login\": {{\n        \"uris\": [\n          {{\n            \"match\": null,\n            \
                     \"uri\": \"{}\"\n          }}\n        ],\n        \"username\": \"{}\",\n        \
                     \"password\": \"{}\",\n        \"totp\": {totp}\n      }},\n      \
                     \"collectionIds\": null\n    }}{sep}\n",
                    l.name, l.url, l.user, l.password
                )
                .unwrap();
            }
            out.push_str("  ]\n}\n");
        }
        "onepassword_json" => {
            let (account, vault) = (uuid_text(&mut r), uuid_text(&mut r));
            write!(
                out,
                "{{\"accounts\":[{{\"attrs\":{{\"accountName\":\"Example\",\"name\":\"Example User\",\
                 \"avatar\":\"\",\"email\":\"user@example.test\",\"uuid\":\"{account}\",\
                 \"domain\":\"https://my.example.test/\"}},\"vaults\":[{{\"attrs\":{{\"uuid\":\"{vault}\",\
                 \"desc\":\"\",\"avatar\":\"\",\"name\":\"Personal\",\"type\":\"P\"}},\"items\":["
            )
            .unwrap();
            let list = logins(&mut r, 3);
            for (i, l) in list.iter().enumerate() {
                let sep = if i + 1 < list.len() { "," } else { "" };
                let id = uuid_text(&mut r);
                write!(
                    out,
                    "{{\"uuid\":\"{id}\",\"favIndex\":0,\"createdAt\":1600000000,\"updatedAt\":1600000000,\
                     \"trashed\":false,\"categoryUuid\":\"001\",\"details\":{{\"loginFields\":[\
                     {{\"value\":\"{}\",\"id\":\"\",\"name\":\"username\",\"fieldType\":\"T\",\"designation\":\"username\"}},\
                     {{\"value\":\"{}\",\"id\":\"\",\"name\":\"password\",\"fieldType\":\"P\",\"designation\":\"password\"}}],\
                     \"notesPlain\":\"\",\"sections\":[],\"passwordHistory\":[]}},\"overview\":{{\"subtitle\":\"{}\",\
                     \"urls\":[{{\"label\":\"\",\"url\":\"{}\"}}],\"title\":\"{}\",\"url\":\"{}\"}}}}{sep}",
                    l.user, l.password, l.user, l.url, l.name, l.url
                )
                .unwrap();
            }
            out.push_str("]}]}]}\n");
        }
        "lastpass_csv" => {
            let head = csv_row(&[
                "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
            ]);
            writeln!(out, "{head}").unwrap();
            for l in logins(&mut r, 5) {
                writeln!(
                    out,
                    "{},{},\"{}\",,,{},,0",
                    l.url, l.user, l.password, l.name
                )
                .unwrap();
            }
        }
        "chrome_csv" => {
            writeln!(
                out,
                "{}",
                csv_row(&["name", "url", "username", "password", "note"])
            )
            .unwrap();
            for l in logins(&mut r, 5) {
                writeln!(out, "{},{},{},\"{}\",", l.name, l.url, l.user, l.password).unwrap();
            }
        }
        "apple_csv" => {
            writeln!(
                out,
                "{}",
                csv_row(&["Title", "URL", "Username", "Password", "Notes", "OTPAuth"])
            )
            .unwrap();
            for l in logins(&mut r, 5) {
                writeln!(out, "{},{},{},\"{}\",,", l.name, l.url, l.user, l.password).unwrap();
            }
        }
        "bitwarden_csv" => {
            let head = csv_row(&[
                "folder",
                "favorite",
                "type",
                "name",
                "notes",
                "fields",
                "reprompt",
                "login_uri",
                "login_username",
                "login_password",
                "login_totp",
            ]);
            writeln!(out, "{head}").unwrap();
            for l in logins(&mut r, 5) {
                writeln!(
                    out,
                    ",,login,{},,,0,{},{},\"{}\",",
                    l.name, l.url, l.user, l.password
                )
                .unwrap();
            }
        }
        "recovery_github" => out = hex_pair_lines(&mut r, 16),
        "recovery_google" => {
            out.push_str("Backup codes\n\nEach code can be used once.\n\n");
            for i in 1..=10 {
                writeln!(
                    out,
                    "{i}. {} {}",
                    r.pick(b"0123456789", 4),
                    r.pick(b"0123456789", 4)
                )
                .unwrap();
            }
        }
        "recovery_alnum" => {
            out.push_str("Your recovery codes\n\n");
            for _ in 0..10 {
                writeln!(out, "{}", r.pick(LOWER36, 10)).unwrap();
            }
        }
        "config_xml_credential" => {
            let name = XML_CREDENTIAL_ELEMENTS[r.below(XML_CREDENTIAL_ELEMENTS.len())];
            let upper = r.below(2) == 1;
            let value = hex_value(&mut r, 32, upper);
            out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Config>\n");
            out.push_str("  <LogLevel>info</LogLevel>\n  <Port>8989</Port>\n");
            writeln!(out, "  <{name}>{value}</{name}>").unwrap();
            out.push_str("  <AuthenticationMethod>Forms</AuthenticationMethod>\n</Config>\n");
        }
        "config_json_credential_object" => {
            let (parent, members) = CREDENTIAL_OBJECTS[r.below(CREDENTIAL_OBJECTS.len())];
            let compact = r.below(2) == 0;
            // A leading member that the filters reject (no digit) must not
            // hide the keys after it.
            let mut pairs = vec!["\"comment\": \"rotate-every-ninety-days\"".to_string()];
            pairs.extend(
                members
                    .iter()
                    .map(|m| format!("\"{m}\": \"{}\"", hex_value(&mut r, 32, true))),
            );
            if compact {
                writeln!(out, "{{\"{parent}\": {{{}}}}}", pairs.join(", ")).unwrap();
            } else {
                out.push_str("{\n  \"mqtt\": {\"host\": \"localhost\", \"port\": 1883},\n");
                writeln!(
                    out,
                    "  \"{parent}\": {{\n    {}\n  }}\n}}",
                    pairs.join(",\n    ")
                )
                .unwrap();
            }
        }
        "config_yaml_credential_mapping" => {
            let (parent, members) = CREDENTIAL_OBJECTS[r.below(CREDENTIAL_OBJECTS.len())];
            let nested = r.below(2) == 0;
            let indent = if nested { "  " } else { "" };
            if nested {
                out.push_str("zwave:\n  port: /dev/ttyUSB0\n");
            }
            writeln!(out, "{indent}{parent}: # rotated quarterly").unwrap();
            writeln!(out, "{indent}  comment: rotate-every-ninety-days").unwrap();
            for (i, m) in members.iter().enumerate() {
                let v = hex_value(&mut r, 32, true);
                if i % 2 == 0 {
                    writeln!(out, "{indent}  {m}: {v}").unwrap();
                } else {
                    writeln!(out, "{indent}  {m}: \"{v}\"").unwrap();
                }
            }
            // A file path as the last member, at the end of the file without a
            // final line feed, must not hide the keys before it.
            write!(out, "{indent}  ca_file: ./certs/client-ca2.pem").unwrap();
        }
        "otpauth_no_secret" => {
            writeln!(
                out,
                "otpauth://totp/Example%20Co:user@example.test?issuer=Example%20Co&digits=6"
            )
            .unwrap();
        }
        "otpauth_short_secret" => {
            writeln!(
                out,
                "otpauth://totp/Example:user@example.test?secret=ABC234&issuer=Example"
            )
            .unwrap();
        }
        "otpauth_example_secret" => {
            // The public example seed used throughout one-time-password documentation.
            for seed in ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ", "base32secret3232"] {
                writeln!(
                    out,
                    "otpauth://totp/Example:alice@example.test?secret={seed}&issuer=Example"
                )
                .unwrap();
            }
        }
        "base32_outside_uri" => {
            writeln!(out, "# base32 identifiers, not one-time-password seeds").unwrap();
            writeln!(out, "bucket_id = {}", r.pick(BASE32, 32)).unwrap();
            writeln!(
                out,
                "see https://example.test/docs/otpauth for the URI format"
            )
            .unwrap();
        }
        "bitwarden_encrypted_json" => {
            let mut blob = vec![0u8; 96];
            r.fill(&mut blob);
            writeln!(
                out,
                "{{\n  \"encrypted\": true,\n  \"encKeyValidation_DO_NOT_EDIT\": \"2.{}\",\n  \"data\": \"2.{}\"\n}}",
                base64(&blob[..32]),
                base64(&blob[32..])
            )
            .unwrap();
        }
        "users_csv" => {
            writeln!(
                out,
                "{}",
                csv_row(&["id", "username", "password_hash", "email"])
            )
            .unwrap();
            for i in 0..5 {
                writeln!(
                    out,
                    "{i},user{i},{},user{i}@example.test",
                    r.pick(LOWER_HEX, 40)
                )
                .unwrap();
            }
        }
        "lastpass_header_only" => {
            let head = csv_row(&[
                "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
            ]);
            writeln!(out, "{head}").unwrap();
        }
        "recovery_prose" => {
            out.push_str(
                "## Recovery codes\n\nIf you lose your device, use one of your backup codes to sign in. \
                 Codes can be regenerated from the security settings, and each one works once.\n",
            );
        }
        "hex_pairs_unlabelled" => {
            out.push_str("# build ids\n");
            out.push_str(&hex_pair_lines(&mut r, 16));
        }
        "recovery_few_codes" => {
            out.push_str("Backup codes\n");
            out.push_str(&hex_pair_lines(&mut r, 3));
        }
        "recovery_large_document" => {
            out.push_str("Backup codes\n\n");
            out.push_str(&source_text(9000, seed));
            out.push_str(&hex_pair_lines(&mut r, 16));
        }
        "recovery_source_like" => {
            // Source lines that start with a ten-letter word: not codes.
            out.push_str("Backup codes helper\n\n");
            for w in [
                "background",
                "javascript",
                "definition",
                "initialize",
                "expression",
                "assertThat",
            ] {
                writeln!(out, "    {w}(value);").unwrap();
            }
        }
        "recovery_digit_at_ends" => {
            // Ten-character codes whose only digit is the first or the last character.
            out.push_str("Your recovery codes\n\n");
            for i in 0..10 {
                let letters = r.pick(b"abcdefghijklmnopqrstuvwxyz", 9);
                let digit = r.pick(b"0123456789", 1);
                if i % 2 == 0 {
                    writeln!(out, "{digit}{letters}").unwrap();
                } else {
                    writeln!(out, "{letters}{digit}").unwrap();
                }
            }
        }
        "otpauth_lowercase_secret" => {
            let uri = otpauth_uri(&mut r, "totp", 1);
            writeln!(out, "{}", uri.to_lowercase()).unwrap();
        }
        // .NET `appSettings`: `<add key="…" value="…" />`, with the
        // attributes in either order and `name` in place of `key`.
        "config_dotnet_app_settings" => {
            let name = XML_CREDENTIAL_ELEMENTS[r.below(XML_CREDENTIAL_ELEMENTS.len())];
            let upper = r.below(2) == 1;
            let value = hex_value(&mut r, 32, upper);
            let attr = if r.below(2) == 0 { "key" } else { "name" };
            let key = if r.below(2) == 0 {
                name.to_string()
            } else {
                format!("Billing:{name}")
            };
            out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n");
            out.push_str("  <appSettings>\n    <add key=\"Environment\" value=\"Production\" />\n");
            if r.below(2) == 0 {
                writeln!(out, "    <add {attr}=\"{key}\" value=\"{value}\" />").unwrap();
            } else {
                writeln!(out, "    <add value=\"{value}\" {attr}=\"{key}\"/>").unwrap();
            }
            out.push_str("  </appSettings>\n</configuration>\n");
        }
        // A credential-named key on one line with a hex value that
        // `generic_api_key`'s entropy minimum drops.
        "config_key_hex_low_entropy" => {
            let v = hex_value_low_entropy(&mut r);
            match r.below(4) {
                0 => writeln!(out, "{{\n  \"user\": \"svc\",\n  \"apiKey\": \"{v}\"\n}}").unwrap(),
                1 => writeln!(out, "service:\n  api_key: {v}").unwrap(),
                2 => writeln!(out, "API_TOKEN={v}").unwrap(),
                _ => writeln!(out, "[oauth]\nclient_secret = \"{v}\"").unwrap(),
            }
        }
        // A member that is credential-named itself inside a credential
        // mapping: `generic_api_key` and the mapping rule both find it.
        "config_yaml_credential_named_member" => {
            let mut v = hex_value(&mut r, 32, false);
            while shannon(&v) < 3.5 {
                v = hex_value(&mut r, 32, false);
            }
            writeln!(out, "credentials:\n  token: {v}").unwrap();
        }
        // Hex and token values under names that hold no credential: public
        // keys, a bare `Key` (S3 listings, property lists), primary keys, and
        // pagination tokens.
        "config_xml_non_secret" => {
            out.push_str("<Config>\n");
            writeln!(
                out,
                "  <PublicKey>{}</PublicKey>",
                hex_value(&mut r, 64, false)
            )
            .unwrap();
            writeln!(out, "  <Key>{}</Key>", hex_value(&mut r, 32, false)).unwrap();
            writeln!(
                out,
                "  <PublicSigningKey>{}</PublicSigningKey>",
                hex_value(&mut r, 64, false)
            )
            .unwrap();
            writeln!(
                out,
                "  <PublicKeyToken>{}</PublicKeyToken>",
                hex_value(&mut r, 16, false)
            )
            .unwrap();
            writeln!(out, "  <NextToken>{}</NextToken>", r.pick(BASE62, 40)).unwrap();
            writeln!(
                out,
                "  <PrimaryKey>{}</PrimaryKey>",
                hex_value(&mut r, 32, false)
            )
            .unwrap();
            out.push_str("</Config>\n");
        }
        "config_json_non_secret" => {
            // One settings document: UUID key ids and subjects, public keys
            // (also behind a qualifier), a bare `keys` object, hotkeys, and
            // design tokens.
            writeln!(
                out,
                "{{\"Credentials\": {{\"Kid\": \"{}\", \"Sub\": \"{}\"}},",
                uuid_text(&mut r),
                uuid_text(&mut r)
            )
            .unwrap();
            writeln!(
                out,
                " \"publicKeys\": {{\"main\": \"{}\"}}, \"publicSigningKeys\": {{\"main\": \"{}\"}},",
                hex_value(&mut r, 64, false),
                hex_value(&mut r, 64, false)
            )
            .unwrap();
            writeln!(
                out,
                " \"keys\": {{\"id\": \"{}\"}}, \"hotkeys\": {{\"save\": \"{}\"}},",
                hex_value(&mut r, 32, false),
                hex_value(&mut r, 32, false)
            )
            .unwrap();
            writeln!(
                out,
                " \"tokens\": {{\"color\": \"{}\"}}}}",
                hex_value(&mut r, 32, false)
            )
            .unwrap();
        }
        // `appSettings` entries that hold no credential: public keys, a
        // non-credential key with a hex value, a placeholder, a template, and
        // a UUID under a credential name.
        "config_dotnet_non_secret" => {
            out.push_str("<configuration>\n  <appSettings>\n");
            writeln!(
                out,
                "    <add key=\"PublicKey\" value=\"{}\" />",
                hex_value(&mut r, 64, false)
            )
            .unwrap();
            writeln!(
                out,
                "    <add value=\"{}\" key=\"PublicSigningKey\" />",
                hex_value(&mut r, 64, false)
            )
            .unwrap();
            writeln!(
                out,
                "    <add key=\"BuildId\" value=\"{}\" />",
                hex_value(&mut r, 32, false)
            )
            .unwrap();
            out.push_str("    <add key=\"ApiKey\" value=\"your-api-key-goes-here\" />\n");
            out.push_str("    <add key=\"AuthToken\" value=\"${AUTH_TOKEN}\" />\n");
            writeln!(
                out,
                "    <add key=\"ClientSecret\" value=\"{}\" />",
                uuid_text(&mut r)
            )
            .unwrap();
            out.push_str("  </appSettings>\n</configuration>\n");
        }
        // Hex values under names that are not credential nouns: no rule
        // may flag them. (Short or sequential values under credential names
        // are `generic_api_key`'s to judge, which flags some by design.)
        "config_key_hex_non_secret" => {
            writeln!(out, "key_sha256: {}", hex_value_low_entropy(&mut r)).unwrap();
            writeln!(out, "commit_sha: {}", hex_value(&mut r, 40, false)).unwrap();
            writeln!(out, "cache_key: {}", hex_value_low_entropy(&mut r)).unwrap();
        }
        "config_yaml_non_secret" => {
            writeln!(out, "publicKeys:\n  main: {}", hex_value(&mut r, 64, false)).unwrap();
            writeln!(
                out,
                "publicEncryptionKeys:\n  main: {}",
                hex_value(&mut r, 64, false)
            )
            .unwrap();
            writeln!(out, "keys:\n  id: {}", hex_value(&mut r, 32, false)).unwrap();
            writeln!(
                out,
                "primaryKeys:\n  users: {}",
                hex_value(&mut r, 32, false)
            )
            .unwrap();
            writeln!(out, "credentials:\n  user: admin").unwrap();
            writeln!(out, "other: {}", hex_value(&mut r, 32, false)).unwrap();
            // A sibling of an indented credential mapping is outside it.
            writeln!(out, "app:\n  secrets:\n    enabled: true").unwrap();
            writeln!(out, "  build_id: {}", hex_value(&mut r, 32, false)).unwrap();
        }
        // 1Password 1PIF: one JSON record per line, each followed by the
        // fixed separator line.
        "onepassword_1pif" | "onepassword_1pif_no_password" => {
            let with_password = kind == "onepassword_1pif";
            let sep = ["***", "5642bee8", "-a5ff-11dc-8314-0800200c9a66", "***"].concat();
            for l in logins(&mut r, 3) {
                let id = r.pick(LOWER36, 26);
                let pw = if with_password {
                    format!(
                        ",{{\"value\":\"{}\",\"id\":\"\",\"name\":\"password\",\"type\":\"P\",\"designation\":\"password\"}}",
                        l.password.replace('"', "")
                    )
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "{{\"uuid\":\"{id}\",\"updatedAt\":1486071244,\"securityLevel\":\"SL5\",\"contentsHash\":\"aaaaaaaa\",\
                     \"title\":\"{}\",\"location\":\"{}\",\"secureContents\":{{\"fields\":[\
                     {{\"value\":\"{}\",\"id\":\"\",\"name\":\"username\",\"type\":\"T\",\"designation\":\"username\"}}{pw}],\
                     \"URLs\":[{{\"label\":\"website\",\"url\":\"{}\"}}]}},\"typeName\":\"webforms.WebForm\"}}",
                    l.name, l.url, l.user, l.url
                )
                .unwrap();
                writeln!(out, "{sep}").unwrap();
            }
        }
        // Firefox saved-logins export (`LoginExport.sys.mjs`): every field
        // quoted, `origin` labelled `url`.
        "firefox_csv" | "firefox_csv_header_only" => {
            let head = [
                "url",
                "username",
                "password",
                "httpRealm",
                "formActionOrigin",
                "guid",
                "timeCreated",
                "timeLastUsed",
                "timePasswordChanged",
            ]
            .map(|c| format!("\"{c}\""))
            .join(",");
            write!(out, "{head}\r\n").unwrap();
            if kind == "firefox_csv" {
                for l in logins(&mut r, 5) {
                    let guid = uuid_text(&mut r);
                    write!(
                        out,
                        "\"{}\",\"{}\",\"{}\",,\"{}\",\"{{{guid}}}\",\"1600000000000\",\"1600000000000\",\"1600000000000\"\r\n",
                        l.url, l.user, l.password, l.url
                    )
                    .unwrap();
                }
            }
        }
        // KeePass 2.x "KeePass XML (2.x)" export: values in plain text.
        "keepass_xml" | "keepass_xml_no_password" => {
            let with_password = kind == "keepass_xml";
            out.push_str(
                "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>\n\t<Meta>\n\t\t<Generator>KeePass</Generator>\n\t</Meta>\n\t<Root>\n\t\t<Group>\n\t\t\t<Name>Database</Name>\n",
            );
            for l in logins(&mut r, 3) {
                let pw = if with_password {
                    l.password.replace('&', "&amp;").replace('<', "&lt;")
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "\t\t\t<Entry>\n\t\t\t\t<String>\n\t\t\t\t\t<Key>Title</Key>\n\t\t\t\t\t<Value>{}</Value>\n\t\t\t\t</String>\n\t\t\t\t<String>\n\t\t\t\t\t<Key>UserName</Key>\n\t\t\t\t\t<Value>{}</Value>\n\t\t\t\t</String>\n\t\t\t\t<String>\n\t\t\t\t\t<Key>Password</Key>\n\t\t\t\t\t<Value ProtectInMemory=\"True\">{pw}</Value>\n\t\t\t\t</String>\n\t\t\t</Entry>",
                    l.name, l.user
                )
                .unwrap();
            }
            out.push_str("\t\t</Group>\n\t</Root>\n</KeePassFile>\n");
        }
        // KeePass "CSV (1.x)" columns and the KeePassXC export columns.
        "keepass_csv" | "keepass_csv_header_only" => {
            let head = ["Account", "Login Name", "Password", "Web Site", "Comments"]
                .map(|c| format!("\"{c}\""))
                .join(",");
            writeln!(out, "{head}").unwrap();
            if kind == "keepass_csv" {
                for l in logins(&mut r, 5) {
                    writeln!(
                        out,
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"\"",
                        l.name, l.user, l.password, l.url
                    )
                    .unwrap();
                }
            }
        }
        "keepassxc_csv" => {
            let head = [
                "Group",
                "Title",
                "Username",
                "Password",
                "URL",
                "Notes",
                "TOTP",
                "Icon",
                "Last Modified",
                "Created",
            ]
            .map(|c| format!("\"{c}\""))
            .join(",");
            writeln!(out, "{head}").unwrap();
            for l in logins(&mut r, 5) {
                writeln!(
                    out,
                    "\"Root/General\",\"{}\",\"{}\",\"{}\",\"{}\",\"\",\"\",\"0\",\"2026-10-01T00:00:00Z\",\"2026-10-01T00:00:00Z\"",
                    l.name, l.user, l.password, l.url
                )
                .unwrap();
            }
        }
        // The six columns KeePassXC wrote before TOTP, Icon, Last Modified,
        // and Created were added (CsvExporter.cpp at tags 2.4.0 to 2.6.2).
        "keepassxc_csv_six" | "keepassxc_csv_six_header_only" => {
            let head = ["Group", "Title", "Username", "Password", "URL", "Notes"]
                .map(|c| format!("\"{c}\""))
                .join(",");
            writeln!(out, "{head}").unwrap();
            if kind == "keepassxc_csv_six" {
                for l in logins(&mut r, 5) {
                    writeln!(
                        out,
                        "\"Root/General\",\"{}\",\"{}\",\"{}\",\"{}\",\"\"",
                        l.name, l.user, l.password, l.url
                    )
                    .unwrap();
                }
            }
        }
        // Dashlane credentials export (`credentials.csv`).
        "dashlane_csv" => {
            let head = csv_row(&[
                "username",
                "username2",
                "username3",
                "title",
                "password",
                "note",
                "url",
                "category",
                "otpSecret",
            ]);
            writeln!(out, "{head}").unwrap();
            for l in logins(&mut r, 5) {
                writeln!(
                    out,
                    "{},,,{},\"{}\",,{},Shopping,",
                    l.user, l.name, l.password, l.url
                )
                .unwrap();
            }
        }
        // Dashlane JSON export: credentials under the `AUTHENTIFIANT` key.
        "dashlane_json" | "dashlane_json_no_password" => {
            let with_password = kind == "dashlane_json";
            out.push_str("{\"AUTHENTIFIANT\":[");
            for (i, l) in logins(&mut r, 3).iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let pw = if with_password {
                    l.password.replace('"', "")
                } else {
                    String::new()
                };
                write!(
                    out,
                    "{{\"title\":\"{}\",\"login\":\"{}\",\"password\":\"{pw}\",\"domain\":\"{}\",\"note\":\"\"}}",
                    l.name, l.user, l.url
                )
                .unwrap();
            }
            out.push_str("],\"EMAIL\":[]}\n");
        }
        // Keeper JSON export (documented import/export layout): shared
        // folders and records with `login`, `password`, and `login_url`.
        "keeper_json" => {
            out.push_str("{\n  \"shared_folders\": [],\n  \"records\": [\n");
            let list = logins(&mut r, 3);
            for (i, l) in list.iter().enumerate() {
                let sep = if i + 1 < list.len() { "," } else { "" };
                writeln!(
                    out,
                    "    {{\n      \"title\": \"{}\",\n      \"login\": \"{}\",\n      \"password\": \"{}\",\n      \"login_url\": \"{}\",\n      \"notes\": \"\",\n      \"folders\": [{{\"folder\": \"Personal\"}}]\n    }}{sep}",
                    l.name, l.user, l.password.replace('"', ""), l.url
                )
                .unwrap();
            }
            out.push_str("  ]\n}\n");
        }
        // A records list that is not a Keeper export.
        "keeper_json_unrelated" => {
            out.push_str("{\n  \"records\": [\n");
            for i in 0..3 {
                let sep = if i < 2 { "," } else { "" };
                writeln!(
                    out,
                    "    {{\"id\": {i}, \"name\": \"item {i}\", \"password_policy\": \"strong\", \"hash\": \"{}\"}}{sep}",
                    r.pick(LOWER_HEX, 40)
                )
                .unwrap();
            }
            out.push_str("  ]\n}\n");
        }
        // Proton Pass CSV export: the writer emits the object keys in order.
        "protonpass_csv" | "protonpass_csv_header_only" => {
            let head = csv_row(&[
                "type",
                "name",
                "url",
                "autofillUrls",
                "email",
                "username",
                "password",
                "note",
                "totp",
                "createTime",
                "modifyTime",
                "vault",
            ]);
            writeln!(out, "{head}").unwrap();
            if kind == "protonpass_csv" {
                for l in logins(&mut r, 5) {
                    writeln!(
                        out,
                        "login,{},{},,{},{},\"{}\",,,1600000000,1600000000,Personal",
                        l.name, l.url, l.user, l.user, l.password
                    )
                    .unwrap();
                }
            }
        }
        // Proton Pass JSON export (unencrypted ZIP or the decrypted file).
        "protonpass_json" | "protonpass_json_encrypted" => {
            if kind == "protonpass_json_encrypted" {
                let mut blob = vec![0u8; 96];
                r.fill(&mut blob);
                writeln!(
                    out,
                    "{{\"version\":\"1.21.2\",\"userId\":\"{}\",\"encrypted\":true,\"vaults\":\"{}\"}}",
                    r.pick(BASE62, 44),
                    base64(&blob)
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "{{\n  \"version\": \"1.21.2\",\n  \"userId\": \"{}\",\n  \"encrypted\": false,\n  \"vaults\": {{\n    \"{}\": {{\n      \"name\": \"Personal\",\n      \"description\": \"\",\n      \"items\": [",
                    r.pick(BASE62, 44),
                    r.pick(BASE62, 44)
                )
                .unwrap();
                let list = logins(&mut r, 3);
                for (i, l) in list.iter().enumerate() {
                    let sep = if i + 1 < list.len() { "," } else { "" };
                    writeln!(
                        out,
                        "        {{\"itemId\": \"{}\", \"data\": {{\"metadata\": {{\"name\": \"{}\", \"note\": \"\"}}, \"type\": \"login\", \"content\": {{\"itemUsername\": \"{}\", \"password\": \"{}\", \"urls\": [\"{}\"], \"totpUri\": \"\"}}}}}}{sep}",
                        r.pick(BASE62, 24),
                        l.name,
                        l.user,
                        l.password.replace('"', ""),
                        l.url
                    )
                    .unwrap();
                }
                out.push_str("      ]\n    }\n  }\n}\n");
            }
        }
        // KeePass XML key files, version 1.00 (base64 key) and 2.0 (hex key
        // with a check hash).
        "keepass_key_file_v1" => {
            let mut key = [0u8; 32];
            r.fill(&mut key);
            writeln!(
                out,
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>1.00</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data>{}</Data>\n\t</Key>\n</KeyFile>",
                base64(&key)
            )
            .unwrap();
        }
        "keepass_key_file_v2" => {
            let hex = r.pick(b"0123456789ABCDEF", 64);
            let groups: Vec<&str> = (0..8).map(|i| &hex[i * 8..i * 8 + 8]).collect();
            writeln!(
                out,
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"{}\">\n\t\t\t{}\n\t\t\t{}\n\t\t</Data>\n\t</Key>\n</KeyFile>",
                r.pick(b"0123456789ABCDEF", 8),
                groups[..4].join(" "),
                groups[4..].join(" ")
            )
            .unwrap();
        }
        // XML with `Key` and `Data` elements that is not a key file.
        "keepass_key_file_lookalike" => {
            out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Settings>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n");
            writeln!(
                out,
                "\t<Key>\n\t\t<Data>{}</Data>\n\t</Key>\n</Settings>",
                r.pick(BASE62, 44)
            )
            .unwrap();
        }
        // A one-time-password URI inside a QR-code image link, percent-encoded.
        "otpauth_encoded" => {
            let secret = r.pick(BASE32, 32);
            writeln!(
                out,
                "<img src=\"https://qr.example.test/chart?size=200x200&data=otpauth%3A%2F%2Ftotp%2FExample%3Auser%40example.test%3Fsecret%3D{secret}%26issuer%3DExample\">"
            )
            .unwrap();
        }
        "otpauth_encoded_example_secret" => {
            for seed in ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ"] {
                writeln!(
                    out,
                    "<img src=\"https://qr.example.test/chart?data=otpauth%3A%2F%2Ftotp%2FExample%3Aalice%40example.test%3Fsecret%3D{seed}%26issuer%3DExample\">"
                )
                .unwrap();
            }
        }
        "otpauth_encoded_no_secret" => {
            writeln!(
                out,
                "<img src=\"https://qr.example.test/chart?data=otpauth%3A%2F%2Ftotp%2FExample%3Auser%40example.test%3Fissuer%3DExample%26digits%3D6\">"
            )
            .unwrap();
        }
        other => panic!("unknown credential file kind `{other}`"),
    }
    out.into_bytes()
}

/// `[limits]` configuration under which [`partly_read_files`] are read in part.
pub const PART_LIMITS: &str = "[limits]\ntext_max = 1024\nsample = 256\n";

/// A file of one kind that is read only in part under [`PART_LIMITS`].
pub struct PartlyRead {
    pub kind: &'static str,
    pub name: &'static str,
    pub bytes: Vec<u8>,
    /// The `not_read` note its report carries.
    pub not_read: String,
}

fn encoded(text: &str, bom: &[u8], unit: impl Fn(u32) -> Vec<u8>) -> Vec<u8> {
    let mut out = bom.to_vec();
    out.extend(text.chars().flat_map(|c| unit(c as u32)));
    out
}

/// One file of each kind a scan reads in part, holding a fake credential in
/// the part read when `secret_read`, else in the part not read.
pub fn partly_read_files(secret_read: bool) -> Vec<PartlyRead> {
    let key = format!("key = \"{}\"\n", fake_secret("aws_access_key", 21));
    let filler = "plain text line\n".repeat(128);
    let text = if secret_read {
        format!("{key}{filler}{filler}")
    } else {
        format!("{filler}{key}{filler}")
    };
    let ends = |n: usize| format!("bytes 256..{} not read", n - 256);

    let utf16 = encoded(&text, &[0xFF, 0xFE], |c| (c as u16).to_le_bytes().to_vec());
    let utf32 = encoded(&text, &[0xFF, 0xFE, 0, 0], |c| c.to_le_bytes().to_vec());

    // A DER private key when the credential is read, a DER header no key
    // rule matches otherwise; either way the file runs past the text limit.
    let mut der = if secret_read {
        let mut body = vec![0u8; 0x40];
        Rng::new(21).fill(&mut body);
        let mut b = vec![0x30, 0x46, 0x02, 0x01, 0x00, 0x02];
        b.extend(body);
        b.extend(std::iter::repeat_n(b' ', 2048));
        b
    } else {
        let mut b = vec![0x30, 0x81, 0xFF, 0x06, 0x03, 0x55, 0x04, 0x03];
        b.extend(std::iter::repeat_n(b' ', 2048));
        b.extend_from_slice(key.as_bytes());
        b
    };
    der.push(b'\n');

    // A version 2.0 `.npy` header longer than the text limit.
    let pad = " ".repeat(2048);
    let dict = if secret_read {
        format!("{{'descr': '<f4', 'note': '{key}', 'shape': (4,), }}{pad}\n")
    } else {
        format!("{{'descr': '<f4', 'shape': (4,), }}{pad}{key}\n")
    };
    let mut npy = b"\x93NUMPY\x02\x00".to_vec();
    npy.extend_from_slice(&(dict.len() as u32).to_le_bytes());
    npy.extend_from_slice(dict.as_bytes());

    vec![
        PartlyRead {
            kind: "text",
            name: "big.txt",
            not_read: ends(text.len()),
            bytes: text.into_bytes(),
        },
        PartlyRead {
            kind: "utf-16 text",
            name: "big16.txt",
            not_read: ends(utf16.len()),
            bytes: utf16,
        },
        PartlyRead {
            kind: "utf-32 text",
            name: "big32.txt",
            not_read: ends(utf32.len()),
            bytes: utf32,
        },
        PartlyRead {
            kind: "key store",
            name: "big.der",
            not_read: format!("bytes 1024..{} not read", der.len()),
            bytes: der,
        },
        PartlyRead {
            kind: "npy header",
            name: "big.npy",
            not_read: format!("bytes 1024..{} not read", npy.len()),
            bytes: npy,
        },
    ]
}

/// A safetensors file whose header runs past the fixed read cap, written
/// sparsely: its first bytes, its last bytes, and its size.
pub struct SafetensorsPastCap {
    head: Vec<u8>,
    tail: Vec<u8>,
    size: u64,
}

/// A [`SafetensorsPastCap`] holding a fake credential in the part read when
/// `secret_read`, else in the part not read.
pub fn safetensors_past_cap(secret_read: bool) -> SafetensorsPastCap {
    let size = crate::classify::SAFETENSORS_CAP + 4096;
    let key = fake_secret("aws_access_key", 22);
    let mut head = (size - 8).to_le_bytes().to_vec();
    head.extend_from_slice(b"{\"__metadata__\":{\"note\":\"");
    if secret_read {
        head.extend_from_slice(key.as_bytes());
    }
    head.extend_from_slice(b"\"}");
    let tail = if secret_read {
        b"\n".to_vec()
    } else {
        format!("\nkey = \"{key}\"\n").into_bytes()
    };
    SafetensorsPastCap { head, tail, size }
}

impl SafetensorsPastCap {
    /// The `not_read` note its report carries.
    pub fn not_read(&self) -> String {
        format!(
            "bytes {}..{} not read",
            crate::classify::SAFETENSORS_CAP,
            self.size
        )
    }

    /// Write the file; the bytes between head and tail are a hole.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom};
        let mut f = std::fs::File::create(path)?;
        f.write_all(&self.head)?;
        f.set_len(self.size)?;
        f.seek(SeekFrom::Start(self.size - self.tail.len() as u64))?;
        f.write_all(&self.tail)
    }
}
