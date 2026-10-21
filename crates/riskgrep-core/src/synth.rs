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
