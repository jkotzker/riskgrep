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

/// A version 1.0 `.npy` file. Float dtypes (`<f4`, `<f8`, `<f2`) get random
/// finite values; other dtypes get random bytes.
pub fn npy(dtype: &str, shape: &[u64]) -> Vec<u8> {
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
    let mut data = vec![0u8; offset as usize];
    Rng::new(offset).fill(&mut data);
    out.extend_from_slice(&data);
    out
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
