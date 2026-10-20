//! Tensor file header tests. Parsers take untrusted bytes and never panic:
//! every malformed input becomes `Drop`.

use super::{Post, PostResult};
use crate::model::ShapeFacts;
use regex::bytes::Regex;
use std::io::{Cursor, Read};
use std::ops::Range;

const NPY_MAGIC: &[u8] = b"\x93NUMPY";
/// Bytes read from each `.npy` member of an archive.
const NPZ_MEMBER_BYTES: u64 = 4096;
/// Archive members examined per file.
const NPZ_MAX_MEMBERS: usize = 1024;
/// Largest safetensors JSON header accepted.
const SAFETENSORS_HEADER_MAX: u64 = 104_857_600;

fn is_float(dtype: &str) -> bool {
    matches!(dtype, "f2" | "f4" | "f8" | "F16" | "BF16" | "F32" | "F64")
}

/// Leading dimensions an embedding-shaped tensor may have: `[d]`, `[n, d]`,
/// or `[a, b, d]`.
const MAX_LEADING_DIMS: usize = 2;

/// A shape qualifies when some dimension is at least `min_dim` and, with
/// `embedding_dims`, the last dimension is one of them and at most
/// [`MAX_LEADING_DIMS`] dimensions precede it.
fn shape_qualifies(shape: &[u64], min_dim: u64, embedding_dims: Option<&[u64]>) -> bool {
    if !shape.iter().any(|&d| d >= min_dim) {
        return false;
    }
    match (embedding_dims, shape.split_last()) {
        (None, _) => true,
        (Some(dims), Some((last, lead))) => dims.contains(last) && lead.len() <= MAX_LEADING_DIMS,
        (Some(_), None) => false,
    }
}

fn value_after<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let pos = header.find(key)? + key.len();
    let rest = header[pos..].trim_start().strip_prefix(':')?;
    Some(rest.trim_start())
}

fn parse_npy_header(header: &str) -> Option<(String, Vec<u64>)> {
    let descr = value_after(header, "'descr'")?;
    let quote = descr.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let body = &descr[1..];
    let descr = &body[..body.find(quote)?];

    let shape = value_after(header, "'shape'")?.strip_prefix('(')?;
    let shape = &shape[..shape.find(')')?];
    let dims = shape
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches(['L', 'l']).parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()?;
    Some((descr.to_string(), dims))
}

/// Dtype and shape of an `.npy` buffer when it is a float array whose shape
/// qualifies (see [`shape_qualifies`]).
fn npy_qualifies(
    data: &[u8],
    min_dim: u64,
    embedding_dims: Option<&[u64]>,
) -> Option<(String, Vec<u64>)> {
    if data.get(..6)? != NPY_MAGIC {
        return None;
    }
    let (len, start): (usize, usize) = match *data.get(6)? {
        1 => (
            u16::from_le_bytes(data.get(8..10)?.try_into().ok()?) as usize,
            10usize,
        ),
        2 | 3 => (
            u32::from_le_bytes(data.get(8..12)?.try_into().ok()?) as usize,
            12,
        ),
        _ => return None,
    };
    let header = data.get(start..start.checked_add(len)?)?;
    let (dtype, shape) = parse_npy_header(std::str::from_utf8(header).ok()?)?;
    let kind = dtype.trim_start_matches(['<', '>', '|', '=']);
    (is_float(kind) && shape_qualifies(&shape, min_dim, embedding_dims)).then_some((dtype, shape))
}

pub struct NpyHeader {
    pub min_dim: u64,
    /// Require an embedding-shaped array with one of these last dimensions.
    pub embedding_dims: Option<Vec<u64>>,
}

impl Post for NpyHeader {
    fn whole_content(&self) -> bool {
        true
    }

    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        match npy_qualifies(content, self.min_dim, self.embedding_dims.as_deref()) {
            Some((dtype, shape)) => PostResult::KeepWithShape(
                m,
                ShapeFacts::Tensor {
                    dtype,
                    shape,
                    name: None,
                },
            ),
            None => PostResult::Drop,
        }
    }
}

pub struct NpzMembers {
    pub min_dim: u64,
    /// Require an embedding-shaped member with one of these last dimensions.
    pub embedding_dims: Option<Vec<u64>>,
}

impl Post for NpzMembers {
    fn whole_content(&self) -> bool {
        true
    }

    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(content)) else {
            return PostResult::Drop;
        };
        for i in 0..zip.len().min(NPZ_MAX_MEMBERS) {
            let Ok(file) = zip.by_index(i) else { continue };
            let Some(name) = file.name().strip_suffix(".npy").map(str::to_string) else {
                continue;
            };
            let mut head = Vec::new();
            if file.take(NPZ_MEMBER_BYTES).read_to_end(&mut head).is_err() {
                continue;
            }
            if let Some((dtype, shape)) =
                npy_qualifies(&head, self.min_dim, self.embedding_dims.as_deref())
            {
                return PostResult::KeepWithShape(
                    m,
                    ShapeFacts::Tensor {
                        dtype,
                        shape,
                        name: Some(name),
                    },
                );
            }
        }
        PostResult::Drop
    }
}

pub struct SafetensorsHeader {
    pub min_dim: u64,
    pub name_regex: Option<Regex>,
    /// Require an embedding-shaped tensor with one of these last dimensions.
    pub embedding_dims: Option<Vec<u64>>,
    /// Tensors whose names match are ignored (layer parameters).
    pub exclude_name_regex: Option<Regex>,
    /// Files with more tensors than this (model layouts) never qualify.
    pub max_tensors: Option<u64>,
}

impl SafetensorsHeader {
    fn qualifying(&self, content: &[u8]) -> Option<ShapeFacts> {
        let len = u64::from_le_bytes(content.get(..8)?.try_into().ok()?);
        if len > SAFETENSORS_HEADER_MAX {
            return None;
        }
        let end = 8usize.checked_add(usize::try_from(len).ok()?)?;
        let json: serde_json::Value = serde_json::from_slice(content.get(8..end)?).ok()?;
        if let Some(max) = self.max_tensors {
            let n = json
                .as_object()?
                .keys()
                .filter(|k| *k != "__metadata__")
                .count();
            if n as u64 > max {
                return None;
            }
        }
        // Smallest qualifying name wins, so the result does not depend on the
        // JSON object's iteration order.
        let mut best: Option<ShapeFacts> = None;
        for (name, entry) in json.as_object()? {
            if name == "__metadata__" {
                continue;
            }
            let Some(dtype) = entry.get("dtype").and_then(|d| d.as_str()) else {
                continue;
            };
            let Some(dims) = entry.get("shape").and_then(|s| s.as_array()) else {
                continue;
            };
            let Some(shape) = dims
                .iter()
                .map(|d| d.as_u64())
                .collect::<Option<Vec<u64>>>()
            else {
                continue;
            };
            let named = self
                .name_regex
                .as_ref()
                .is_none_or(|re| re.is_match(name.as_bytes()));
            let excluded = self
                .exclude_name_regex
                .as_ref()
                .is_some_and(|re| re.is_match(name.as_bytes()));
            if is_float(dtype)
                && named
                && !excluded
                && shape_qualifies(&shape, self.min_dim, self.embedding_dims.as_deref())
            {
                let better = match &best {
                    Some(ShapeFacts::Tensor { name: Some(n), .. }) => name < n,
                    _ => true,
                };
                if better {
                    best = Some(ShapeFacts::Tensor {
                        dtype: dtype.to_string(),
                        shape,
                        name: Some(name.clone()),
                    });
                }
            }
        }
        best
    }
}

impl Post for SafetensorsHeader {
    fn whole_content(&self) -> bool {
        true
    }

    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        match self.qualifying(content) {
            Some(shape) => PostResult::KeepWithShape(m, shape),
            None => PostResult::Drop,
        }
    }
}
