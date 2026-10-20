//! Tensor file header tests. Parsers take untrusted bytes and never panic:
//! every malformed input becomes `Drop`.

use super::{Post, PostResult};
use crate::model::ShapeFacts;
use regex::bytes::Regex;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::ops::Range;

const NPY_MAGIC: &[u8] = b"\x93NUMPY";
/// Bytes read from each `.npy` member of an archive.
pub(crate) const NPZ_MEMBER_BYTES: u64 = 4096;
/// Archive members examined per file.
pub(crate) const NPZ_MAX_MEMBERS: usize = 1024;
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

/// Dtype and shape of an `.npy` buffer holding a float array.
fn npy_float(data: &[u8]) -> Option<(String, Vec<u64>)> {
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
    is_float(kind).then_some((dtype, shape))
}

/// A bank of `count` identically shaped tensors qualifies when it has at
/// least `min` tensors and, with `share` (percent), makes up more than that
/// share of the file's `floats` float tensors.
fn bank_qualifies(count: u64, floats: u64, min: u64, share: Option<u64>) -> bool {
    count >= min && share.is_none_or(|s| count.saturating_mul(100) > s.saturating_mul(floats))
}

fn excluded(re: Option<&Regex>, name: &str) -> bool {
    re.is_some_and(|re| re.is_match(name.as_bytes()))
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
        match npy_float(content)
            .filter(|(_, s)| shape_qualifies(s, self.min_dim, self.embedding_dims.as_deref()))
        {
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
    /// Members whose names (without `.npy`) match are ignored.
    pub exclude_name_regex: Option<Regex>,
    /// Require at least this many qualifying members of one identical shape.
    pub min_bank: Option<u64>,
    /// With `min_bank`: the bank must be more than this percentage of the
    /// archive's float members.
    pub min_bank_share: Option<u64>,
}

impl Post for NpzMembers {
    fn whole_content(&self) -> bool {
        true
    }

    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(content)) else {
            return PostResult::Drop;
        };
        let mut floats = 0u64;
        // Per shape: member count, archive index of the first member, facts.
        let mut banks: BTreeMap<Vec<u64>, (u64, usize, ShapeFacts)> = BTreeMap::new();
        for i in 0..zip.len().min(NPZ_MAX_MEMBERS) {
            let Ok(file) = zip.by_index(i) else { continue };
            let Some(name) = file.name().strip_suffix(".npy").map(str::to_string) else {
                continue;
            };
            let mut head = Vec::new();
            if file.take(NPZ_MEMBER_BYTES).read_to_end(&mut head).is_err() {
                continue;
            }
            let Some((dtype, shape)) = npy_float(&head) else {
                continue;
            };
            floats += 1;
            if excluded(self.exclude_name_regex.as_ref(), &name)
                || !shape_qualifies(&shape, self.min_dim, self.embedding_dims.as_deref())
            {
                continue;
            }
            let facts = ShapeFacts::Tensor {
                dtype,
                shape: shape.clone(),
                name: Some(name),
            };
            if self.min_bank.is_none() {
                return PostResult::KeepWithShape(m, facts);
            }
            banks.entry(shape).or_insert((0, i, facts)).0 += 1;
        }
        let Some(min) = self.min_bank else {
            return PostResult::Drop;
        };
        // Archive order: the first member of the earliest qualifying bank.
        banks
            .into_values()
            .filter(|(n, _, _)| bank_qualifies(*n, floats, min, self.min_bank_share))
            .min_by_key(|(_, first, _)| *first)
            .map_or(PostResult::Drop, |(_, _, facts)| {
                PostResult::KeepWithShape(m, facts)
            })
    }
}

pub struct SafetensorsHeader {
    pub min_dim: u64,
    pub name_regex: Option<Regex>,
    /// Require an embedding-shaped tensor with one of these last dimensions.
    pub embedding_dims: Option<Vec<u64>>,
    /// Tensors whose names match are ignored (layer parameters).
    pub exclude_name_regex: Option<Regex>,
    /// Require at least this many qualifying tensors of one identical shape
    /// (an embedding bank: one vector per person).
    pub min_bank: Option<u64>,
    /// With `min_bank`: the bank must be more than this percentage of the
    /// file's float tensors.
    pub min_bank_share: Option<u64>,
}

impl SafetensorsHeader {
    fn qualifying(&self, content: &[u8]) -> Option<ShapeFacts> {
        let len = u64::from_le_bytes(content.get(..8)?.try_into().ok()?);
        if len > SAFETENSORS_HEADER_MAX {
            return None;
        }
        let end = 8usize.checked_add(usize::try_from(len).ok()?)?;
        let json: serde_json::Value = serde_json::from_slice(content.get(8..end)?).ok()?;
        // Smallest qualifying name wins (per shape, for banks), so the result
        // does not depend on the JSON object's iteration order.
        let mut best: Option<ShapeFacts> = None;
        let mut floats = 0u64;
        let mut banks: BTreeMap<Vec<u64>, (u64, String, String)> = BTreeMap::new();
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
            if !is_float(dtype) {
                continue;
            }
            floats += 1;
            let named = self
                .name_regex
                .as_ref()
                .is_none_or(|re| re.is_match(name.as_bytes()));
            if named
                && !excluded(self.exclude_name_regex.as_ref(), name)
                && shape_qualifies(&shape, self.min_dim, self.embedding_dims.as_deref())
            {
                if self.min_bank.is_some() {
                    let e =
                        banks
                            .entry(shape.clone())
                            .or_insert((0, name.clone(), dtype.to_string()));
                    e.0 += 1;
                    if *name < e.1 {
                        e.1 = name.clone();
                        e.2 = dtype.to_string();
                    }
                    continue;
                }
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
        if let Some(min) = self.min_bank {
            return banks
                .into_iter()
                .filter(|(_, (n, _, _))| bank_qualifies(*n, floats, min, self.min_bank_share))
                .min_by(|a, b| (a.1).1.cmp(&(b.1).1))
                .map(|(shape, (_, name, dtype))| ShapeFacts::Tensor {
                    dtype,
                    shape,
                    name: Some(name),
                });
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
