//! Printed-float run detection in one linear pass.

use super::{Post, PostResult};
use std::ops::Range;

pub struct FloatRun {
    pub min_floats: u64,
}

fn is_sep(b: u8) -> bool {
    matches!(b, b',' | b' ' | b'\t' | b'\r' | b'\n' | b'[' | b']')
}

fn digits_end(c: &[u8], mut i: usize) -> usize {
    while i < c.len() && c[i].is_ascii_digit() {
        i += 1;
    }
    i
}

/// Float token at `i`: `-?digits.digits([eE][-+]?digits)?`. `Ok(end)` or
/// `Err(next)` with the index to resume from (always > `i`), so no byte is
/// rescanned and the whole pass is linear.
fn float_at(c: &[u8], i: usize) -> Result<usize, usize> {
    let start = if c[i] == b'-' { i + 1 } else { i };
    let int_end = digits_end(c, start);
    if int_end == start {
        return Err(i + 1);
    }
    if c.get(int_end) != Some(&b'.') {
        return Err(int_end);
    }
    let frac_end = digits_end(c, int_end + 1);
    if frac_end == int_end + 1 {
        return Err(int_end + 1);
    }
    if matches!(c.get(frac_end), Some(b'e' | b'E')) {
        let mut e = frac_end + 1;
        if matches!(c.get(e), Some(b'+' | b'-')) {
            e += 1;
        }
        let exp_end = digits_end(c, e);
        if exp_end > e {
            return Ok(exp_end);
        }
    }
    Ok(frac_end)
}

/// Maximal runs of at least `min` floats separated by commas, whitespace, or
/// brackets. Each range spans first float start to last float end.
pub fn float_runs(c: &[u8], min: u64) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let (mut start, mut last_end, mut count) = (0usize, 0usize, 0u64);
    let mut sep_seen = false;
    let mut i = 0;
    let flush = |out: &mut Vec<Range<usize>>, start, last_end, count| {
        if count >= min && count > 0 {
            out.push(start..last_end);
        }
    };
    while i < c.len() {
        match float_at(c, i) {
            Ok(end) => {
                if count > 0 && sep_seen {
                    count += 1;
                } else {
                    flush(&mut out, start, last_end, count);
                    start = i;
                    count = 1;
                }
                last_end = end;
                sep_seen = false;
                i = end;
            }
            Err(next) => {
                if is_sep(c[i]) {
                    sep_seen = true;
                } else {
                    flush(&mut out, start, last_end, count);
                    count = 0;
                    sep_seen = false;
                }
                i = next;
            }
        }
    }
    flush(&mut out, start, last_end, count);
    out
}

impl Post for FloatRun {
    fn apply(&self, _content: &[u8], m: Range<usize>) -> PostResult {
        PostResult::Keep(m)
    }

    fn runs(&self, content: &[u8]) -> Option<Vec<Range<usize>>> {
        Some(float_runs(content, self.min_floats))
    }
}

/// Bracketed arrays (`[...]`) that hold only floats separated by commas or
/// whitespace and whose element count is one of `dims`, in one linear pass.
/// Each range spans the brackets. In a nested array (`[[...], [...]]`) each
/// innermost row is judged on its own.
pub fn float_arrays(c: &[u8], dims: &[u64]) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    // Open bracket of the array being read, its float count, and whether a
    // separator is due before the next float.
    let mut open: Option<usize> = None;
    let (mut count, mut need_sep) = (0u64, false);
    let mut i = 0;
    while i < c.len() {
        let b = c[i];
        if b == b'[' {
            open = Some(i);
            count = 0;
            need_sep = false;
            i += 1;
            continue;
        }
        let Some(start) = open else {
            i += 1;
            continue;
        };
        if b == b']' {
            if dims.contains(&count) {
                out.push(start..i + 1);
            }
            open = None;
            i += 1;
        } else if matches!(b, b',' | b' ' | b'\t' | b'\r' | b'\n') {
            need_sep = false;
            i += 1;
        } else {
            match float_at(c, i) {
                Ok(end) if !need_sep => {
                    count += 1;
                    need_sep = true;
                    i = end;
                }
                Ok(_) => {
                    open = None;
                    i += 1;
                }
                Err(next) => {
                    open = None;
                    i = next;
                }
            }
        }
    }
    out
}

/// Printed arrays of an embedding width; supplies its own evidence ranges
/// like [`FloatRun`].
pub struct FloatArray {
    pub embedding_dims: Vec<u64>,
}

impl Post for FloatArray {
    fn apply(&self, _content: &[u8], m: Range<usize>) -> PostResult {
        PostResult::Keep(m)
    }

    fn runs(&self, content: &[u8]) -> Option<Vec<Range<usize>>> {
        Some(float_arrays(content, &self.embedding_dims))
    }
}
