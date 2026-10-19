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
