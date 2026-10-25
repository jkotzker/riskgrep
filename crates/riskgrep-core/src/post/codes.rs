//! Two-factor recovery-code lines in one linear pass.

use super::{Post, PostResult};
use std::ops::Range;

pub struct CodeLines {
    pub min_codes: u64,
}

/// The shapes a line of a recovery-code list can have.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Two groups of five lowercase hexadecimal characters joined by `-`.
    HexPair,
    /// Two groups of four digits joined by a space.
    DigitPair,
    /// Ten letters and digits with at least one digit.
    Alnum,
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// True when `rest` starts with `n` bytes that all satisfy `ok` and the code
/// ends there (end of line or a non-word byte).
fn code_of(rest: &[u8], n: usize, ok: impl Fn(usize, u8) -> bool) -> bool {
    rest.len() >= n
        && rest[..n].iter().enumerate().all(|(i, &b)| ok(i, b))
        && rest.get(n).is_none_or(|&b| !is_word(b))
}

/// The shape of one line: optional indentation and list number or bullet,
/// then a code.
fn shape_of(line: &[u8]) -> Option<Shape> {
    let skip_blanks = |mut i: usize| {
        while matches!(line.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        i
    };
    let mut i = skip_blanks(0);
    let digits = line[i..].iter().take_while(|b| b.is_ascii_digit()).count();
    if (1..=2).contains(&digits) && matches!(line.get(i + digits), Some(b'.' | b')')) {
        i = skip_blanks(i + digits + 1);
    } else if matches!(line.get(i), Some(b'-' | b'*')) {
        i = skip_blanks(i + 1);
    }
    let rest = &line[i..];
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if code_of(rest, 11, |k, b| if k == 5 { b == b'-' } else { hex(b) }) {
        Some(Shape::HexPair)
    } else if code_of(rest, 9, |k, b| {
        if k == 4 {
            b == b' '
        } else {
            b.is_ascii_digit()
        }
    }) {
        Some(Shape::DigitPair)
    } else if code_of(rest, 10, |_, b| b.is_ascii_alphanumeric())
        && rest[..10].iter().any(u8::is_ascii_digit)
    {
        Some(Shape::Alnum)
    } else {
        None
    }
}

/// The lines (without their line ending) of the most common code shape,
/// when at least `min` lines have it; empty otherwise. One pass over `c`.
pub fn code_line_runs(c: &[u8], min: u64) -> Vec<Range<usize>> {
    let mut lines: [Vec<Range<usize>>; 3] = Default::default();
    let mut start = 0;
    while start < c.len() {
        let end = c[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(c.len(), |p| start + p);
        let line = &c[start..end];
        if let Some(shape) = shape_of(line) {
            lines[shape as usize]
                .push(start..start + line.strip_suffix(b"\r").unwrap_or(line).len());
        }
        start = end + 1;
    }
    lines
        .into_iter()
        .max_by_key(Vec::len)
        .filter(|l| l.len() as u64 >= min)
        .unwrap_or_default()
}

impl Post for CodeLines {
    fn apply(&self, _content: &[u8], m: Range<usize>) -> PostResult {
        PostResult::Keep(m)
    }

    fn runs(&self, content: &[u8]) -> Option<Vec<Range<usize>>> {
        Some(code_line_runs(content, self.min_codes))
    }
}
