use super::{Post, PostResult};
use std::ops::Range;

/// Drops a match whose Shannon entropy (bits per byte) is below `min`.
pub struct Entropy {
    pub min: f64,
}

pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

impl Post for Entropy {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        match content.get(m.clone()) {
            Some(b) if shannon(b) >= self.min => PostResult::Keep(m),
            _ => PostResult::Drop,
        }
    }
}
