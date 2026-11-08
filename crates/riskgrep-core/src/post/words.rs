use super::{Post, PostResult};
use std::ops::Range;

/// Drops a match containing any listed word (ASCII case-insensitive).
///
/// With [`hex_min_len`](Stopwords::hex_min_len), a match made only of hex
/// digits is judged by the listed words of at least that length. A short word
/// spelt with hex digits (`dead`, `feed`) is a coincidence in a random hex
/// value, which holds one about once in 1,100 draws of 32 digits, while a
/// long one (a 32-digit example value) is a listed placeholder.
pub struct Stopwords {
    words: Vec<Vec<u8>>,
    hex_min_len: Option<usize>,
}

impl Stopwords {
    pub fn new(words: &[String]) -> Self {
        Stopwords {
            words: words
                .iter()
                .filter(|w| !w.is_empty())
                .map(|w| w.to_ascii_lowercase().into_bytes())
                .collect(),
            hex_min_len: None,
        }
    }

    /// For a match made only of hex digits (`0-9`, `a-f`, `A-F`), ignore the
    /// listed words shorter than `min_len`. An empty match is not a hex value.
    pub fn hex_min_len(mut self, min_len: Option<usize>) -> Self {
        self.hex_min_len = min_len;
        self
    }
}

impl Post for Stopwords {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Some(hay) = content.get(m.clone()) else {
            return PostResult::Drop;
        };
        let min_len = match self.hex_min_len {
            Some(n) if !hay.is_empty() && hay.iter().all(u8::is_ascii_hexdigit) => n,
            _ => 0,
        };
        let hay = hay.to_ascii_lowercase();
        if self
            .words
            .iter()
            .filter(|w| w.len() >= min_len)
            .any(|w| hay.windows(w.len()).any(|win| win == w.as_slice()))
        {
            PostResult::Drop
        } else {
            PostResult::Keep(m)
        }
    }
}
