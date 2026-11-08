use super::{Post, PostResult};
use std::ops::Range;

/// Drops a match containing any listed word (ASCII case-insensitive).
///
/// With [`skip_hex`](Stopwords::skip_hex), a match made only of hex digits is
/// kept whatever it contains: a word of the list that is spelt with hex digits
/// (`dead`, `feed`) is a coincidence in a random hex value, which holds one
/// about once in 1,000 draws of 32 digits.
pub struct Stopwords {
    words: Vec<Vec<u8>>,
    skip_hex: bool,
}

impl Stopwords {
    pub fn new(words: &[String]) -> Self {
        Stopwords {
            words: words
                .iter()
                .filter(|w| !w.is_empty())
                .map(|w| w.to_ascii_lowercase().into_bytes())
                .collect(),
            skip_hex: false,
        }
    }

    /// Keep a match made only of hex digits (`0-9`, `a-f`, `A-F`) without
    /// looking at the list. An empty match is not a hex value.
    pub fn skip_hex(mut self, skip: bool) -> Self {
        self.skip_hex = skip;
        self
    }
}

impl Post for Stopwords {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Some(hay) = content.get(m.clone()) else {
            return PostResult::Drop;
        };
        if self.skip_hex && !hay.is_empty() && hay.iter().all(u8::is_ascii_hexdigit) {
            return PostResult::Keep(m);
        }
        let hay = hay.to_ascii_lowercase();
        if self
            .words
            .iter()
            .any(|w| hay.windows(w.len()).any(|win| win == w.as_slice()))
        {
            PostResult::Drop
        } else {
            PostResult::Keep(m)
        }
    }
}
