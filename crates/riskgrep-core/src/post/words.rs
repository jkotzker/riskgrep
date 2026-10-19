use super::{Post, PostResult};
use std::ops::Range;

/// Drops a match containing any listed word (ASCII case-insensitive).
pub struct Stopwords {
    words: Vec<Vec<u8>>,
}

impl Stopwords {
    pub fn new(words: &[String]) -> Self {
        Stopwords {
            words: words
                .iter()
                .filter(|w| !w.is_empty())
                .map(|w| w.to_ascii_lowercase().into_bytes())
                .collect(),
        }
    }
}

impl Post for Stopwords {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Some(hay) = content.get(m.clone()) else {
            return PostResult::Drop;
        };
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
