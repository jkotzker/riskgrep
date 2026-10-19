use super::{Post, PostResult};
use regex::bytes::Regex;
use std::ops::Range;

/// Narrows a match to one capture group of a regex applied inside it.
pub struct Span {
    re: Regex,
    group: usize,
}

impl Span {
    pub fn new(re: Regex, group: usize) -> Self {
        Span { re, group }
    }
}

impl Post for Span {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Some(hay) = content.get(m.clone()) else {
            return PostResult::Drop;
        };
        match self.re.captures(hay).and_then(|c| c.get(self.group)) {
            Some(g) => PostResult::Keep(m.start + g.start()..m.start + g.end()),
            None => PostResult::Drop,
        }
    }
}

/// Drops a match when the regex matches anywhere inside it.
pub struct AllowRegex {
    re: Regex,
}

impl AllowRegex {
    pub fn new(re: Regex) -> Self {
        AllowRegex { re }
    }
}

impl Post for AllowRegex {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        match content.get(m.clone()) {
            Some(hay) if !self.re.is_match(hay) => PostResult::Keep(m),
            _ => PostResult::Drop,
        }
    }
}
