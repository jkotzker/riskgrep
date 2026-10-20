use super::{Post, PostResult};
use crate::meta::FIRST_NONEMPTY_GROUP;
use regex::bytes::Regex;
use std::ops::Range;

/// Narrows a match to one capture group of a regex applied inside it, or
/// (with [`FIRST_NONEMPTY_GROUP`]) to the first non-empty group.
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
        let Some(caps) = self.re.captures(hay) else {
            return PostResult::Drop;
        };
        let g = if self.group == FIRST_NONEMPTY_GROUP {
            (1..caps.len())
                .filter_map(|i| caps.get(i))
                .find(|g| !g.is_empty())
                .or_else(|| caps.get(0))
        } else {
            caps.get(self.group)
        };
        match g {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn span(re: &str, group: usize, content: &[u8]) -> PostResult {
        Span::new(Regex::new(re).unwrap(), group).apply(content, 0..content.len())
    }

    #[test]
    fn first_nonempty_takes_the_first_group_that_matched_non_empty() {
        // Group 1 does not take part; group 2 does.
        let re = r"k=(?:([a-z]{4})|([0-9]{4}))";
        assert_eq!(
            span(re, FIRST_NONEMPTY_GROUP, b"k=1234"),
            PostResult::Keep(2..6)
        );
        assert_eq!(
            span(re, FIRST_NONEMPTY_GROUP, b"k=abcd"),
            PostResult::Keep(2..6)
        );
        // Group 1 is fixed at 1 and drops the group-2 form.
        assert_eq!(span(re, 1, b"k=1234"), PostResult::Drop);
    }

    #[test]
    fn first_nonempty_skips_empty_groups() {
        // Group 1 takes part but is empty; group 2 holds the secret.
        let re = r"k=(x*)([0-9]+)";
        assert_eq!(
            span(re, FIRST_NONEMPTY_GROUP, b"k=1234"),
            PostResult::Keep(2..6)
        );
    }

    #[test]
    fn first_nonempty_falls_back_to_the_whole_match() {
        assert_eq!(
            span(r"k=(x*)[0-9]+", FIRST_NONEMPTY_GROUP, b"k=1234"),
            PostResult::Keep(0..6)
        );
        assert_eq!(
            span(r"k=[0-9]+", FIRST_NONEMPTY_GROUP, b"k=1234"),
            PostResult::Keep(0..6)
        );
    }

    #[test]
    fn first_nonempty_offsets_are_relative_to_the_match() {
        let content = b"....k=1234....";
        let s = Span::new(Regex::new(r"k=(x*)([0-9]+)").unwrap(), FIRST_NONEMPTY_GROUP);
        assert_eq!(s.apply(content, 4..10), PostResult::Keep(6..10));
        assert_eq!(
            s.apply(content, 0..3),
            PostResult::Drop,
            "no match inside the range"
        );
    }
}
