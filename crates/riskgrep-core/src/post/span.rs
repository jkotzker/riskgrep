use super::{Post, PostResult};
use crate::meta::FIRST_NONEMPTY_GROUP;
use regex::bytes::Regex;
use std::collections::HashSet;
use std::ops::Range;

/// Narrows a match to one capture group of a regex applied inside it, or
/// (with [`FIRST_NONEMPTY_GROUP`]) to the first non-empty group. Every
/// non-overlapping match of the regex in the window counts: a window that
/// holds several secrets (a greedy anchor running from the first key's
/// header to the last key's footer) yields one range per secret.
pub struct Span {
    re: Regex,
    group: usize,
}

impl Span {
    pub fn new(re: Regex, group: usize) -> Self {
        Span { re, group }
    }

    /// The secret range of one regex match, if any.
    fn secret(&self, caps: &regex::bytes::Captures) -> Option<Range<usize>> {
        let g = if self.group == FIRST_NONEMPTY_GROUP {
            (1..caps.len())
                .filter_map(|i| caps.get(i))
                .find(|g| !g.is_empty())
                .or_else(|| caps.get(0))
        } else {
            caps.get(self.group)
        };
        g.filter(|g| !g.is_empty()).map(|g| g.range())
    }

    /// The ranges [`Span::apply`] would yield for each of `windows`, merged
    /// (sorted, without duplicates), and the number of regex matches
    /// examined. Within one window the search after a non-empty match
    /// resumes at its end and sees only bytes up to the window's end, so
    /// two windows with the same end that reach the same non-empty match
    /// continue identically after it: the second keeps that match's capture
    /// (which can differ, through an assertion at its window start) and then
    /// stops instead of repeating the first. Nested windows sharing an end (one per key
    /// header, each running to the last footer) cost one pass, not N^2/2.
    pub fn split_windows(
        &self,
        content: &[u8],
        windows: &[Range<usize>],
    ) -> (Vec<Range<usize>>, usize) {
        let mut seen: HashSet<(usize, usize, usize)> = HashSet::new();
        let mut out: Vec<Range<usize>> = Vec::new();
        let mut examined = 0;
        for w in windows {
            let Some(hay) = content.get(w.clone()) else {
                continue;
            };
            for caps in self.re.captures_iter(hay) {
                examined += 1;
                let m = caps.get(0).expect("group 0 always takes part");
                // Keep this window's capture before stopping: an assertion at
                // the window start (`\b`, `^`) can make the same match capture
                // a different group here than in the window that found it.
                if let Some(g) = self.secret(&caps) {
                    out.push(w.start + g.start..w.start + g.end);
                }
                if !m.is_empty() && !seen.insert((w.start + m.start(), w.start + m.end(), w.end)) {
                    break;
                }
            }
        }
        out.sort_by_key(|r| (r.start, r.end));
        out.dedup();
        (out, examined)
    }
}

impl Post for Span {
    fn apply(&self, content: &[u8], m: Range<usize>) -> PostResult {
        let Some(hay) = content.get(m.clone()) else {
            return PostResult::Drop;
        };
        let mut found: Vec<Range<usize>> = Vec::new();
        for caps in self.re.captures_iter(hay) {
            if let Some(g) = self.secret(&caps) {
                found.push(m.start + g.start..m.start + g.end);
            }
        }
        match found.len() {
            0 => PostResult::Drop,
            1 => PostResult::Keep(found.remove(0)),
            _ => PostResult::KeepAll(found),
        }
    }

    fn splits(&self) -> bool {
        true
    }

    fn apply_windows(&self, content: &[u8], windows: &[Range<usize>]) -> Option<Vec<Range<usize>>> {
        Some(self.split_windows(content, windows).0)
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
    fn every_match_in_the_window_is_kept() {
        let content = b"..k=12 k=345 x k=6789..";
        let s = Span::new(Regex::new(r"k=([0-9]+)").unwrap(), 1);
        assert_eq!(
            s.apply(content, 0..content.len()),
            PostResult::KeepAll(vec![4..6, 9..12, 17..21])
        );
        let s = Span::new(Regex::new(r"k=(x*)([0-9]+)").unwrap(), FIRST_NONEMPTY_GROUP);
        assert_eq!(
            s.apply(content, 2..12),
            PostResult::KeepAll(vec![4..6, 9..12])
        );
        // One match stays a plain `Keep`.
        assert_eq!(s.apply(content, 2..6), PostResult::Keep(4..6));
    }

    /// Ranges each window yields on its own, merged: what the engine
    /// would collect by applying the span to every window.
    fn per_window(s: &Span, content: &[u8], windows: &[Range<usize>]) -> Vec<Range<usize>> {
        let mut out: Vec<Range<usize>> = Vec::new();
        for w in windows {
            match s.apply(content, w.clone()) {
                PostResult::Keep(r) => out.push(r),
                PostResult::KeepAll(rs) => out.extend(rs),
                _ => {}
            }
        }
        out.sort_by_key(|r| (r.start, r.end));
        out.dedup();
        out
    }

    #[test]
    fn nested_windows_are_searched_once_each_match() {
        // Greedy anchors give one window per block, all ending at the last
        // block's end. Searched window by window that is N^2/2 matches.
        let n = 500;
        let block = b"<k>xyz</k>\n";
        let content: Vec<u8> = block
            .iter()
            .copied()
            .cycle()
            .take(block.len() * n)
            .collect();
        let windows: Vec<Range<usize>> =
            (0..n).map(|i| i * block.len()..content.len() - 1).collect();
        let s = Span::new(Regex::new(r"<k>[\s\S]+?</k>").unwrap(), 0);
        let (ranges, examined) = s.split_windows(&content, &windows);
        assert_eq!(ranges.len(), n);
        assert_eq!(ranges, per_window(&s, &content, &windows));
        assert!(
            examined <= 2 * n,
            "{examined} matches examined for {n} blocks"
        );
    }

    #[test]
    fn split_windows_equals_the_per_window_union() {
        // A stray header before a block: the outer window's leftmost match
        // ends inside the block's header and steps over the block; the inner
        // window finds it. Windows with different ends do not share work.
        let content = b"<k>stray <k>abcdef</k> mid <k>gh</k> <k>tail";
        let s = Span::new(Regex::new(r"<k>[\s\S]{4,}?k>").unwrap(), 0);
        let starts = [0, 9, 28, 37];
        let mut windows = Vec::new();
        for &a in &starts {
            for b in [22, 36, content.len()] {
                if a < b {
                    windows.push(a..b);
                }
            }
        }
        let (ranges, _) = s.split_windows(content, &windows);
        assert_eq!(ranges, per_window(&s, content, &windows));
        assert!(ranges.contains(&(9..22)), "{ranges:?}");
    }

    #[test]
    fn a_shared_match_keeps_each_windows_capture() {
        // `\b` at the inner window's start sees the window edge, at the outer
        // window's position it sees a letter: the same match captures a
        // different group in each window, so both captures must be kept.
        let content = b"zab";
        let s = Span::new(Regex::new(r"\b(ab)|a(b)").unwrap(), FIRST_NONEMPTY_GROUP);
        let windows = [0..3, 1..3];
        let (ranges, _) = s.split_windows(content, &windows);
        assert_eq!(ranges, per_window(&s, content, &windows));
        assert!(ranges.contains(&(1..3)), "{ranges:?}");
    }

    #[test]
    fn lazy_regex_finds_each_block_in_a_greedy_window() {
        let content = b"<a>xx</a> mid <b>yyy</b>";
        let s = Span::new(Regex::new(r"<[a-z]>[\s\S]+?</[a-z]>").unwrap(), 0);
        assert_eq!(
            s.apply(content, 0..content.len()),
            PostResult::KeepAll(vec![0..9, 14..24])
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
