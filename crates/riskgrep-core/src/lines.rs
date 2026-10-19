//! Byte offset to line number mapping.

/// Line start offsets of one buffer; lines are 1-based.
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(content: &[u8]) -> Self {
        let mut starts = vec![0];
        starts.extend(
            content
                .iter()
                .enumerate()
                .filter(|(_, &b)| b == b'\n')
                .map(|(i, _)| i + 1),
        );
        LineIndex { starts }
    }

    fn line_of(&self, offset: u64) -> u32 {
        let off = usize::try_from(offset).unwrap_or(usize::MAX);
        self.starts.partition_point(|&s| s <= off) as u32
    }

    /// Lines of the byte range `start..end`; the end line is that of the last
    /// byte in the range, or of `end` itself for an empty range.
    pub fn lines(&self, start: u64, end: u64) -> (u32, u32) {
        let last = if end > start { end - 1 } else { end };
        (self.line_of(start), self.line_of(last))
    }
}
