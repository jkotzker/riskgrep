//! UTF-16 and UTF-32 text. Detects the encoding from a byte-order mark or
//! the code-unit pattern of the sniff window, transcodes the bytes read to
//! UTF-8 for the text rules, and maps offsets in the transcoded text back to
//! offsets in the file. Every LF code unit becomes one LF byte, so the line
//! numbers of the transcoded text are the lines of the file.

use crate::model::Evidence;

/// A Unicode encoding form other than UTF-8, with its byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Utf {
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl Utf {
    /// Bytes per code unit.
    pub fn unit(self) -> usize {
        match self {
            Utf::Utf16Le | Utf::Utf16Be => 2,
            Utf::Utf32Le | Utf::Utf32Be => 4,
        }
    }

    fn read(self, b: &[u8]) -> u32 {
        match self {
            Utf::Utf16Le => u32::from(u16::from_le_bytes([b[0], b[1]])),
            Utf::Utf16Be => u32::from(u16::from_be_bytes([b[0], b[1]])),
            Utf::Utf32Le => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Utf::Utf32Be => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
}

/// A detected encoding: the form, and the length in bytes of the
/// byte-order mark the file starts with (0 when it has none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Encoding {
    pub utf: Utf,
    pub bom: u8,
}

/// One decoded code point: the source bytes it took, and the character, or
/// `None` for an invalid sequence (an unpaired surrogate, a UTF-32 value
/// beyond Unicode, or an incomplete final code unit).
fn next(utf: Utf, src: &[u8]) -> Option<(usize, Option<char>)> {
    let n = utf.unit();
    if src.is_empty() {
        return None;
    }
    if src.len() < n {
        return Some((src.len(), None));
    }
    let u = utf.read(src);
    if n == 2 && (0xD800..0xDC00).contains(&u) {
        if let Some(lo) = src.get(2..4).map(|b| utf.read(b)) {
            if (0xDC00..0xE000).contains(&lo) {
                let c = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                return Some((4, char::from_u32(c)));
            }
        }
    }
    Some((n, char::from_u32(u)))
}

/// Iterate the code points of `src`.
fn code_points(utf: Utf, mut src: &[u8]) -> impl Iterator<Item = (usize, Option<char>)> + '_ {
    std::iter::from_fn(move || {
        let (n, c) = next(utf, src)?;
        src = &src[n..];
        Some((n, c))
    })
}

const MARKS: [(Utf, &[u8]); 4] = [
    (Utf::Utf32Le, &[0xFF, 0xFE, 0, 0]),
    (Utf::Utf32Be, &[0, 0, 0xFE, 0xFF]),
    (Utf::Utf16Le, &[0xFF, 0xFE]),
    (Utf::Utf16Be, &[0xFE, 0xFF]),
];

/// Counts over the complete code points of a sniff window.
#[derive(Default)]
struct Census {
    points: usize,
    invalid: usize,
    nul: bool,
    ascii: usize,
    controls: bool,
}

/// Census of `window`, ignoring a final code unit the window cut short and
/// a final high surrogate whose pair the window cut off.
fn census(utf: Utf, window: &[u8]) -> Census {
    let n = utf.unit();
    let whole = &window[..window.len() / n * n];
    let mut c = Census::default();
    let mut at = 0;
    for (len, ch) in code_points(utf, whole) {
        at += len;
        match ch {
            None if at == whole.len()
                && len == 2
                && (0xD800..0xDC00).contains(&utf.read(&whole[at - 2..])) => {}
            None => {
                c.points += 1;
                c.invalid += 1;
            }
            Some(ch) => {
                c.points += 1;
                c.nul |= ch == '\0';
                c.ascii += usize::from(('\u{1}'..='\u{7f}').contains(&ch));
                c.controls |= ch.is_ascii_control()
                    && !matches!(ch, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1b');
            }
        }
    }
    c
}

/// The encoding of a file starting with `head` (its sniff window), if it is
/// UTF-16 or UTF-32 text.
///
/// - With a byte-order mark (UTF-32 marks are tested before UTF-16 ones):
///   the window after the mark holds no U+0000 and at most one code point
///   in 16 is invalid.
/// - Without one, only when `head` holds a NUL byte (all UTF-16 and UTF-32
///   text of ASCII characters does): the window holds at least two code
///   points, every one valid, none U+0000, none a C0 control other than tab,
///   LF, VT, FF, CR, and ESC, and more than half of them in U+0001..U+007F
///   (the alternating-NUL pattern). UTF-32 is tested first; ASCII text in
///   one form fails the test for another, because a UTF-32 ASCII code unit
///   holds a U+0000 UTF-16 unit and two UTF-16 ASCII units read as one
///   UTF-32 value exceed U+10FFFF. A binary with runs of NULs fails on
///   U+0000.
pub fn detect(head: &[u8]) -> Option<Encoding> {
    for (utf, mark) in MARKS {
        if head.starts_with(mark) {
            let c = census(utf, &head[mark.len()..]);
            if c.nul || c.invalid * 16 > c.points {
                return None;
            }
            return Some(Encoding {
                utf,
                bom: mark.len() as u8,
            });
        }
    }
    if !head.contains(&0) {
        return None;
    }
    [Utf::Utf32Le, Utf::Utf32Be, Utf::Utf16Le, Utf::Utf16Be]
        .into_iter()
        .find(|&utf| {
            let c = census(utf, head);
            c.points >= 2 && c.invalid == 0 && !c.nul && !c.controls && c.ascii * 2 > c.points
        })
        .map(|utf| Encoding { utf, bom: 0 })
}

/// `src` transcoded to UTF-8; invalid sequences become U+FFFD.
pub fn decode(utf: Utf, src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    let mut buf = [0u8; 4];
    for (_, c) in code_points(utf, src) {
        out.extend_from_slice(c.unwrap_or('\u{fffd}').encode_utf8(&mut buf).as_bytes());
    }
    out
}

/// Text read from a UTF-16 or UTF-32 file and transcoded for the scan
/// engine. The scanned content is the transcoded head (the file's bytes from
/// the end of the byte-order mark), then, for a sampled file, an added LF
/// and the transcoded tail sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub encoding: Encoding,
    /// The file's first bytes, from offset 0, byte-order mark included.
    pub head: Vec<u8>,
    /// For a sampled file: the file offset of the tail sample, and its bytes.
    pub tail: Option<(u64, Vec<u8>)>,
    /// Length of the transcoded head in the scanned content.
    head_len: u64,
}

impl Decoded {
    /// Transcode `head` (and `tail`) into the content the engine scans.
    pub fn new(
        encoding: Encoding,
        head: Vec<u8>,
        tail: Option<(u64, Vec<u8>)>,
    ) -> (Decoded, Vec<u8>) {
        let skip = usize::from(encoding.bom).min(head.len());
        let mut text = decode(encoding.utf, &head[skip..]);
        let head_len = text.len() as u64;
        if let Some((_, t)) = &tail {
            text.push(b'\n');
            text.extend(decode(encoding.utf, t));
        }
        let d = Decoded {
            encoding,
            head,
            tail,
            head_len,
        };
        (d, text)
    }

    /// Move evidence offsets from the scanned content to the file. A start
    /// inside a transcoded character moves to the character's first byte,
    /// an end inside one to the byte after its last, so a location covers
    /// at least the source bytes of what matched. Evidence in the tail
    /// sample of a sampled file loses its line numbers (0), as for sampled
    /// UTF-8 text: the lines of the unread middle were never counted; a
    /// range across the joint keeps its start and also loses its lines.
    pub fn place(&self, evidence: &mut [Evidence]) {
        let at = self.tail.as_ref().map(|_| self.head_len + 1);
        let in_tail = |end: u64| at.is_some_and(|at| end >= at);
        let (mut hq, mut tq) = (Vec::new(), Vec::new());
        for l in evidence.iter().flat_map(|e| e.locations.iter()) {
            match at {
                Some(at) if in_tail(l.end) => {
                    if l.start >= at {
                        tq.push(l.start - at);
                    } else {
                        hq.push(l.start);
                    }
                    tq.push(l.end.max(at) - at);
                }
                _ => hq.extend([l.start, l.end]),
            }
        }
        let skip = usize::from(self.encoding.bom).min(self.head.len());
        let hm = Map::new(self.encoding.utf, &self.head[skip..], skip as u64, hq);
        let tm = match &self.tail {
            Some((offset, bytes)) => Map::new(self.encoding.utf, bytes, *offset, tq),
            None => Map::default(),
        };
        for l in evidence.iter_mut().flat_map(|e| e.locations.iter_mut()) {
            match at {
                Some(at) if in_tail(l.end) => {
                    l.start = if l.start >= at {
                        tm.floor(l.start - at)
                    } else {
                        hm.floor(l.start)
                    };
                    l.end = tm.ceil(l.end.max(at) - at);
                    l.line_start = 0;
                    l.line_end = 0;
                }
                _ => {
                    l.start = hm.floor(l.start);
                    l.end = hm.ceil(l.end);
                }
            }
        }
    }
}

/// Source offsets of sorted transcoded offsets: for each, the start of the
/// source character holding it (`floor`) and the first source boundary at
/// or after it (`ceil`).
#[derive(Default)]
struct Map {
    queries: Vec<u64>,
    floor: Vec<u64>,
    ceil: Vec<u64>,
}

impl Map {
    /// One pass over `src` (transcoded from offset 0 of the content part),
    /// whose first byte is at file offset `base`.
    fn new(utf: Utf, src: &[u8], base: u64, mut queries: Vec<u64>) -> Map {
        queries.sort_unstable();
        queries.dedup();
        let (mut floor, mut ceil) = (Vec::with_capacity(queries.len()), Vec::new());
        let mut q = queries.iter().peekable();
        let (mut d, mut s) = (0u64, base);
        for (len, c) in code_points(utf, src) {
            if q.peek().is_none() {
                break;
            }
            let dlen = c.map_or(3, char::len_utf8) as u64;
            while let Some(&&x) = q.peek().filter(|&&&x| x < d + dlen) {
                floor.push(s);
                ceil.push(if x == d { s } else { s + len as u64 });
                q.next();
            }
            d += dlen;
            s += len as u64;
        }
        for _ in q {
            floor.push(s);
            ceil.push(s);
        }
        Map {
            queries,
            floor,
            ceil,
        }
    }

    fn index(&self, x: u64) -> usize {
        self.queries.binary_search(&x).expect("offset was queried")
    }

    fn floor(&self, x: u64) -> u64 {
        self.floor[self.index(x)]
    }

    fn ceil(&self, x: u64) -> u64 {
        self.ceil[self.index(x)]
    }
}
