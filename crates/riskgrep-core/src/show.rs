//! A masked view of one file, for `riskgrep show`.
//!
//! The file is read once into memory, and that buffer is scanned whole by
//! every built-in rule and every rule configuration adds: no category
//! filter, ruleset selection, weight override, ignore entry, baseline, or
//! path allowlist applies ([`crate::config::ShowConfig`]), so configuration can add to the
//! mask but never narrow it. Every located match, whatever its score, is
//! replaced by a marker; a match spanning lines leaves the same number of
//! line feeds after its marker, so line numbers stay aligned with the file.
//! The masked text is then scanned again, and a match found outside the
//! markers is masked too, for at most [`ROUNDS`] rounds. The view is
//! returned only once a rescan finds nothing outside a marker.
//!
//! Everything that prevents that guarantee is a [`Refusal`]: the file is
//! larger than `[show] max_bytes`, a scan errors, times out, or reads only
//! part of the content, or a rule matched the content without a location
//! (path rules, which describe the file's name, are not content). A refusal
//! carries a reason and never file content. Formats read by structure
//! (tensor files, key stores, archives, images, other binary files) get a
//! [`Shown::Summary`] instead: the format, tensor data types and shapes,
//! member counts, and scores, never names or values.

use crate::classify::{FileClass, Known, Limits};
use crate::config::{Config, ShowConfig};
use crate::model::{round1, Evidence, ShapeFacts, TargetReport, TargetStatus};
use crate::scanner::RiskGrep;
use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The marker that replaces a masked span by default. It names no rule.
pub const FIXED_MARKER: &str = "<redacted>";

/// Rescans of the masked text before the view is refused.
pub const ROUNDS: usize = 4;

/// What a marker says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Marker {
    /// [`FIXED_MARKER`].
    #[default]
    Fixed,
    /// `<redacted: ruleset:rule, …>`: the ruleset and rule ids that matched
    /// in the span.
    RuleIds,
}

/// How to show a file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShowOptions {
    pub marker: Marker,
    /// Only these lines (1-based, inclusive) of the masked text; lines are
    /// counted after masking, which keeps them aligned with the file's.
    pub lines: Option<(u64, u64)>,
}

/// What `show` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// The masked text: UTF-8 for UTF-16 and UTF-32 files, otherwise the
    /// file's own bytes outside the markers.
    Masked {
        text: Vec<u8>,
        /// Markers in the whole view (not only in the selected lines).
        masks: usize,
        /// Lines in the whole view (a last line without a line feed
        /// counts), the file's own line count.
        lines: u64,
    },
    /// A structural summary of a file that is not text, one fact per line.
    Summary(String),
}

/// Why nothing is shown. Holds no file content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(why: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(why.into()))
}

/// A span to mask: byte offsets, and the rules that matched in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub rules: BTreeSet<String>,
}

impl Span {
    pub fn new(range: Range<usize>, rule: &str) -> Span {
        Span {
            start: range.start,
            end: range.end,
            rules: BTreeSet::from([rule.to_string()]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(Vec<u8>),
    Mask {
        rules: BTreeSet<String>,
        newlines: usize,
    },
}

/// Spans sorted and merged: spans that overlap or touch become one, with
/// the union of their rules. Empty spans are dropped.
fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|s| s.start < s.end);
    spans.sort_by_key(|s| (s.start, s.end));
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        match out.last_mut() {
            Some(last) if s.start <= last.end => {
                last.end = last.end.max(s.end);
                last.rules.extend(s.rules);
            }
            _ => out.push(s),
        }
    }
    out
}

fn marker_text(rules: &BTreeSet<String>, marker: Marker) -> String {
    match marker {
        Marker::RuleIds if !rules.is_empty() => {
            let names: Vec<&str> = rules.iter().map(String::as_str).collect();
            format!("<redacted: {}>", names.join(", "))
        }
        _ => FIXED_MARKER.to_string(),
    }
}

fn newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b == b'\n').count()
}

/// The pieces' text, and the byte range of each marker in it (with its
/// line feeds).
fn render(pieces: &[Piece], marker: Marker) -> (Vec<u8>, Vec<Range<usize>>) {
    let mut out = Vec::new();
    let mut marks = Vec::new();
    for p in pieces {
        match p {
            Piece::Text(t) => out.extend_from_slice(t),
            Piece::Mask { rules, newlines } => {
                let start = out.len();
                out.extend_from_slice(marker_text(rules, marker).as_bytes());
                out.resize(out.len() + newlines, b'\n');
                marks.push(start..out.len());
            }
        }
    }
    (out, marks)
}

/// `src` with `spans` (offsets in `src`) masked; the text between them is
/// passed through `decode`, and a masked span keeps the line feeds its
/// decoded text held. A span past the end of `src` is cut at the end.
fn mask_source(src: &[u8], spans: Vec<Span>, decode: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut pos = 0;
    for mut s in merge(spans) {
        s.end = s.end.min(src.len());
        if s.start >= s.end {
            continue;
        }
        if s.start > pos {
            pieces.push(Piece::Text(decode(&src[pos..s.start])));
        }
        pieces.push(Piece::Mask {
            rules: s.rules,
            newlines: newlines(&decode(&src[s.start..s.end])),
        });
        pos = s.end;
    }
    if pos < src.len() {
        pieces.push(Piece::Text(decode(&src[pos..])));
    }
    pieces
}

/// Mask more of a masked view: `spans` are offsets in its rendering with
/// `marker`. A span that overlaps a marker takes in the whole marker, and
/// the merged mask keeps every line feed of what it covers.
fn remask(pieces: &[Piece], spans: Vec<Span>, marker: Marker) -> Vec<Piece> {
    let (text, marks) = render(pieces, marker);
    let mut rules_of_marks = pieces.iter().filter_map(|p| match p {
        Piece::Mask { rules, .. } => Some(rules.clone()),
        Piece::Text(_) => None,
    });
    let mut all: Vec<Span> = spans;
    for m in &marks {
        let rules = rules_of_marks.next().unwrap_or_default();
        all.push(Span {
            start: m.start,
            end: m.end,
            rules,
        });
    }
    // Overlap, not touching, joins a span to a marker; touching spans of
    // the scan were merged already.
    all.retain(|s| s.start < s.end);
    all.sort_by_key(|s| (s.start, s.end));
    let mut groups: Vec<Span> = Vec::new();
    for s in all {
        match groups.last_mut() {
            Some(g) if s.start < g.end => {
                g.end = g.end.max(s.end);
                g.rules.extend(s.rules);
            }
            _ => groups.push(s),
        }
    }
    let mut out = Vec::new();
    let mut pos = 0;
    for mut g in groups {
        g.end = g.end.min(text.len());
        if g.start >= g.end {
            continue;
        }
        if g.start > pos {
            out.push(Piece::Text(text[pos..g.start].to_vec()));
        }
        out.push(Piece::Mask {
            rules: g.rules,
            newlines: newlines(&text[g.start..g.end]),
        });
        pos = g.end;
    }
    if pos < text.len() {
        out.push(Piece::Text(text[pos..].to_vec()));
    }
    out
}

/// `text` with every span replaced by a marker. Spans are byte offsets;
/// spans that overlap or touch are masked as one, and a span keeps the
/// line feeds it covered after its marker. This is the masking step alone,
/// for callers that hold evidence offsets of their own.
pub fn mask(text: &[u8], spans: Vec<Span>, marker: Marker) -> Vec<u8> {
    render(&mask_source(text, spans, &|b| b.to_vec()), marker).0
}

/// Lines `first..=last` (1-based) of `text`, each with its line feed.
pub fn select_lines(text: &[u8], first: u64, last: u64) -> &[u8] {
    let mut line = 1u64;
    let mut start = None;
    if first <= 1 {
        start = Some(0);
    }
    for (i, &b) in text.iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        if line == last {
            return &text[start.unwrap_or(text.len())..=i];
        }
        line += 1;
        if line == first {
            start = Some(i + 1);
        }
    }
    match start {
        Some(s) if s <= text.len() => &text[s..],
        _ => &[],
    }
}

/// Parse `A:B` (1-based, `A <= B`).
pub fn parse_lines(s: &str) -> Result<(u64, u64), String> {
    let bad = || format!("`{s}` is not FIRST:LAST (line numbers from 1, FIRST at most LAST)");
    let (a, b) = s.split_once(':').ok_or_else(bad)?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    if !digits(a) || !digits(b) {
        return Err(bad());
    }
    let (a, b): (u64, u64) = (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?);
    if a == 0 || b < a {
        return Err(bad());
    }
    Ok((a, b))
}

/// The configuration a `show` scan uses: the defaults, every rule
/// `cfg` adds, the command's own time limit, and no evidence cache. The
/// text limit is `text_max`: for text, the size was checked against
/// `[show] max_bytes` before the read, and the masked text, which the
/// rescans read, can be longer than the file (markers naming rules are
/// longer than short matches), so text is never sampled. Path allowlists
/// are off whatever the `path_allowlist` setting: a rule that skips a path
/// (gitleaks' global allowlist skips `node_modules/`) would leave its
/// matches there unmasked.
fn scan_config(cfg: &ShowConfig, text_max: u64) -> Config {
    Config {
        path_allowlist: false,
        extra_ruleset_dirs: cfg.extra_ruleset_dirs.clone(),
        limits: Limits {
            text_max,
            time_budget: cfg.time_budget,
            ..Limits::default()
        },
        no_cache: true,
        ..Config::default()
    }
}

/// Show the file at `path`, masked. `cache_dir` holds compiled rules
/// (`None`: compile them).
pub fn show_file(
    cfg: &ShowConfig,
    path: &Path,
    opts: &ShowOptions,
    cache_dir: Option<PathBuf>,
) -> Result<Shown, Refusal> {
    // Checked before opening too: opening a FIFO would wait for a writer.
    match fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return refuse("not a regular file"),
        Err(e) => return refuse(format!("cannot open ({:?})", e.kind())),
    }
    let mut file = File::open(path).or_else(|e| refuse(format!("cannot open ({:?})", e.kind())))?;
    let md = file
        .metadata()
        .or_else(|e| refuse(format!("cannot read ({:?})", e.kind())))?;
    if !md.is_file() {
        return refuse("not a regular file");
    }
    let too_large = || {
        Refusal(format!(
            "larger than {} bytes ([show] max_bytes)",
            cfg.max_bytes
        ))
    };
    if md.len() > cfg.max_bytes {
        return Err(too_large());
    }
    let mut bytes = Vec::with_capacity(md.len() as usize);
    (&mut file)
        .take(cfg.max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .or_else(|e| refuse(format!("cannot read ({:?})", e.kind())))?;
    if bytes.len() as u64 > cfg.max_bytes {
        return Err(too_large());
    }
    drop(file);
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let head = &bytes[..bytes.len().min(Limits::default().sniff)];
    let class = crate::classify::settle_npz(
        crate::scanner::classify(&name, head, bytes.len() as u64),
        bytes.as_slice(),
        bytes.len() as u64,
        &Limits::default(),
    );
    let text = matches!(class, FileClass::Text | FileClass::EncodedText(_));
    // A format read from disk by structure keeps the size cap as its text
    // limit, should the file grow before that read.
    let text_max = if text { u64::MAX } else { cfg.max_bytes };
    let mut rg = RiskGrep::with_cache_dir(scan_config(cfg, text_max), None, cache_dir)
        .or_else(|e| refuse(format!("could not start the scanner ({})", e.0)))?;
    let target = path.display().to_string();
    if text {
        masked(
            &mut rg,
            &target,
            &real,
            &bytes,
            &class,
            opts,
            cfg.time_budget,
        )
    } else {
        drop(bytes);
        summary(&mut rg, path, &class)
    }
}

/// The rule ids that match the file's name alone: their location-free
/// evidence describes the path, not the content.
fn path_rules(rg: &mut RiskGrep, real: &Path) -> Result<HashSet<String>, Refusal> {
    // `scan_names` derives the path the rules see from the absolute path,
    // as the content scan does (`RiskGrep::rules_path`).
    let r = rg.scan_names(&[real.to_string_lossy().into_owned()]);
    let t = only(&r.targets)?;
    if t.status != TargetStatus::Scanned {
        return refuse(status_reason(t));
    }
    Ok(t.evidence
        .iter()
        .filter(|e| e.locations.is_empty())
        .map(|e| e.rule.clone())
        .collect())
}

fn only(ts: &[TargetReport]) -> Result<&TargetReport, Refusal> {
    match ts {
        [t] => Ok(t),
        _ => refuse("the scan returned an unexpected report"),
    }
}

fn status_reason(t: &TargetReport) -> String {
    match &t.status {
        TargetStatus::Partial { not_read } => {
            format!("part of the content was not scanned ({not_read})")
        }
        TargetStatus::Skipped { reason } | TargetStatus::Unscanned { reason } => {
            format!("could not scan ({reason})")
        }
        TargetStatus::Scanned => "scanned".to_string(),
    }
}

/// The spans of `evidence` (offsets in content of `len` bytes), named for
/// the marker, or the reason the content cannot be masked.
fn spans_of(
    rg: &RiskGrep,
    evidence: &[Evidence],
    path_rules: &HashSet<String>,
    len: usize,
) -> Result<Vec<Span>, Refusal> {
    let mut spans = Vec::new();
    for e in evidence {
        if !e.shape.is_empty() {
            return refuse(format!(
                "rule {} reported structure, not a location",
                e.rule
            ));
        }
        if e.locations.is_empty() {
            if path_rules.contains(&e.rule) {
                continue;
            }
            return refuse(format!(
                "rule {} matched the content without a location",
                e.rule
            ));
        }
        let name = rg.rule_key(&e.rule).unwrap_or(&e.rule);
        for l in &e.locations {
            let (start, end) = (l.start as usize, l.end as usize);
            if start >= end || end > len {
                return refuse(format!("rule {} reported an unusable location", e.rule));
            }
            spans.push(Span::new(start..end, name));
        }
    }
    Ok(spans)
}

fn masked(
    rg: &mut RiskGrep,
    target: &str,
    real: &Path,
    bytes: &[u8],
    class: &FileClass,
    opts: &ShowOptions,
    budget: Duration,
) -> Result<Shown, Refusal> {
    // The budget is for the command: each scan is bounded by it, and no
    // rescan starts once it is spent.
    let deadline = Instant::now() + budget;
    let report = rg.scan_text_file(target, real, bytes, false);
    let t = only(&report.targets)?;
    if t.status != TargetStatus::Scanned {
        return refuse(status_reason(t));
    }
    let path_rules = path_rules(rg, real)?;
    let spans = spans_of(rg, &t.evidence, &path_rules, bytes.len())?;
    let mut pieces = match class {
        FileClass::EncodedText(e) => {
            let bom = usize::from(e.bom).min(bytes.len());
            let shifted = spans
                .into_iter()
                .map(|s| Span {
                    start: s.start.saturating_sub(bom),
                    end: s.end.saturating_sub(bom),
                    rules: s.rules,
                })
                .collect();
            let utf = e.utf;
            mask_source(&bytes[bom..], shifted, &|b| crate::encoding::decode(utf, b))
        }
        _ => mask_source(bytes, spans, &|b| b.to_vec()),
    };
    for _ in 0..ROUNDS {
        if Instant::now() >= deadline {
            return refuse(
                "the masked text could not be checked: the time budget ran out \
                 ([show] time_budget_ms)",
            );
        }
        let (text, marks) = render(&pieces, opts.marker);
        let check = rg.scan_text_file(target, real, &text, true);
        let c = only(&check.targets)?;
        if c.status != TargetStatus::Scanned {
            return refuse(format!(
                "the masked text could not be checked: {}",
                status_reason(c)
            ));
        }
        let found = spans_of(rg, &c.evidence, &path_rules, text.len())?;
        let outside: Vec<Span> = found
            .into_iter()
            .filter(|s| !inside_marker(&marks, s))
            .collect();
        if outside.is_empty() {
            let masks = marks.len();
            let lines =
                newlines(&text) as u64 + u64::from(!text.is_empty() && !text.ends_with(b"\n"));
            let text = match opts.lines {
                Some((a, b)) => select_lines(&text, a, b).to_vec(),
                None => text,
            };
            return Ok(Shown::Masked { text, masks, lines });
        }
        pieces = remask(&pieces, outside, opts.marker);
    }
    refuse(format!(
        "matches remained outside the markers after {ROUNDS} rounds of masking"
    ))
}

/// Whether `s` lies wholly inside one of `marks` (sorted, disjoint).
fn inside_marker(marks: &[Range<usize>], s: &Span) -> bool {
    let i = marks.partition_point(|m| m.start <= s.start);
    i > 0 && s.end <= marks[i - 1].end
}

fn format_name(class: &FileClass) -> String {
    match class {
        FileClass::KnownBinary(Known::Npy) => "npy tensor file".into(),
        FileClass::KnownBinary(Known::Npz) => "npz archive of tensors".into(),
        FileClass::KnownBinary(Known::Safetensors) => "safetensors tensor file".into(),
        FileClass::KnownBinary(Known::KeyStore) => "key store".into(),
        FileClass::KnownBinary(Known::Vault) => "password vault or keychain file".into(),
        FileClass::Container(k) => format!("{} container", k.name()),
        FileClass::Image(k) => format!("{k} image"),
        FileClass::UnknownBinary => "binary file of unknown format".into(),
        _ => "binary file".into(),
    }
}

/// A summary of a file read by structure: what it is, how it was read,
/// its tensors' data types and shapes, its member counts, and its scores.
/// Never a name, a path inside it, or a value.
fn summary(rg: &mut RiskGrep, path: &Path, class: &FileClass) -> Result<Shown, Refusal> {
    let report = rg.scan_paths(&[path.to_path_buf()]);
    let t = only(&report.targets)?;
    let mut s = String::new();
    let _ = writeln!(s, "format: {}", format_name(class));
    let _ = writeln!(s, "content: not shown (not text)");
    let _ = writeln!(s, "status: {}", status_reason(t));
    let tensors: Vec<(&str, &[u64])> = t
        .evidence
        .iter()
        .flat_map(|e| e.shape.iter())
        .map(|f| match f {
            ShapeFacts::Tensor { dtype, shape, .. } => (dtype.as_str(), shape.as_slice()),
        })
        .collect();
    let mut seen: Vec<(&str, &[u64])> = Vec::new();
    for x in tensors {
        if !seen.contains(&x) {
            seen.push(x);
        }
    }
    if !seen.is_empty() {
        let _ = writeln!(s, "tensors reported: {}", seen.len());
        for (dtype, shape) in &seen {
            let dims: Vec<String> = shape.iter().map(u64::to_string).collect();
            let _ = writeln!(s, "  {dtype} [{}]", dims.join(", "));
        }
    }
    if let Some(c) = &t.container {
        let _ = writeln!(
            s,
            "members: {} ({} scanned, {} read in part, {} skipped, {} not read)",
            c.members, c.scanned, c.read_in_part, c.skipped, c.not_read
        );
    }
    if !t.scores.is_empty() {
        let scores: Vec<String> = t
            .scores
            .iter()
            .map(|(c, v)| format!("{} {:.1}", c.0, round1(*v)))
            .collect();
        let _ = writeln!(s, "scores: {}", scores.join(", "));
    }
    Ok(Shown::Summary(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(a: usize, b: usize, r: &str) -> Span {
        Span::new(a..b, r)
    }

    #[test]
    fn merge_joins_overlapping_and_touching_spans() {
        let m = merge(vec![
            sp(5, 9, "b"),
            sp(0, 3, "a"),
            sp(3, 4, "c"),
            sp(8, 12, "d"),
        ]);
        assert_eq!(m.len(), 2);
        assert_eq!((m[0].start, m[0].end), (0, 4));
        assert_eq!((m[1].start, m[1].end), (5, 12));
        assert_eq!(m[1].rules.len(), 2);
    }

    #[test]
    fn remask_absorbs_an_overlapped_marker_and_keeps_line_feeds() {
        let pieces = mask_source(b"ab\nSECRET\ncd", vec![sp(3, 9, "r1")], &|b| b.to_vec());
        let (text, marks) = render(&pieces, Marker::Fixed);
        assert_eq!(text, b"ab\n<redacted>\ncd");
        // A span from the end of line 1 into the marker.
        let more = remask(
            &pieces,
            vec![sp(1, marks[0].start + 2, "r2")],
            Marker::Fixed,
        );
        let (text, _) = render(&more, Marker::Fixed);
        assert_eq!(text, b"a<redacted>\n\ncd");
        assert_eq!(text.iter().filter(|&&b| b == b'\n').count(), 2);
    }

    #[test]
    fn containment_in_a_marker() {
        let marks = vec![2..5, 8..12];
        let inside = |a, b| inside_marker(&marks, &sp(a, b, "r"));
        assert!(inside(2, 5) && inside(3, 4) && inside(8, 12) && inside(9, 12));
        assert!(!inside(1, 3) && !inside(4, 6) && !inside(5, 8) && !inside(0, 1));
        assert!(!inside(11, 13) && !inside(2, 9) && !inside(12, 13));
    }

    #[test]
    fn rule_id_markers_list_every_rule() {
        let out = mask(
            b"xx KEY yy",
            vec![sp(3, 6, "ns:b"), sp(4, 6, "ns:a")],
            Marker::RuleIds,
        );
        assert_eq!(out, b"xx <redacted: ns:a, ns:b> yy");
    }
}
