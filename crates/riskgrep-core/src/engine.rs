//! Scan engine: runs precompiled YARA-X rules over content, refines each
//! match with the rule's post-processors, and emits value-free evidence.

use crate::bundle::Bundle;
use crate::lines::LineIndex;
use crate::model::{Evidence, Location, ShapeFacts};
use crate::post::{self, Post, PostResult};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    Timeout,
    Yara(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Timeout => f.write_str("scan timed out"),
            ScanError::Yara(m) => write!(f, "yara-x: {m}"),
        }
    }
}

impl std::error::Error for ScanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError(pub String);

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EngineError {}

pub struct Engine {
    bundle: Bundle,
    /// Keyed by `namespace:identifier`, in the rule's declared order.
    posts: HashMap<String, Vec<Box<dyn Post>>>,
}

fn is_anchor(pattern_id: &str) -> bool {
    ["$re", "$hdr", "$hit"]
        .iter()
        .any(|p| pattern_id.starts_with(p))
}

/// Per end offset keep the longest match, then drop matches lying entirely
/// inside another kept match. Result is ordered by start offset.
fn dedupe(ranges: Vec<Range<usize>>) -> Vec<Range<usize>> {
    let mut by_end: BTreeMap<usize, usize> = BTreeMap::new();
    for r in ranges {
        let s = by_end.entry(r.end).or_insert(r.start);
        *s = (*s).min(r.start);
    }
    let mut v: Vec<Range<usize>> = by_end.into_iter().map(|(end, start)| start..end).collect();
    v.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Range<usize>> = Vec::new();
    let mut max_end = 0;
    for r in v {
        if out.is_empty() || r.end > max_end {
            max_end = max_end.max(r.end);
            out.push(r);
        }
    }
    out
}

impl Engine {
    /// Compile every post-processor once. A bad regex is reported with the
    /// rule key and the meta key that held it.
    pub fn new(bundle: Bundle) -> Result<Engine, EngineError> {
        let mut posts = HashMap::new();
        for (key, meta) in &bundle.meta {
            let mut chain = Vec::new();
            for spec in &meta.post {
                let p = post::build(spec, &bundle.stopwords)
                    .map_err(|(k, e)| EngineError(format!("rule {key}: `{k}`: {e}")))?;
                chain.push(p);
            }
            posts.insert(key.clone(), chain);
        }
        Ok(Engine { bundle, posts })
    }

    pub fn rules(&self) -> &yara_x::Rules {
        &self.bundle.rules
    }

    pub fn bundle_hash(&self) -> &str {
        &self.bundle.hash
    }

    /// Run the scanner over `content`. The caller owns the scanner (and its
    /// timeout); `path_for_rules` is exposed to rules as the `path` global.
    pub fn scan_content(
        &self,
        scanner: &mut yara_x::Scanner,
        path_for_rules: &str,
        content: &[u8],
    ) -> Result<Vec<Evidence>, ScanError> {
        scanner
            .set_global("path", path_for_rules)
            .map_err(|e| ScanError::Yara(e.to_string()))?;
        let results = scanner.scan(content).map_err(|e| match e {
            yara_x::errors::ScanError::Timeout => ScanError::Timeout,
            other => ScanError::Yara(other.to_string()),
        })?;

        let mut found: Vec<(String, Evidence)> = Vec::new();
        let mut lines: Option<LineIndex> = None;
        for rule in results.matching_rules() {
            let key = format!("{}:{}", rule.namespace(), rule.identifier());
            let (Some(meta), Some(chain)) = (self.bundle.meta.get(&key), self.posts.get(&key))
            else {
                return Err(ScanError::Yara(format!("rule {key}: no metadata")));
            };
            let mut has_anchor = false;
            let mut ranges = Vec::new();
            for p in rule.patterns() {
                if is_anchor(p.identifier()) {
                    has_anchor = true;
                    ranges.extend(p.matches().map(|m| m.range()));
                }
            }

            let mut ev = Evidence {
                rule: rule.identifier().to_string(),
                category: meta.category.clone(),
                weight: meta.weight,
                count: 1,
                locations: Vec::new(),
                shape: Vec::new(),
                fingerprints: Vec::new(),
            };
            if has_anchor {
                let index = lines.get_or_insert_with(|| LineIndex::new(content));
                // Verdicts of whole-content processors, computed once per rule.
                let mut whole: Vec<Option<Option<ShapeFacts>>> = vec![None; chain.len()];
                let mut kept: Vec<(Range<usize>, Vec<ShapeFacts>)> = Vec::new();
                for mut range in dedupe(ranges) {
                    let mut shapes: Vec<ShapeFacts> = Vec::new();
                    let mut alive = true;
                    for (i, post) in chain.iter().enumerate() {
                        let result = if post.whole_content() {
                            let verdict =
                                whole[i].get_or_insert_with(|| match post.apply(content, 0..0) {
                                    PostResult::KeepWithShape(_, s) => Some(s),
                                    _ => None,
                                });
                            match verdict {
                                Some(s) => PostResult::KeepWithShape(range.clone(), s.clone()),
                                None => PostResult::Drop,
                            }
                        } else {
                            post.apply(content, range.clone())
                        };
                        match result {
                            PostResult::Keep(r) => range = r,
                            PostResult::KeepWithShape(r, s) => {
                                range = r;
                                shapes.push(s);
                            }
                            PostResult::Drop => {
                                alive = false;
                                break;
                            }
                        }
                    }
                    if alive && range.start < range.end && range.end <= content.len() {
                        kept.push((range, shapes));
                    }
                }
                // Post-processors can narrow distinct matches to one range.
                kept.sort_by_key(|a| (a.0.start, a.0.end));
                kept.dedup_by(|dup, first| {
                    let same = dup.0 == first.0;
                    if same {
                        first.1.append(&mut dup.1);
                    }
                    same
                });
                for (range, shapes) in kept {
                    let (line_start, line_end) = index.lines(range.start as u64, range.end as u64);
                    ev.locations.push(Location {
                        start: range.start as u64,
                        end: range.end as u64,
                        line_start,
                        line_end,
                    });
                    ev.fingerprints
                        .push(*blake3::hash(&content[range]).as_bytes());
                    for s in shapes {
                        if !ev.shape.contains(&s) {
                            ev.shape.push(s);
                        }
                    }
                }
                ev.count = ev.locations.len() as u32;
                if ev.count == 0 {
                    continue;
                }
            }
            found.push((key, ev));
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(found.into_iter().map(|(_, e)| e).collect())
    }
}
