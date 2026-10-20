//! Scan engine: runs precompiled YARA-X rules over content, refines each
//! match with the rule's post-processors, and emits value-free evidence.

use crate::bundle::Bundle;
use crate::lines::LineIndex;
use crate::model::{Evidence, Location, ShapeFacts};
use crate::post::{self, Post, PostResult};
use regex::bytes::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::Range;
use std::sync::{Mutex, OnceLock};

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

type Chain = Vec<Box<dyn Post>>;

pub struct Engine {
    bundle: Bundle,
    /// Post-processor chains keyed by `namespace:identifier`, in the rule's
    /// declared order, built on the rule's first match (or by
    /// [`Engine::validate_all`]). An `Err` names the rule and meta key.
    chains: HashMap<String, OnceLock<Result<Chain, String>>>,
    /// Compiled regexes by source text, shared between rules.
    regexes: Mutex<HashMap<String, Regex>>,
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
    /// Cheap: post-processors are compiled per rule on its first match, so
    /// start-up cost does not grow with the number of rules. Use
    /// [`Engine::validate_all`] to compile and check every rule up front.
    pub fn new(bundle: Bundle) -> Result<Engine, EngineError> {
        let chains = bundle
            .meta
            .keys()
            .map(|k| (k.clone(), OnceLock::new()))
            .collect();
        Ok(Engine {
            bundle,
            chains,
            regexes: Mutex::new(HashMap::new()),
        })
    }

    /// Build every rule's post-processor chain now. The first failure (in
    /// rule key order) names the rule and the meta key that held the bad
    /// value.
    pub fn validate_all(&self) -> Result<(), EngineError> {
        let mut keys: Vec<&String> = self.chains.keys().collect();
        keys.sort();
        for key in keys {
            self.chain(key).map_err(EngineError)?;
        }
        Ok(())
    }

    /// Number of distinct regexes compiled so far.
    pub fn compiled_regexes(&self) -> usize {
        self.regexes.lock().map_or(0, |m| m.len())
    }

    fn regex(&self, src: &str) -> Result<Regex, regex::Error> {
        let mut cache = self.regexes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(re) = cache.get(src) {
            return Ok(re.clone());
        }
        let re = post::compile_regex(src)?;
        cache.insert(src.to_string(), re.clone());
        Ok(re)
    }

    fn chain(&self, key: &str) -> Result<&[Box<dyn Post>], String> {
        let (Some(meta), Some(cell)) = (self.bundle.meta.get(key), self.chains.get(key)) else {
            return Err(format!("rule {key}: no metadata"));
        };
        let built = cell.get_or_init(|| {
            meta.post
                .iter()
                .map(|spec| {
                    post::build(spec, &self.bundle.stopwords, &|s| self.regex(s))
                        .map_err(|(k, e)| format!("rule {key}: `{k}`: {e}"))
                })
                .collect()
        });
        match built {
            Ok(chain) => Ok(chain),
            Err(e) => Err(e.clone()),
        }
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
        // Digest of the whole content, for evidence its matched bytes do not
        // identify (see `Evidence::fingerprints`).
        let mut whole_digest: Option<[u8; 32]> = None;
        let mut content_digest =
            || *whole_digest.get_or_insert_with(|| *blake3::hash(content).as_bytes());
        for rule in results.matching_rules() {
            let key = format!("{}:{}", rule.namespace(), rule.identifier());
            let chain = self.chain(&key).map_err(ScanError::Yara)?;
            let meta = &self.bundle.meta[&key];
            // A whole-content verdict matches on a shared anchor (a magic
            // number), so the content, not the anchor, identifies it.
            let by_content = chain.iter().any(|p| p.whole_content());
            let mut has_anchor = false;
            let mut ranges = Vec::new();
            // A range-producing processor replaces the pattern matches: the
            // rule's patterns are only its cheap trigger.
            let producer = chain
                .iter()
                .enumerate()
                .find_map(|(i, p)| p.runs(content).map(|r| (i, r)));
            let mut producer_idx = None;
            if let Some((i, runs)) = producer {
                if runs.is_empty() {
                    continue;
                }
                has_anchor = true;
                ranges = runs;
                producer_idx = Some(i);
            } else {
                for p in rule.patterns() {
                    if is_anchor(p.identifier()) {
                        has_anchor = true;
                        ranges.extend(p.matches().map(|m| m.range()));
                    }
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
                        if producer_idx == Some(i) {
                            continue;
                        }
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
                    ev.fingerprints.push(if by_content {
                        content_digest()
                    } else {
                        *blake3::hash(&content[range]).as_bytes()
                    });
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
            } else {
                ev.fingerprints.push(content_digest());
            }
            found.push((key, ev));
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(found.into_iter().map(|(_, e)| e).collect())
    }
}
