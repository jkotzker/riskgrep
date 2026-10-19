//! Suppression: path/rule ignore globs and the fingerprint baseline.
//! Fingerprints are keyed hashes of the rule, the repository-relative path,
//! and the digest of the matched bytes, so neither the baseline file nor a
//! fingerprint can reveal a matched value.

use crate::model::TargetReport;
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressError(pub String);

impl fmt::Display for SuppressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SuppressError {}

/// One `[[ignore.rules]]` entry: rules suppressed under a path glob.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleIgnore {
    pub path: String,
    pub rules: Vec<String>,
}

/// The `[ignore]` table as written in configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreSpec {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleIgnore>,
}

/// Compiled ignore globs.
#[derive(Debug, Clone, Default)]
pub struct IgnoreRules {
    spec: IgnoreSpec,
    paths: Vec<GlobMatcher>,
    rules: Vec<(GlobMatcher, Vec<String>)>,
}

fn glob(pattern: &str) -> Result<GlobMatcher, SuppressError> {
    Glob::new(pattern)
        .map(|g| g.compile_matcher())
        .map_err(|e| SuppressError(format!("invalid ignore glob `{pattern}`: {e}")))
}

impl IgnoreRules {
    pub fn new(spec: IgnoreSpec) -> Result<IgnoreRules, SuppressError> {
        let paths = spec
            .paths
            .iter()
            .map(|p| glob(p))
            .collect::<Result<_, _>>()?;
        let rules = spec
            .rules
            .iter()
            .map(|r| Ok((glob(&r.path)?, r.rules.clone())))
            .collect::<Result<_, SuppressError>>()?;
        Ok(IgnoreRules { spec, paths, rules })
    }

    pub fn spec(&self) -> &IgnoreSpec {
        &self.spec
    }

    /// True when `rule` findings in `rel_path` are ignored.
    pub fn ignores(&self, rel_path: &str, rule: &str) -> bool {
        self.paths.iter().any(|g| g.is_match(rel_path))
            || self
                .rules
                .iter()
                .any(|(g, rules)| g.is_match(rel_path) && rules.iter().any(|r| r == rule))
    }
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            let h = (p[0] as char).to_digit(16)?;
            let l = (p[1] as char).to_digit(16)?;
            Some((h * 16 + l) as u8)
        })
        .collect()
}

/// Keyed fingerprint of one finding. `matched_digest` is the BLAKE3 digest
/// the engine stored in `Evidence.fingerprints`; structural evidence has
/// none and is identified by rule and path alone.
pub fn fingerprint(
    key: &[u8; 32],
    rule: &str,
    rel_path: &str,
    matched_digest: Option<&[u8; 32]>,
) -> String {
    let mut buf = Vec::with_capacity(rule.len() + rel_path.len() + 34);
    buf.extend_from_slice(rule.as_bytes());
    buf.push(0);
    buf.extend_from_slice(rel_path.as_bytes());
    buf.push(0);
    if let Some(d) = matched_digest {
        buf.extend_from_slice(d);
    }
    hex(blake3::keyed_hash(key, &buf).as_bytes())
}

/// Fingerprint inputs of one evidence item: one digest per location when
/// the evidence is location-addressable, otherwise a single unit.
fn units(ev: &crate::model::Evidence) -> Vec<Option<&[u8; 32]>> {
    if !ev.locations.is_empty() && ev.fingerprints.len() == ev.locations.len() {
        ev.fingerprints.iter().map(Some).collect()
    } else {
        vec![None]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub key: [u8; 32],
    pub fingerprints: BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineFile {
    version: u32,
    key: String,
    fingerprints: Vec<String>,
}

impl Baseline {
    /// Baseline of every finding in `targets`, under a fresh random key.
    pub fn create(
        targets: &[TargetReport],
        rel: impl Fn(&str) -> String,
    ) -> Result<Baseline, SuppressError> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)
            .map_err(|e| SuppressError(format!("no system randomness: {e}")))?;
        let mut fingerprints = BTreeSet::new();
        for t in targets {
            let path = rel(&t.target);
            for ev in &t.evidence {
                for u in units(ev) {
                    fingerprints.insert(fingerprint(&key, &ev.rule, &path, u));
                }
            }
        }
        Ok(Baseline { key, fingerprints })
    }

    pub fn load(path: &Path) -> Result<Baseline, SuppressError> {
        let name = path.display();
        let raw = std::fs::read(path)
            .map_err(|e| SuppressError(format!("cannot read baseline {name}: {e}")))?;
        let f: BaselineFile = serde_json::from_slice(&raw)
            .map_err(|e| SuppressError(format!("invalid baseline {name}: {e}")))?;
        if f.version != 1 {
            return Err(SuppressError(format!(
                "baseline {name}: unsupported version {}",
                f.version
            )));
        }
        let key: [u8; 32] = unhex(&f.key)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| SuppressError(format!("baseline {name}: `key` is not 64 hex digits")))?;
        Ok(Baseline {
            key,
            fingerprints: f.fingerprints.into_iter().collect(),
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), SuppressError> {
        let f = BaselineFile {
            version: 1,
            key: hex(&self.key),
            fingerprints: self.fingerprints.iter().cloned().collect(),
        };
        let mut json = serde_json::to_vec_pretty(&f).map_err(|e| SuppressError(e.to_string()))?;
        json.push(b'\n');
        let name = path.display();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(path)
            .map_err(|e| SuppressError(format!("cannot write baseline {name}: {e}")))?;
        file.write_all(&json)
            .map_err(|e| SuppressError(format!("cannot write baseline {name}: {e}")))
    }

    fn contains(&self, rule: &str, rel_path: &str, digest: Option<&[u8; 32]>) -> bool {
        self.fingerprints
            .contains(&fingerprint(&self.key, rule, rel_path, digest))
    }
}

/// Remove ignored and baselined findings. Multi-location evidence loses
/// only the suppressed locations; evidence left with none is dropped.
/// `suppressed` grows by the locations removed (1 for a whole item).
/// Scores are not recomputed.
pub fn apply(
    targets: &mut [TargetReport],
    ignore: &IgnoreRules,
    baseline: Option<&Baseline>,
    rel: impl Fn(&str) -> String,
) {
    for t in targets.iter_mut() {
        let path = rel(&t.target);
        let mut removed = 0u32;
        let mut kept = Vec::with_capacity(t.evidence.len());
        for mut ev in std::mem::take(&mut t.evidence) {
            let ignored = ignore.ignores(&path, &ev.rule);
            let suppress = |digest: Option<&[u8; 32]>| {
                ignored || baseline.is_some_and(|b| b.contains(&ev.rule, &path, digest))
            };
            if ev.locations.is_empty() || ev.fingerprints.len() != ev.locations.len() {
                if suppress(None) {
                    removed += 1;
                } else {
                    kept.push(ev);
                }
                continue;
            }
            let drop: Vec<bool> = ev.fingerprints.iter().map(|d| suppress(Some(d))).collect();
            let n = drop.iter().filter(|d| **d).count();
            if n == 0 {
                kept.push(ev);
                continue;
            }
            removed += n as u32;
            let mut i = 0;
            ev.locations.retain(|_| {
                i += 1;
                !drop[i - 1]
            });
            let mut i = 0;
            ev.fingerprints.retain(|_| {
                i += 1;
                !drop[i - 1]
            });
            ev.count = ev.count.saturating_sub(n as u32);
            if !ev.locations.is_empty() {
                kept.push(ev);
            }
        }
        t.evidence = kept;
        t.suppressed += removed;
    }
}
