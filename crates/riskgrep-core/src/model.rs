//! Report model. Types here cannot hold matched content: evidence carries
//! rule ids, counts, offsets, and structural facts only.

use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;

/// Round to one decimal, half away from zero.
pub fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn ser_scores<S: Serializer>(m: &BTreeMap<Category, f64>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_map(m.iter().map(|(k, v)| (k, round1(*v))))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Category(pub String);

/// Byte offsets into the scanned content; lines are 1-based.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub start: u64,
    pub end: u64,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ShapeFacts {
    Tensor {
        dtype: String,
        shape: Vec<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Bare rule identifier, e.g. `aws_access_token`.
    pub rule: String,
    pub category: Category,
    pub weight: f64,
    pub count: u32,
    pub locations: Vec<Location>,
    pub shape: Vec<ShapeFacts>,
    /// One BLAKE3 digest of the matched bytes per location; empty for
    /// structural rules. Never serialized.
    #[serde(skip)]
    pub fingerprints: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TargetStatus {
    Scanned,
    Partial { not_read: String },
    Skipped { reason: String },
    Unscanned { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TargetReport {
    pub target: String,
    #[serde(flatten)]
    pub status: TargetStatus,
    #[serde(serialize_with = "ser_scores")]
    pub scores: BTreeMap<Category, f64>,
    pub evidence: Vec<Evidence>,
    pub suppressed: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    #[serde(serialize_with = "ser_scores")]
    pub scores: BTreeMap<Category, f64>,
    pub targets: u32,
    pub scanned: u32,
    pub partial: u32,
    pub skipped: u32,
    pub unscanned: u32,
    pub suppressed: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub riskgrep_version: String,
    pub rules_bundle: String,
    pub summary: Summary,
    pub targets: Vec<TargetReport>,
}

impl Report {
    pub fn from_targets(version: &str, bundle: &str, targets: Vec<TargetReport>) -> Report {
        let mut summary = Summary {
            scores: BTreeMap::new(),
            targets: targets.len() as u32,
            scanned: 0,
            partial: 0,
            skipped: 0,
            unscanned: 0,
            suppressed: 0,
        };
        for t in &targets {
            match t.status {
                TargetStatus::Scanned => summary.scanned += 1,
                TargetStatus::Partial { .. } => summary.partial += 1,
                TargetStatus::Skipped { .. } => summary.skipped += 1,
                TargetStatus::Unscanned { .. } => summary.unscanned += 1,
            }
            summary.suppressed += t.suppressed;
            for (cat, &s) in &t.scores {
                let e = summary.scores.entry(cat.clone()).or_insert(s);
                if s > *e {
                    *e = s;
                }
            }
        }
        Report {
            riskgrep_version: version.to_string(),
            rules_bundle: bundle.to_string(),
            summary,
            targets,
        }
    }
}
