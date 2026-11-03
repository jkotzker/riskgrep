//! Report model. Types here cannot hold matched content: evidence carries
//! rule ids, counts, offsets, and structural facts only.

use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;

/// Round to one decimal, half away from zero.
pub fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Whether `score` meets `threshold`: the score rounded to one decimal, the
/// number every output shows, is at or above it. Every threshold in RiskGrep
/// (`scan --fail-at`, the git hook's `block_at`, the Claude Code hook's
/// `ask` and `deny`) uses this one rule.
pub fn meets_threshold(score: f64, threshold: f64) -> bool {
    round1(score) >= threshold
}

fn ser_scores<S: Serializer>(m: &BTreeMap<Category, f64>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_map(m.iter().map(|(k, v)| (k, round1(*v))))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Category(pub String);

/// Byte offsets into the file (for formats read selectively, such as tensor
/// headers, into the bytes read; for evidence in a container member, into
/// the member's uncompressed bytes); lines are 1-based, and 0 when unknown:
/// evidence in the tail sample of a partly read text file has file offsets
/// but no line numbers, because the lines it skipped were not counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub start: u64,
    pub end: u64,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ShapeFacts {
    Tensor {
        dtype: String,
        shape: Vec<u64>,
        /// In memory only: names come from the file and may be personal data.
        #[serde(skip)]
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
    /// One BLAKE3 digest per location: of the matched bytes, or, for rules
    /// decided by a whole-content post-processor (tensor headers), of all
    /// the bytes scanned. Location-free evidence (path and condition-only
    /// rules) carries one digest of all the bytes scanned. Never serialized.
    #[serde(skip)]
    pub fingerprints: Vec<[u8; 32]>,
    /// The rule is marked `line_complete`: every match of it gets its own
    /// location, and a match never spans more lines than its location, so
    /// the locations bound what the file holds for this rule. Set from the
    /// rule metadata when the target is scored; never stored.
    #[serde(skip)]
    pub line_complete: bool,
    /// For evidence found in a container member: the member's path inside
    /// the container (`config/.env`, nested `inner.zip!/x`). Its locations
    /// are offsets and lines in that member. Absent for evidence about the
    /// file itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
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
    /// The content was scanned as text and its evidence line numbers are the
    /// lines the consumer numbers, so line ranges may be matched against
    /// them. False for binary formats read by structure (key stores, tensor
    /// files), for targets that were not scanned, for UTF-16 and UTF-32 text
    /// other than UTF-16 LE with a byte-order mark (see
    /// [`crate::classify::FileClass::is_text`]), and for every UTF-16 and
    /// UTF-32 git blob, whose lines git numbers at 0x0A bytes.
    #[serde(skip)]
    pub text: bool,
    /// Set for a container whose members were read (an archive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerReport>,
    /// The `partial` status is content that could not be read (an `.npz`
    /// member that does not read), not a part left unread by a read limit.
    /// Only the wording of the hooks' messages depends on it: `on_partial`
    /// applies to both (see [`TargetReport::unseen_part`]).
    #[serde(skip)]
    pub read_failed: bool,
}

impl TargetReport {
    /// What was not read, when `on_partial` applies: part of the content was
    /// never seen, as with every `partial` target: a container with a member
    /// not read whole, text sampled at its ends, a key store, a tensor header,
    /// or standard input past its limit, or an `.npz`'s unreadable member.
    /// `None` for a file read whole, and for one whose format is read for its
    /// header alone (`.npy` and vault files), which is `scanned`.
    pub fn unseen_part(&self) -> Option<&str> {
        match &self.status {
            TargetStatus::Partial { not_read } => Some(not_read),
            _ => None,
        }
    }
}

/// What a container's members held.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContainerReport {
    /// The extractor that read it, e.g. `zip`.
    pub format: String,
    /// Members examined or counted, nested members included. Each is in
    /// exactly one of the counts below, which add up to this.
    pub members: u64,
    /// Members read whole and scanned.
    pub scanned: u64,
    /// Members read and scanned only in part: sampled, cut at a limit, or
    /// holding bytes their stream does not show.
    pub read_in_part: u64,
    /// Members of formats that are not scanned (images, binary files of
    /// unknown format).
    pub skipped: u64,
    /// Members not read or not scanned at all.
    pub not_read: u64,
    /// Nested containers opened; what they hold is counted as members.
    pub opened: u64,
    /// Members with evidence, then members not read whole, at most
    /// [`crate::container::LISTED_MAX`].
    pub listed: Vec<MemberReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MemberReport {
    /// Path inside the container, as in [`Evidence::member`].
    pub path: String,
    #[serde(flatten)]
    pub status: TargetStatus,
    /// The member's own scores, for display; the container's scores cover
    /// all of its members together.
    #[serde(serialize_with = "ser_scores")]
    pub scores: BTreeMap<Category, f64>,
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

#[cfg(test)]
mod threshold_tests {
    use super::*;

    #[test]
    fn threshold_is_inclusive_and_uses_the_rounded_score() {
        assert!(meets_threshold(80.0, 80.0));
        assert!(!meets_threshold(80.0, 80.1));
        assert!(meets_threshold(80.0, 79.9));
        // Raw 79.96 shows as 80.0, so it meets 80.
        assert_eq!(round1(79.96), 80.0);
        assert!(meets_threshold(79.96, 80.0));
        // Raw 79.94 shows as 79.9, so it does not.
        assert!(!meets_threshold(79.94, 80.0));
        assert!(meets_threshold(79.94, 79.9));
    }
}
