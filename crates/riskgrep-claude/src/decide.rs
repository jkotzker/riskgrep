//! The hook decision: a pure function of the scan report, the config, and
//! the lines a `Read` call asks for.

use crate::input::Lines;
use riskgrep_core::config::{Action, ClaudeCodeConfig};
use riskgrep_core::model::{meets_threshold, round1};
use riskgrep_core::{Category, Report, TargetReport, TargetStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    NoOpinion,
    Ask(String),
    Deny(String),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Sev {
    Ask,
    Deny,
}

struct Item {
    sev: Sev,
    score: f64,
    text: String,
    /// For a category finding: its target, and whether that target's
    /// flagged lines are known (a partial read is possible).
    finding: Option<(usize, bool)>,
}

/// How many reasons are listed before `and N more`.
const LISTED: usize = 3;
/// Rule ids named per finding.
const RULES_NAMED: usize = 5;
/// Line ranges named per finding.
const RANGES_NAMED: usize = 50;

const OTHER_MEANS_ONE: &str = "Do not read this file by other means (Bash, Grep, scripts).";
const OTHER_MEANS_MANY: &str = "Do not read these files by other means (Bash, Grep, scripts).";
const RANGE_ONE: &str = "To use the rest of it, Read it with offset and limit ranges that exclude the lines above, or ask the user.";
const RANGE_MANY: &str = "To use the rest of them, Read each with offset and limit ranges that exclude the lines above, or ask the user.";
const NO_PARTIAL_ONE: &str = "No partial read is available for this file; ask the user.";
const NO_PARTIAL_MANY: &str = "No partial read is available for these files; ask the user.";
const MIXED: &str = "Read a file with listed lines using offset and limit ranges that exclude them; no partial read is available for the others; ask the user.";

fn severity(a: Action) -> Option<Sev> {
    match a {
        Action::Allow => None,
        Action::Ask => Some(Sev::Ask),
        Action::Deny | Action::Block => Some(Sev::Deny),
    }
}

/// The decision for `action` when something went wrong, with `reason`.
pub fn error_decision(action: Action, reason: &str) -> Decision {
    match severity(action) {
        None => Decision::NoOpinion,
        Some(Sev::Ask) => Decision::Ask(reason.to_string()),
        Some(Sev::Deny) => Decision::Deny(reason.to_string()),
    }
}

fn num(n: f64) -> String {
    format!("{n}")
}

/// Claude Code 2.1.301 ignores `offset` and `limit` for notebooks: `Read`
/// of an `.ipynb` file (any case) returns every cell.
fn is_notebook(target: &str) -> bool {
    let n = target.len();
    n >= 6 && target.is_char_boundary(n - 6) && target[n - 6..].eq_ignore_ascii_case(".ipynb")
}

/// The merged line ranges (1-based, inclusive) of `t`'s evidence in
/// `cats`, or `None` when they cannot bound what a partial read would show:
/// the target was not read whole, is not text, is a notebook, or some of
/// that evidence comes from a rule not marked line-complete (whose matches
/// may span lines or go unlocated), has no location, an unknown line (0),
/// or structural facts.
fn flagged_lines(t: &TargetReport, cats: &[&Category]) -> Option<Vec<(u32, u32)>> {
    if t.status != TargetStatus::Scanned || !t.text || is_notebook(&t.target) {
        return None;
    }
    let mut ranges = Vec::new();
    for e in t.evidence.iter().filter(|e| cats.contains(&&e.category)) {
        if !e.line_complete || e.locations.is_empty() || !e.shape.is_empty() {
            return None;
        }
        for l in &e.locations {
            if l.line_start == 0 || l.line_end < l.line_start {
                return None;
            }
            ranges.push((l.line_start, l.line_end));
        }
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (a, b) in ranges {
        match merged.last_mut() {
            Some(last) if u64::from(a) <= u64::from(last.1) + 1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    Some(merged)
}

/// Whether the requested lines, widened by one line on each side, touch
/// any of `ranges`.
fn overlaps(req: Lines, ranges: &[(u32, u32)]) -> bool {
    let lo = req.first.saturating_sub(1);
    let hi = req.last.map_or(u64::MAX, |l| l.saturating_add(1));
    ranges
        .iter()
        .any(|&(a, b)| u64::from(a) <= hi && lo <= u64::from(b))
}

/// `line 10`, `lines 3–7, 20`, with at most [`RANGES_NAMED`] ranges named.
fn describe(ranges: &[(u32, u32)]) -> String {
    let plural = ranges.len() > 1 || ranges.first().is_some_and(|r| r.0 != r.1);
    let mut parts: Vec<String> = ranges
        .iter()
        .take(RANGES_NAMED)
        .map(|&(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}\u{2013}{b}")
            }
        })
        .collect();
    let extra = ranges.len().saturating_sub(RANGES_NAMED);
    if extra > 0 {
        parts.push(format!("and {extra} more"));
    }
    format!(
        "{} {}",
        if plural { "lines" } else { "line" },
        parts.join(", ")
    )
}

/// What the agent may do instead, for the category findings listed.
fn guidance(listed: &[&Item]) -> Option<String> {
    let mut files: Vec<(usize, bool)> = listed.iter().filter_map(|i| i.finding).collect();
    files.sort_unstable();
    files.dedup();
    if files.is_empty() {
        return None;
    }
    let partial = files.iter().filter(|f| f.1).count();
    let (other, then) = match (files.len(), partial) {
        (1, 1) => (OTHER_MEANS_ONE, RANGE_ONE),
        (1, _) => (OTHER_MEANS_ONE, NO_PARTIAL_ONE),
        (n, p) if p == n => (OTHER_MEANS_MANY, RANGE_MANY),
        (_, 0) => (OTHER_MEANS_MANY, NO_PARTIAL_MANY),
        _ => (OTHER_MEANS_MANY, MIXED),
    };
    Some(format!("{other} {then}"))
}

/// The decision for `report`. `lines` is what a `Read` call asks for
/// ([`crate::input::requested_lines`]): a category whose flagged lines it
/// avoids, after widening by one line on each side, is dropped. A target
/// whose flagged lines are not all known gets no such allowance.
pub fn decide(
    report: &Report,
    unresolved: bool,
    cfg: &ClaudeCodeConfig,
    lines: Option<Lines>,
) -> Decision {
    let mut items: Vec<Item> = Vec::new();
    for (ti, t) in report.targets.iter().enumerate() {
        let not_scanned = match &t.status {
            TargetStatus::Unscanned { reason } => severity(cfg.on_error).map(|s| (s, reason)),
            TargetStatus::Skipped { reason } => severity(cfg.on_skipped).map(|s| (s, reason)),
            _ => None,
        };
        if let Some((sev, reason)) = not_scanned {
            items.push(Item {
                sev,
                score: -1.0,
                text: format!("RiskGrep: could not scan {} ({reason})", t.target),
                finding: None,
            });
        }
        let mut hits: Vec<(&Category, f64, Sev, f64)> = Vec::new();
        for (cat, &raw) in &t.scores {
            let Some(th) = cfg.thresholds.get(cat) else {
                continue;
            };
            if let Some(d) = th.deny.filter(|d| meets_threshold(raw, *d)) {
                hits.push((cat, raw, Sev::Deny, d));
            } else if let Some(a) = th.ask.filter(|a| meets_threshold(raw, *a)) {
                hits.push((cat, raw, Sev::Ask, a));
            }
        }
        let cats: Vec<&Category> = hits.iter().map(|h| h.0).collect();
        let partial = !hits.is_empty() && flagged_lines(t, &cats).is_some();
        for (cat, raw, sev, at) in hits {
            let own = if partial {
                flagged_lines(t, &[cat])
            } else {
                None
            };
            if let (Some(req), Some(ranges)) = (lines, &own) {
                if !overlaps(req, ranges) {
                    continue;
                }
            }
            let mut rules: Vec<&str> = Vec::new();
            for e in t.evidence.iter().filter(|e| &e.category == cat) {
                if !rules.contains(&e.rule.as_str()) {
                    rules.push(&e.rule);
                }
            }
            let extra = rules.len().saturating_sub(RULES_NAMED);
            rules.truncate(RULES_NAMED);
            let mut named = rules.join(", ");
            if extra > 0 {
                named.push_str(&format!(", and {extra} more"));
            }
            let located = own
                .as_deref()
                .map_or_else(String::new, |r| format!(" on {}", describe(r)));
            let level = if sev == Sev::Deny { "deny" } else { "ask" };
            let score = round1(raw);
            items.push(Item {
                sev,
                score,
                text: format!(
                    "RiskGrep: {} scored {} {:.1} ({}){located}. Threshold: {level} at {}.",
                    t.target,
                    cat.0,
                    score,
                    named,
                    num(at)
                ),
                finding: Some((ti, partial)),
            });
        }
    }
    if unresolved {
        if let Some(sev) = severity(cfg.on_unresolved) {
            items.push(Item {
                sev,
                score: -1.0,
                text: "RiskGrep: command reads files that could not be determined".to_string(),
                finding: None,
            });
        }
    }
    let Some(top) = items.iter().map(|i| i.sev).max() else {
        return Decision::NoOpinion;
    };
    let mut chosen: Vec<&Item> = items.iter().filter(|i| i.sev == top).collect();
    chosen.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.text.cmp(&b.text)));
    let more = chosen.len().saturating_sub(LISTED);
    chosen.truncate(LISTED);
    let mut reason = chosen
        .iter()
        .map(|i| i.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    if more > 0 {
        if reason.ends_with('.') {
            reason.pop();
        }
        reason.push_str(&format!(", and {more} more."));
    }
    if let Some(g) = guidance(&chosen) {
        reason.push(' ');
        reason.push_str(&g);
    }
    match top {
        Sev::Ask => Decision::Ask(reason),
        Sev::Deny => Decision::Deny(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::config::Config;
    use riskgrep_core::{Category, Evidence, Location, TargetReport};
    use std::collections::BTreeMap;

    fn target(path: &str, cat: &str, score: f64) -> TargetReport {
        TargetReport {
            target: path.to_string(),
            status: TargetStatus::Scanned,
            scores: BTreeMap::from([(Category(cat.to_string()), score)]),
            evidence: vec![Evidence {
                rule: "r1".into(),
                category: Category(cat.to_string()),
                weight: 1.0,
                count: 1,
                locations: vec![],
                shape: vec![],
                fingerprints: vec![],
                line_complete: false,
            }],
            suppressed: 0,
            text: true,
        }
    }

    fn report(ts: Vec<TargetReport>) -> Report {
        Report::from_targets("0", "b", ts)
    }

    const NP1: &str = " Do not read this file by other means (Bash, Grep, scripts). No partial read is available for this file; ask the user.";
    const RANGE1: &str = " Do not read this file by other means (Bash, Grep, scripts). To use the rest of it, Read it with offset and limit ranges that exclude the lines above, or ask the user.";

    fn ev(rule: &str, cat: &str, lines: &[(u32, u32)]) -> Evidence {
        Evidence {
            rule: rule.into(),
            category: Category(cat.to_string()),
            weight: 1.0,
            count: lines.len() as u32,
            locations: lines
                .iter()
                .map(|&(a, b)| Location {
                    start: 0,
                    end: 1,
                    line_start: a,
                    line_end: b,
                })
                .collect(),
            shape: vec![],
            fingerprints: vec![],
            line_complete: true,
        }
    }

    /// A scanned text target with evidence at known lines.
    fn lined(path: &str, scores: &[(&str, f64)], evidence: Vec<Evidence>) -> TargetReport {
        TargetReport {
            target: path.to_string(),
            status: TargetStatus::Scanned,
            scores: scores
                .iter()
                .map(|&(c, s)| (Category(c.to_string()), s))
                .collect(),
            evidence,
            suppressed: 0,
            text: true,
        }
    }

    fn secret_at(lines: &[(u32, u32)]) -> TargetReport {
        lined(
            "/a",
            &[("secret", 95.0)],
            vec![ev("aws_access_token", "secret", lines)],
        )
    }

    fn read(first: u64, last: Option<u64>) -> Option<Lines> {
        Some(Lines { first, last })
    }

    fn deny_or_none(t: &TargetReport, lines: Option<Lines>) -> &'static str {
        let cfg = Config::default().claude_code;
        match decide(&report(vec![t.clone()]), false, &cfg, lines) {
            Decision::NoOpinion => "none",
            Decision::Ask(_) => "ask",
            Decision::Deny(_) => "deny",
        }
    }

    #[test]
    fn reason_lists_lines_and_the_safe_paths() {
        let cfg = Config::default().claude_code;
        let d = decide(&report(vec![secret_at(&[(10, 10)])]), false, &cfg, None);
        assert_eq!(
            d,
            Decision::Deny(format!(
                "RiskGrep: /a scored secret 95.0 (aws_access_token) on line 10. Threshold: deny at 95.{RANGE1}"
            ))
        );
        let t = secret_at(&[(20, 20), (3, 7), (21, 22), (5, 6)]);
        let Decision::Deny(text) = decide(&report(vec![t]), false, &cfg, None) else {
            panic!("expected deny")
        };
        assert!(
            text.contains("(aws_access_token) on lines 3\u{2013}7, 20\u{2013}22."),
            "{text}"
        );
    }

    #[test]
    fn many_ranges_are_capped_in_the_text_but_all_count() {
        let cfg = Config::default().claude_code;
        let lines: Vec<(u32, u32)> = (1..=60).map(|i| (2 * i, 2 * i)).collect();
        let t = secret_at(&lines);
        let Decision::Deny(text) = decide(&report(vec![t.clone()]), false, &cfg, None) else {
            panic!("expected deny")
        };
        assert!(text.contains("on lines 2, 4, "), "{text}");
        assert!(text.contains(", 100, and 10 more. Threshold"), "{text}");
        assert!(!text.contains(" 102,"), "{text}");
        // The unlisted ranges still count: line 120 is flagged.
        assert_eq!(deny_or_none(&t, read(119, Some(119))), "deny");
        assert_eq!(deny_or_none(&t, read(123, None)), "none");
    }

    #[test]
    fn read_range_avoiding_flagged_lines_gets_no_decision() {
        let t = secret_at(&[(10, 10)]);
        assert_eq!(deny_or_none(&t, read(1, Some(8))), "none");
        // Widened by one line on each side, 1-9 touches line 10.
        assert_eq!(deny_or_none(&t, read(1, Some(9))), "deny");
        assert_eq!(deny_or_none(&t, read(11, Some(20))), "deny");
        assert_eq!(deny_or_none(&t, read(12, Some(21))), "none");
        assert_eq!(deny_or_none(&t, read(5, Some(14))), "deny");
        assert_eq!(deny_or_none(&t, read(12, None)), "none");
        assert_eq!(deny_or_none(&t, read(1, None)), "deny");
        assert_eq!(deny_or_none(&t, None), "deny");
        // A block of lines 3-7: anything within 2-8 overlaps once widened.
        let pem = secret_at(&[(3, 7)]);
        for (first, last) in [(1, 1), (2, 2), (8, 8), (9, 9), (5, 5), (1, 100)] {
            let expect = if first <= 8 && last >= 2 {
                "deny"
            } else {
                "none"
            };
            assert_eq!(
                deny_or_none(&pem, read(first, Some(last))),
                expect,
                "{first}-{last}"
            );
        }
        let two = secret_at(&[(5, 5), (20, 20)]);
        assert_eq!(deny_or_none(&two, read(8, Some(16))), "none");
        assert_eq!(deny_or_none(&two, read(8, Some(21))), "deny");
    }

    #[test]
    fn ask_level_findings_get_the_same_allowance() {
        let t = lined(
            "/e.txt",
            &[("biometric", 60.0)],
            vec![ev("printed_embedding_array", "biometric", &[(10, 10)])],
        );
        assert_eq!(deny_or_none(&t, None), "ask");
        assert_eq!(deny_or_none(&t, read(1, Some(9))), "ask");
        assert_eq!(deny_or_none(&t, read(1, Some(8))), "none");
    }

    #[test]
    fn no_partial_read_when_lines_cannot_be_trusted() {
        let cfg = Config::default().claude_code;
        let mut cases: Vec<(&str, TargetReport)> = Vec::new();
        let mut t = secret_at(&[(10, 10)]);
        t.status = TargetStatus::Partial {
            not_read: "bytes 1..2 not read".into(),
        };
        cases.push(("partial", t));
        cases.push(("unknown line", secret_at(&[(10, 10), (0, 0)])));
        let mut t = secret_at(&[(10, 10)]);
        t.evidence.push(ev("pkcs12_file", "secret", &[]));
        cases.push(("location-free rule", t));
        let mut t = secret_at(&[(1, 1)]);
        t.evidence[0]
            .shape
            .push(riskgrep_core::model::ShapeFacts::Tensor {
                dtype: "F32".into(),
                shape: vec![1, 192],
                name: None,
            });
        cases.push(("structural shape", t));
        let mut t = secret_at(&[(1, 1)]);
        t.text = false;
        cases.push(("binary file", t));
        let mut t = secret_at(&[(10, 10)]);
        t.target = "/nb/Analysis.IPYNB".into();
        cases.push(("notebook", t));
        let mut t = secret_at(&[(10, 10)]);
        t.evidence[0].line_complete = false;
        cases.push(("rule not line-complete", t));
        for (what, t) in cases {
            let d = decide(&report(vec![t.clone()]), false, &cfg, read(1, Some(2)));
            let Decision::Deny(text) = d else {
                panic!("{what}: expected deny, got {d:?}")
            };
            assert!(text.ends_with(NP1), "{what}: {text}");
            assert!(!text.contains(" on line"), "{what}: {text}");
        }
    }

    #[test]
    fn below_threshold_structural_evidence_does_not_block_the_allowance() {
        // A biometric path hit scoring 30 asks for nothing; the secret's
        // lines alone decide.
        let mut t = secret_at(&[(10, 10)]);
        t.scores.insert(Category("biometric".into()), 30.0);
        t.evidence.push(ev("path_biometric_name", "biometric", &[]));
        assert_eq!(deny_or_none(&t, read(1, Some(8))), "none");
    }

    #[test]
    fn each_category_is_dropped_on_its_own_lines() {
        let t = lined(
            "/a",
            &[("secret", 95.0), ("biometric", 60.0)],
            vec![
                ev("aws_access_token", "secret", &[(10, 10)]),
                ev("printed_embedding_array", "biometric", &[(30, 30)]),
            ],
        );
        assert_eq!(deny_or_none(&t, None), "deny");
        assert_eq!(deny_or_none(&t, read(1, Some(8))), "none");
        // Lines 25-35 avoid the secret but hold the embedding.
        let cfg = Config::default().claude_code;
        let d = decide(&report(vec![t.clone()]), false, &cfg, read(25, Some(35)));
        assert_eq!(
            d,
            Decision::Ask(format!(
                "RiskGrep: /a scored biometric 60.0 (printed_embedding_array) on line 30. Threshold: ask at 50.{RANGE1}"
            ))
        );
        // A structural finding in either category removes the allowance.
        let mut s = t.clone();
        s.evidence.push(ev("path_biometric_name", "biometric", &[]));
        assert_eq!(deny_or_none(&s, read(1, Some(8))), "deny");
    }

    #[test]
    fn unscanned_items_survive_a_range() {
        let mut cfg = Config::default().claude_code;
        cfg.on_error = Action::Deny;
        let mut bad = target("/u", "secret", 0.0);
        bad.status = TargetStatus::Unscanned {
            reason: "timeout".into(),
        };
        let d = decide(&report(vec![bad]), false, &cfg, read(1, Some(2)));
        assert_eq!(
            d,
            Decision::Deny("RiskGrep: could not scan /u (timeout)".into())
        );
    }

    #[test]
    fn several_files_get_plural_or_mixed_guidance() {
        let cfg = Config::default().claude_code;
        let mut b = secret_at(&[(4, 4)]);
        b.target = "/b".into();
        let Decision::Deny(text) =
            decide(&report(vec![secret_at(&[(10, 10)]), b]), false, &cfg, None)
        else {
            panic!("expected deny")
        };
        assert!(text.ends_with(" Do not read these files by other means (Bash, Grep, scripts). To use the rest of them, Read each with offset and limit ranges that exclude the lines above, or ask the user."), "{text}");
        let Decision::Deny(text) = decide(
            &report(vec![secret_at(&[(10, 10)]), target("/c", "secret", 95.0)]),
            false,
            &cfg,
            None,
        ) else {
            panic!("expected deny")
        };
        assert!(text.ends_with(" Do not read these files by other means (Bash, Grep, scripts). Read a file with listed lines using offset and limit ranges that exclude them; no partial read is available for the others; ask the user."), "{text}");
    }

    #[test]
    fn deny_beats_ask_and_text_is_exact() {
        let cfg = Config::default().claude_code;
        let r = report(vec![
            target("/a", "biometric", 85.0),
            target("/b", "secret", 90.0),
        ]);
        assert_eq!(
            decide(&r, false, &cfg, None),
            Decision::Deny(
                "RiskGrep: /a scored biometric 85.0 (r1). Threshold: deny at 75. Do not read this file by other means (Bash, Grep, scripts). No partial read is available for this file; ask the user."
                    .into()
            )
        );
    }

    #[test]
    fn default_secret_thresholds_ask_at_80_and_deny_at_95() {
        let cfg = Config::default().claude_code;
        let d = |score| {
            decide(
                &report(vec![target("/a", "secret", score)]),
                false,
                &cfg,
                None,
            )
        };
        assert_eq!(d(79.9), Decision::NoOpinion);
        assert_eq!(
            d(80.0),
            Decision::Ask(format!(
                "RiskGrep: /a scored secret 80.0 (r1). Threshold: ask at 80.{NP1}"
            ))
        );
        assert!(matches!(d(94.9), Decision::Ask(_)));
        assert_eq!(
            d(95.0),
            Decision::Deny(format!(
                "RiskGrep: /a scored secret 95.0 (r1). Threshold: deny at 95.{NP1}"
            ))
        );
    }

    #[test]
    fn thresholds_use_the_rounded_score() {
        let cfg = Config::default().claude_code;
        // Raw 74.96 shows as 75.0, which meets the biometric deny at 75.
        let r = report(vec![target("/a", "biometric", 74.96)]);
        assert!(matches!(decide(&r, false, &cfg, None), Decision::Deny(_)));
        let r = report(vec![target("/a", "biometric", 74.94)]);
        assert!(!matches!(decide(&r, false, &cfg, None), Decision::Deny(_)));
    }

    #[test]
    fn lists_three_then_counts_the_rest() {
        let cfg = Config::default().claude_code;
        let ts = (0..6)
            .map(|i| target(&format!("/f{i}"), "secret", 85.0 + i as f64))
            .collect();
        let Decision::Ask(text) = decide(&report(ts), false, &cfg, None) else {
            panic!("expected ask")
        };
        assert!(
            text.starts_with("RiskGrep: /f5 scored secret 90.0"),
            "{text}"
        );
        assert!(
            text.ends_with(", and 3 more. Do not read these files by other means (Bash, Grep, scripts). No partial read is available for these files; ask the user."),
            "{text}"
        );
        assert!(!text.contains("/f0"));
    }

    #[test]
    fn below_threshold_and_allowed_statuses_are_silent() {
        let cfg = Config::default().claude_code;
        let mut skipped = target("/s", "secret", 0.0);
        skipped.status = TargetStatus::Skipped {
            reason: "binary".into(),
        };
        let r = report(vec![target("/a", "secret", 79.9), skipped]);
        assert_eq!(decide(&r, true, &cfg, None), Decision::NoOpinion);
    }

    #[test]
    fn highest_severity_wins_across_items() {
        let mut cfg = Config::default().claude_code;
        cfg.on_error = Action::Deny;
        let mut bad = target("/u", "secret", 0.0);
        bad.status = TargetStatus::Unscanned {
            reason: "unreadable: PermissionDenied".into(),
        };
        let r = report(vec![target("/a", "secret", 90.0), bad]);
        assert_eq!(
            decide(&r, false, &cfg, None),
            Decision::Deny("RiskGrep: could not scan /u (unreadable: PermissionDenied)".into())
        );
    }

    #[test]
    fn many_rule_ids_are_counted() {
        let cfg = Config::default().claude_code;
        let mut t = target("/a", "secret", 90.0);
        let proto = t.evidence[0].clone();
        t.evidence = (0..8)
            .map(|i| Evidence {
                rule: format!("r{i}"),
                ..proto.clone()
            })
            .collect();
        assert_eq!(
            decide(&report(vec![t]), false, &cfg, None),
            Decision::Ask(
                format!("RiskGrep: /a scored secret 90.0 (r0, r1, r2, r3, r4, and 3 more). Threshold: ask at 80.{NP1}")
            )
        );
    }

    #[test]
    fn unscanned_and_unresolved_follow_config() {
        let mut cfg = Config::default().claude_code;
        let mut bad = target("/u", "secret", 0.0);
        bad.status = TargetStatus::Unscanned {
            reason: "unreadable: PermissionDenied".into(),
        };
        let r = report(vec![bad]);
        assert_eq!(
            decide(&r, false, &cfg, None),
            Decision::Ask("RiskGrep: could not scan /u (unreadable: PermissionDenied)".into())
        );
        cfg.on_error = Action::Allow;
        cfg.on_unresolved = Action::Deny;
        assert_eq!(
            decide(&r, true, &cfg, None),
            Decision::Deny("RiskGrep: command reads files that could not be determined".into())
        );
    }
}
