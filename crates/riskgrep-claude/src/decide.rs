//! The hook decision: a pure function of the scan report and the config.

use riskgrep_core::config::{Action, ClaudeCodeConfig};
use riskgrep_core::model::{meets_threshold, round1};
use riskgrep_core::{Report, TargetStatus};

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
}

/// How many reasons are listed before `and N more`.
const LISTED: usize = 3;
/// Rule ids named per finding.
const RULES_NAMED: usize = 5;

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

pub fn decide(report: &Report, unresolved: bool, cfg: &ClaudeCodeConfig) -> Decision {
    let mut items: Vec<Item> = Vec::new();
    for t in &report.targets {
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
            });
        }
        for (cat, &raw) in &t.scores {
            let Some(th) = cfg.thresholds.get(cat) else {
                continue;
            };
            let score = round1(raw);
            let (sev, at) = if let Some(d) = th.deny.filter(|d| meets_threshold(raw, *d)) {
                (Sev::Deny, d)
            } else if let Some(a) = th.ask.filter(|a| meets_threshold(raw, *a)) {
                (Sev::Ask, a)
            } else {
                continue;
            };
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
            let level = if sev == Sev::Deny { "deny" } else { "ask" };
            items.push(Item {
                sev,
                score,
                text: format!(
                    "RiskGrep: {} scored {} {:.1} ({}). Threshold: {level} at {}.",
                    t.target,
                    cat.0,
                    score,
                    named,
                    num(at)
                ),
            });
        }
    }
    if unresolved {
        if let Some(sev) = severity(cfg.on_unresolved) {
            items.push(Item {
                sev,
                score: -1.0,
                text: "RiskGrep: command reads files that could not be determined".to_string(),
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
    match top {
        Sev::Ask => Decision::Ask(reason),
        Sev::Deny => Decision::Deny(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::config::Config;
    use riskgrep_core::{Category, Evidence, TargetReport};
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
            }],
            suppressed: 0,
        }
    }

    fn report(ts: Vec<TargetReport>) -> Report {
        Report::from_targets("0", "b", ts)
    }

    #[test]
    fn deny_beats_ask_and_text_is_exact() {
        let cfg = Config::default().claude_code;
        let r = report(vec![
            target("/a", "biometric", 85.0),
            target("/b", "secret", 90.0),
        ]);
        assert_eq!(
            decide(&r, false, &cfg),
            Decision::Deny(
                "RiskGrep: /a scored biometric 85.0 (r1). Threshold: deny at 75.".into()
            )
        );
    }

    #[test]
    fn default_secret_thresholds_ask_at_80_and_deny_at_95() {
        let cfg = Config::default().claude_code;
        let d = |score| decide(&report(vec![target("/a", "secret", score)]), false, &cfg);
        assert_eq!(d(79.9), Decision::NoOpinion);
        assert_eq!(
            d(80.0),
            Decision::Ask("RiskGrep: /a scored secret 80.0 (r1). Threshold: ask at 80.".into())
        );
        assert!(matches!(d(94.9), Decision::Ask(_)));
        assert_eq!(
            d(95.0),
            Decision::Deny("RiskGrep: /a scored secret 95.0 (r1). Threshold: deny at 95.".into())
        );
    }

    #[test]
    fn thresholds_use_the_rounded_score() {
        let cfg = Config::default().claude_code;
        // Raw 74.96 shows as 75.0, which meets the biometric deny at 75.
        let r = report(vec![target("/a", "biometric", 74.96)]);
        assert!(matches!(decide(&r, false, &cfg), Decision::Deny(_)));
        let r = report(vec![target("/a", "biometric", 74.94)]);
        assert!(!matches!(decide(&r, false, &cfg), Decision::Deny(_)));
    }

    #[test]
    fn lists_three_then_counts_the_rest() {
        let cfg = Config::default().claude_code;
        let ts = (0..6)
            .map(|i| target(&format!("/f{i}"), "secret", 85.0 + i as f64))
            .collect();
        let Decision::Ask(text) = decide(&report(ts), false, &cfg) else {
            panic!("expected ask")
        };
        assert!(
            text.starts_with("RiskGrep: /f5 scored secret 90.0"),
            "{text}"
        );
        assert!(text.ends_with(", and 3 more."), "{text}");
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
        assert_eq!(decide(&r, true, &cfg), Decision::NoOpinion);
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
            decide(&r, false, &cfg),
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
            decide(&report(vec![t]), false, &cfg),
            Decision::Ask(
                "RiskGrep: /a scored secret 90.0 (r0, r1, r2, r3, r4, and 3 more). Threshold: ask at 80."
                    .into()
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
            decide(&r, false, &cfg),
            Decision::Ask("RiskGrep: could not scan /u (unreadable: PermissionDenied)".into())
        );
        cfg.on_error = Action::Allow;
        cfg.on_unresolved = Action::Deny;
        assert_eq!(
            decide(&r, true, &cfg),
            Decision::Deny("RiskGrep: command reads files that could not be determined".into())
        );
    }
}
