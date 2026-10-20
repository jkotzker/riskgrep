//! The hook decision: a pure function of the scan report and the config.

use riskgrep_core::config::{Action, ClaudeCodeConfig};
use riskgrep_core::model::round1;
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
            let (sev, at) = if let Some(d) = th.deny.filter(|d| score >= *d) {
                (Sev::Deny, d)
            } else if let Some(a) = th.ask.filter(|a| score >= *a) {
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
            rules.truncate(RULES_NAMED);
            let level = if sev == Sev::Deny { "deny" } else { "ask" };
            items.push(Item {
                sev,
                score,
                text: format!(
                    "RiskGrep: {} scored {} {:.1} ({}). Threshold: {level} at {}.",
                    t.target,
                    cat.0,
                    score,
                    rules.join(", "),
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
            target("/b", "secret", 95.0),
        ]);
        assert_eq!(
            decide(&r, false, &cfg),
            Decision::Deny(
                "RiskGrep: /a scored biometric 85.0 (r1). Threshold: deny at 75.".into()
            )
        );
    }

    #[test]
    fn lists_three_then_counts_the_rest() {
        let cfg = Config::default().claude_code;
        let ts = (0..6)
            .map(|i| target(&format!("/f{i}"), "secret", 90.0 + i as f64))
            .collect();
        let Decision::Ask(text) = decide(&report(ts), false, &cfg) else {
            panic!("expected ask")
        };
        assert!(
            text.starts_with("RiskGrep: /f5 scored secret 95.0"),
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
        let r = report(vec![target("/a", "secret", 89.9), skipped]);
        assert_eq!(decide(&r, true, &cfg), Decision::NoOpinion);
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
