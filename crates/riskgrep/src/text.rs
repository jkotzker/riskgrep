//! Text output: one line per target with findings, then a summary line.
//! Reports carry no matched content, so neither does this output.

use riskgrep_core::model::round1;
use riskgrep_core::{Evidence, Report, TargetReport, TargetStatus};
use std::fmt::Write;

/// At most this many line numbers are listed per rule.
const MAX_LINES: usize = 5;

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    for t in &report.targets {
        if let Some(line) = target_line(t) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out.push_str(&summary_line(report));
    out.push('\n');
    out
}

fn target_line(t: &TargetReport) -> Option<String> {
    let scores: Vec<String> = t
        .scores
        .iter()
        .filter(|(_, s)| **s > 0.0)
        .map(|(c, s)| format!("{} {:.1}", c.0, round1(*s)))
        .collect();
    match &t.status {
        TargetStatus::Unscanned { reason } => Some(format!("{}  unscanned: {reason}", t.target)),
        _ if scores.is_empty() => match &t.status {
            TargetStatus::Partial { not_read } => {
                Some(format!("{}  partial: {not_read}", t.target))
            }
            _ => None,
        },
        status => {
            let evidence: Vec<String> = t.evidence.iter().map(evidence_text).collect();
            let mut line = format!(
                "{}  {}  [{}]",
                t.target,
                scores.join("  "),
                evidence.join("; ")
            );
            if let TargetStatus::Partial { not_read } = status {
                let _ = write!(line, "  (partial: {not_read})");
            }
            Some(line)
        }
    }
}

fn evidence_text(e: &Evidence) -> String {
    let mut s = format!("{} ×{}", e.rule, e.count);
    let mut lines: Vec<(u32, u32)> = e
        .locations
        .iter()
        .map(|l| (l.line_start, l.line_end))
        .collect();
    lines.sort_unstable();
    lines.dedup();
    // Line 0: a finding in the tail sample of a partly read file, whose
    // line is not known.
    let unknown = lines.iter().any(|&(a, b)| a == 0 || b == 0);
    lines.retain(|&(a, b)| a != 0 && b != 0);
    if !lines.is_empty() {
        let shown: Vec<String> = lines
            .iter()
            .take(MAX_LINES)
            .map(|&(a, b)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}-{b}")
                }
            })
            .collect();
        let more = if lines.len() > MAX_LINES { ",…" } else { "" };
        let _ = write!(s, ", lines {}{more}", shown.join(","));
    }
    if unknown {
        s.push_str(", line unknown");
    }
    s
}

fn summary_line(report: &Report) -> String {
    let s = &report.summary;
    let mut line = format!(
        "{} targets: {} scanned, {} partial, {} skipped, {} unscanned",
        s.targets, s.scanned, s.partial, s.skipped, s.unscanned
    );
    if !s.scores.is_empty() {
        let max: Vec<String> = s
            .scores
            .iter()
            .map(|(c, v)| format!("{} {:.1}", c.0, round1(*v)))
            .collect();
        let _ = write!(line, "; max {}", max.join(", "));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::{Category, Location};
    use std::collections::BTreeMap;

    fn loc(a: u32, b: u32) -> Location {
        Location {
            start: 0,
            end: 1,
            line_start: a,
            line_end: b,
        }
    }

    fn ev(rule: &str, locs: Vec<Location>) -> Evidence {
        Evidence {
            rule: rule.into(),
            category: Category("secret".into()),
            weight: 95.0,
            count: locs.len().max(1) as u32,
            locations: locs,
            shape: vec![],
            fingerprints: vec![],
        }
    }

    fn target(
        name: &str,
        status: TargetStatus,
        score: f64,
        evidence: Vec<Evidence>,
    ) -> TargetReport {
        TargetReport {
            target: name.into(),
            status,
            scores: BTreeMap::from([(Category("secret".into()), score)]),
            evidence,
            suppressed: 0,
        }
    }

    #[test]
    fn evidence_lines() {
        let e = ev("r", vec![loc(7, 7), loc(3, 5), loc(7, 7)]);
        assert_eq!(evidence_text(&e), "r ×3, lines 3-5,7");
        assert_eq!(evidence_text(&ev("path_rule", vec![])), "path_rule ×1");
        let many = ev("m", (1..=8).map(|n| loc(n, n)).collect());
        assert_eq!(evidence_text(&many), "m ×8, lines 1,2,3,4,5,…");
    }

    #[test]
    fn line_0_is_unknown() {
        let tail = ev("t", vec![loc(0, 0)]);
        assert_eq!(evidence_text(&tail), "t ×1, line unknown");
        let mixed = ev("m", vec![loc(4, 4), loc(0, 0)]);
        assert_eq!(evidence_text(&mixed), "m ×2, lines 4, line unknown");
    }

    #[test]
    fn lines_and_summary() {
        let r = Report::from_targets(
            "0",
            "b",
            vec![
                target(
                    "a",
                    TargetStatus::Scanned,
                    94.96,
                    vec![ev("x", vec![loc(2, 2)])],
                ),
                target("b", TargetStatus::Scanned, 0.0, vec![]),
                target(
                    "c",
                    TargetStatus::Unscanned {
                        reason: "nope".into(),
                    },
                    0.0,
                    vec![],
                ),
                target(
                    "d",
                    TargetStatus::Skipped {
                        reason: "bin".into(),
                    },
                    0.0,
                    vec![],
                ),
            ],
        );
        assert_eq!(
            render(&r),
            "a  secret 95.0  [x ×1, lines 2]\n\
             c  unscanned: nope\n\
             4 targets: 2 scanned, 0 partial, 1 skipped, 1 unscanned; max secret 95.0\n"
        );
    }

    #[test]
    fn partial_targets() {
        let p = TargetStatus::Partial {
            not_read: "tail".into(),
        };
        let r = Report::from_targets(
            "0",
            "b",
            vec![
                target("a", p.clone(), 50.0, vec![ev("x", vec![loc(1, 1)])]),
                target("b", p, 0.0, vec![]),
            ],
        );
        assert_eq!(
            render(&r),
            "a  secret 50.0  [x ×1, lines 1]  (partial: tail)\n\
             b  partial: tail\n\
             2 targets: 0 scanned, 2 partial, 0 skipped, 0 unscanned; max secret 50.0\n"
        );
    }

    #[test]
    fn empty_report() {
        let r = Report::from_targets("0", "b", vec![]);
        assert_eq!(
            render(&r),
            "0 targets: 0 scanned, 0 partial, 0 skipped, 0 unscanned\n"
        );
    }
}
