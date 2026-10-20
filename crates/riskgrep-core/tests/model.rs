use riskgrep_core::model::*;
use std::collections::BTreeMap;

fn cat(s: &str) -> Category {
    Category(s.to_string())
}

fn target(name: &str, score: f64, status: TargetStatus) -> TargetReport {
    let mut scores = BTreeMap::new();
    scores.insert(cat("secret"), score);
    TargetReport {
        target: name.to_string(),
        status,
        scores,
        evidence: vec![],
        suppressed: 0,
    }
}

#[test]
fn report_json_shape() {
    let mut t = target("a.env", 90.0, TargetStatus::Scanned);
    t.evidence.push(Evidence {
        rule: "aws_access_token".into(),
        category: cat("secret"),
        weight: 90.0,
        count: 1,
        locations: vec![Location {
            start: 4,
            end: 24,
            line_start: 1,
            line_end: 1,
        }],
        shape: vec![ShapeFacts::Tensor {
            dtype: "<f4".into(),
            shape: vec![10, 192],
            name: None,
        }],
        fingerprints: vec![[0u8; 32]],
    });
    let r = Report::from_targets("0.1.0", "bundle-1", vec![t]);
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    for k in ["riskgrep_version", "rules_bundle", "summary", "targets"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    let s = &v["summary"];
    for k in [
        "scores",
        "targets",
        "scanned",
        "partial",
        "skipped",
        "unscanned",
        "suppressed",
    ] {
        assert!(s.get(k).is_some(), "missing summary.{k}");
    }
    assert_eq!(s["scores"]["secret"], 90.0);
    let t0 = &v["targets"][0];
    assert_eq!(t0["status"], "scanned");
    assert_eq!(t0["target"], "a.env");
    let e = &t0["evidence"][0];
    for k in ["rule", "category", "weight", "count", "locations", "shape"] {
        assert!(e.get(k).is_some(), "missing evidence.{k}");
    }
    assert_eq!(e["category"], "secret");
    assert_eq!(e["locations"][0]["line_start"], 1);
    assert_eq!(e["locations"][0]["end"], 24);
    assert_eq!(
        e["shape"][0],
        serde_json::json!({"dtype": "<f4", "shape": [10, 192]})
    );
    let p = Report::from_targets(
        "0.1.0",
        "b",
        vec![target(
            "p",
            1.0,
            TargetStatus::Partial {
                not_read: "tail".into(),
            },
        )],
    );
    let pv = serde_json::to_value(&p).unwrap();
    assert_eq!(pv["targets"][0]["status"], "partial");
    assert_eq!(pv["targets"][0]["not_read"], "tail");
}

#[test]
fn status_variants_serialize_tagged() {
    let p = serde_json::to_value(TargetStatus::Partial {
        not_read: "middle".into(),
    })
    .unwrap();
    assert_eq!(p["status"], "partial");
    assert_eq!(p["not_read"], "middle");
    let s = serde_json::to_value(TargetStatus::Skipped {
        reason: "binary".into(),
    })
    .unwrap();
    assert_eq!(s["status"], "skipped");
    assert_eq!(s["reason"], "binary");
    let u = serde_json::to_value(TargetStatus::Unscanned {
        reason: "limit".into(),
    })
    .unwrap();
    assert_eq!(u["status"], "unscanned");
}

#[test]
fn summary_takes_max() {
    let r = Report::from_targets(
        "0.1.0",
        "b",
        vec![
            target("a", 40.0, TargetStatus::Scanned),
            target(
                "b",
                95.0,
                TargetStatus::Partial {
                    not_read: "x".into(),
                },
            ),
            target("c", 10.0, TargetStatus::Skipped { reason: "r".into() }),
            target("d", 0.0, TargetStatus::Unscanned { reason: "r".into() }),
        ],
    );
    assert_eq!(r.summary.scores[&cat("secret")], 95.0);
    assert_eq!(r.summary.targets, 4);
    assert_eq!(r.summary.scanned, 1);
    assert_eq!(r.summary.partial, 1);
    assert_eq!(r.summary.skipped, 1);
    assert_eq!(r.summary.unscanned, 1);
}

#[test]
fn summary_sums_suppressed() {
    let mut a = target("a", 1.0, TargetStatus::Scanned);
    a.suppressed = 2;
    let mut b = target("b", 1.0, TargetStatus::Scanned);
    b.suppressed = 3;
    let r = Report::from_targets("0.1.0", "b", vec![a, b]);
    assert_eq!(r.summary.suppressed, 5);
}

#[test]
fn scores_rounded_in_json() {
    let r = Report::from_targets(
        "0.1.0",
        "b",
        vec![
            target("a", 72.46, TargetStatus::Scanned),
            target("b", 72.44, TargetStatus::Scanned),
        ],
    );
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["targets"][0]["scores"]["secret"], 72.5);
    assert_eq!(v["targets"][1]["scores"]["secret"], 72.4);
    assert_eq!(v["summary"]["scores"]["secret"], 72.5);
    assert_eq!(round1(72.46), 72.5);
    assert_eq!(round1(-0.25), -0.3);
}

#[test]
fn fingerprints_not_serialized() {
    let e = Evidence {
        rule: "r".into(),
        category: cat("secret"),
        weight: 1.0,
        count: 1,
        locations: vec![],
        shape: vec![],
        fingerprints: vec![[7u8; 32]],
    };
    let s = serde_json::to_string(&e).unwrap();
    assert!(!s.contains("fingerprints"));
}

#[test]
fn tensor_name_is_never_serialized() {
    let f = ShapeFacts::Tensor {
        dtype: "F32".into(),
        shape: vec![1, 192],
        name: Some("speaker_embedding".into()),
    };
    let json = serde_json::to_string(&f).unwrap();
    assert!(
        !json.contains("speaker_embedding") && !json.contains("name"),
        "{json}"
    );
    let back: ShapeFacts = serde_json::from_str(&json).unwrap();
    assert_eq!(
        back,
        ShapeFacts::Tensor {
            dtype: "F32".into(),
            shape: vec![1, 192],
            name: None
        }
    );
}
