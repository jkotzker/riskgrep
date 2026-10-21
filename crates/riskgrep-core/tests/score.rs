use riskgrep_core::model::Category;
use riskgrep_core::score::*;

fn c(rule: &str, w: f64, count: u32) -> Contribution {
    Contribution {
        rule: rule.into(),
        category: Category("secret".into()),
        weight: w,
        count,
        tiers: None,
        family: None,
        family_cap: None,
    }
}

fn get(v: &[Contribution]) -> Option<f64> {
    score(v).get(&Category("secret".into())).copied()
}

fn near(a: f64, b: f64) {
    assert!((a - b).abs() < 1e-9, "{a} != {b}");
}

#[test]
fn single_90() {
    near(get(&[c("a", 90.0, 1)]).unwrap(), 90.0);
}

#[test]
fn two_50s() {
    near(get(&[c("a", 50.0, 1), c("b", 50.0, 1)]).unwrap(), 75.0);
}

#[test]
fn thirty_and_forty() {
    near(get(&[c("a", 30.0, 1), c("b", 40.0, 1)]).unwrap(), 58.0);
}

#[test]
fn empty() {
    assert!(get(&[]).is_none());
}

#[test]
fn repeat_without_tiers_counts_once() {
    near(get(&[c("a", 50.0, 3)]).unwrap(), 50.0);
}

#[test]
fn tiers() {
    let t: Tiers = "1:20,2:50,100:90".parse().unwrap();
    near(t.weight_for(0), 0.0);
    near(t.weight_for(1), 20.0);
    near(t.weight_for(2), 50.0);
    near(t.weight_for(99), 50.0);
    near(t.weight_for(100), 90.0);
    let mut x = c("a", 0.0, 2);
    x.tiers = Some(t);
    near(get(&[x]).unwrap(), 50.0);
}

#[test]
fn family_cap() {
    let mut a = c("a", 50.0, 1);
    let mut b = c("b", 50.0, 1);
    for x in [&mut a, &mut b] {
        x.family = Some("generic".into());
        x.family_cap = Some(60.0);
    }
    near(get(&[a, b, c("z", 30.0, 1)]).unwrap(), 72.0);
}

#[test]
fn negative_dampens() {
    near(get(&[c("a", 90.0, 1), c("n", -50.0, 1)]).unwrap(), 45.0);
}

#[test]
fn bad_tiers_rejected() {
    assert!("2:50,1:20".parse::<Tiers>().is_err());
    assert!("1:120".parse::<Tiers>().is_err());
}

#[test]
fn categories_are_independent() {
    let mut other = c("o", 80.0, 1);
    other.category = Category("pii".into());
    let m = score(&[c("a", 10.0, 1), other]);
    near(m[&Category("secret".into())], 10.0);
    near(m[&Category("pii".into())], 80.0);
}

#[test]
fn tiers_round_trip_through_text_and_json() {
    let t: Tiers = "1:20,2:50.5,100:-90".parse().unwrap();
    assert_eq!(t.to_string().parse::<Tiers>().unwrap(), t);
    let json = serde_json::to_string(&t).unwrap();
    assert_eq!(json, "\"1:20,2:50.5,100:-90\"");
    assert_eq!(serde_json::from_str::<Tiers>(&json).unwrap(), t);
    assert!(serde_json::from_str::<Tiers>("\"2:1,1:1\"").is_err());
}

#[test]
fn score_target_uses_meta_weights_and_tiers() {
    use riskgrep_core::meta::RuleMeta;
    use riskgrep_core::model::Evidence;
    use std::collections::HashMap;
    let ev = |rule: &str, count: u32| Evidence {
        rule: rule.into(),
        category: Category("secret".into()),
        weight: 99.0,
        count,
        locations: vec![],
        shape: vec![],
        fingerprints: vec![],
        line_complete: false,
    };
    let m = |w: f64, tiers: Option<&str>| RuleMeta {
        category: Category("secret".into()),
        weight: w,
        tiers: tiers.map(|t| t.parse().unwrap()),
        family: None,
        family_cap: None,
        post: vec![],
        line_complete: false,
    };
    let meta = HashMap::from([
        ("ns:a".to_string(), m(50.0, None)),
        ("ns:b".to_string(), m(0.0, Some("1:10,3:20"))),
    ]);
    let s = score_target(&[ev("a", 1), ev("b", 3)], &meta);
    let got = s[&Category("secret".into())];
    assert!((got - 60.0).abs() < 1e-9, "{got}");
    // Unknown rule: its own weight.
    let s = score_target(&[ev("zzz", 1)], &meta);
    assert!((s[&Category("secret".into())] - 99.0).abs() < 1e-9);
}
