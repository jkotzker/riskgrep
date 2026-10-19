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
