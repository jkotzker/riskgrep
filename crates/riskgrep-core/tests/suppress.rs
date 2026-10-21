use riskgrep_core::model::{Category, Evidence, Location, TargetReport, TargetStatus};
use riskgrep_core::suppress::{apply, fingerprint, Baseline, IgnoreRules, IgnoreSpec, RuleIgnore};
use riskgrep_core::synth::fake_secret;
use std::collections::BTreeMap;

fn loc(i: u64) -> Location {
    Location {
        start: i,
        end: i + 10,
        line_start: i as u32,
        line_end: i as u32,
    }
}

fn ev(rule: &str, secrets: &[(&str, u64)]) -> Evidence {
    Evidence {
        rule: rule.into(),
        category: Category("secret".into()),
        weight: 1.0,
        count: secrets.len() as u32,
        locations: secrets.iter().map(|(_, at)| loc(*at)).collect(),
        shape: vec![],
        fingerprints: secrets
            .iter()
            .map(|(s, _)| *blake3::hash(s.as_bytes()).as_bytes())
            .collect(),
        line_complete: false,
    }
}

fn target(path: &str, evidence: Vec<Evidence>) -> TargetReport {
    TargetReport {
        target: path.into(),
        status: TargetStatus::Scanned,
        scores: BTreeMap::new(),
        evidence,
        suppressed: 0,
        text: true,
    }
}

fn ident(s: &str) -> String {
    s.to_string()
}

fn rules(paths: &[&str], scoped: &[(&str, &[&str])]) -> IgnoreRules {
    IgnoreRules::new(IgnoreSpec {
        paths: paths.iter().map(|s| s.to_string()).collect(),
        rules: scoped
            .iter()
            .map(|(p, r)| RuleIgnore {
                path: p.to_string(),
                rules: r.iter().map(|s| s.to_string()).collect(),
            })
            .collect(),
    })
    .unwrap()
}

#[test]
fn glob_ignore() {
    let r = rules(&["vendor/**", "*.lock"], &[]);
    assert!(r.ignores("vendor/a/b.rs", "any_rule"));
    assert!(r.ignores("Cargo.lock", "any_rule"));
    assert!(!r.ignores("src/main.rs", "any_rule"));
}

#[test]
fn rule_scoped_ignore() {
    let r = rules(&[], &[("docs/**", &["generic_api_key"])]);
    assert!(r.ignores("docs/guide/a.md", "generic_api_key"));
    assert!(!r.ignores("docs/guide/a.md", "aws_access_token"));
    assert!(!r.ignores("src/a.rs", "generic_api_key"));

    let mut t = [target(
        "docs/a.md",
        vec![
            ev(
                "generic_api_key",
                &[(&fake_secret("generic_api_key_assignment", 1), 3)],
            ),
            ev(
                "aws_access_token",
                &[(&fake_secret("aws_access_key", 2), 9)],
            ),
        ],
    )];
    apply(&mut t, &r, None, ident);
    assert_eq!(t[0].suppressed, 1);
    assert_eq!(t[0].evidence.len(), 1);
    assert_eq!(t[0].evidence[0].rule, "aws_access_token");
}

#[test]
fn baseline_suppresses_known_not_new() {
    let a = fake_secret("aws_access_key", 10);
    let b = fake_secret("aws_access_key", 11);
    let scan_a = [target("src/a.rs", vec![ev("aws_access_token", &[(&a, 5)])])];
    let base = Baseline::create(&scan_a, ident).unwrap();

    let mut scan_b = [target(
        "src/a.rs",
        vec![ev("aws_access_token", &[(&a, 5), (&b, 20)])],
    )];
    apply(&mut scan_b, &IgnoreRules::default(), Some(&base), ident);
    assert_eq!(scan_b[0].suppressed, 1);
    let e = &scan_b[0].evidence;
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].count, 1);
    assert_eq!(e[0].locations, vec![loc(20)]);
    assert_eq!(
        e[0].fingerprints,
        vec![*blake3::hash(b.as_bytes()).as_bytes()]
    );
}

#[test]
fn baseline_drops_fully_known_and_structural_evidence() {
    let a = fake_secret("github_pat", 4);
    let mut structural = ev("npy_embedding", &[]);
    structural.count = 1;
    let scan = [target(
        "m/e.npy",
        vec![structural.clone(), ev("github_pat", &[(&a, 1)])],
    )];
    let base = Baseline::create(&scan, ident).unwrap();
    let mut again = [target(
        "m/e.npy",
        vec![structural, ev("github_pat", &[(&a, 1)])],
    )];
    apply(&mut again, &IgnoreRules::default(), Some(&base), ident);
    assert!(again[0].evidence.is_empty());
    assert_eq!(again[0].suppressed, 2);
}

#[test]
fn location_free_evidence_is_keyed_by_its_content_digest() {
    let structural = |content: &[u8]| {
        let mut e = ev("path_biometric_name", &[]);
        e.count = 1;
        e.fingerprints = vec![*blake3::hash(content).as_bytes()];
        e
    };
    let base = Baseline::create(&[target("speaker.txt", vec![structural(b"one")])], ident).unwrap();
    let mut same = [target("speaker.txt", vec![structural(b"one")])];
    apply(&mut same, &IgnoreRules::default(), Some(&base), ident);
    assert!(same[0].evidence.is_empty());
    let mut changed = [target("speaker.txt", vec![structural(b"two")])];
    apply(&mut changed, &IgnoreRules::default(), Some(&base), ident);
    assert_eq!(changed[0].evidence.len(), 1);
    assert_eq!(changed[0].suppressed, 0);
}

#[test]
fn fingerprint_stable_across_line_moves() {
    let s = fake_secret("github_pat", 7);
    let digest = *blake3::hash(s.as_bytes()).as_bytes();
    let key = [3u8; 32];
    let f = fingerprint(&key, "github_pat", "src/a.rs", Some(&digest));
    // The same secret ten lines further down hashes identically.
    let moved = ev("github_pat", &[(&s, 15)]);
    assert_eq!(
        f,
        fingerprint(&key, "github_pat", "src/a.rs", Some(&moved.fingerprints[0]))
    );
    assert_ne!(
        f,
        fingerprint(&key, "github_pat", "src/b.rs", Some(&digest))
    );
    assert_ne!(f, fingerprint(&key, "other", "src/a.rs", Some(&digest)));
    assert_ne!(
        f,
        fingerprint(&[4u8; 32], "github_pat", "src/a.rs", Some(&digest))
    );
    assert_ne!(f, fingerprint(&key, "github_pat", "src/a.rs", None));
}

#[test]
fn baseline_file_has_no_values() {
    let s = fake_secret("anthropic_key", 9);
    let scan = [target("k.txt", vec![ev("anthropic_key", &[(&s, 1)])])];
    let base = Baseline::create(&scan, ident).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".riskgrep-baseline.json");
    base.save(&path).unwrap();
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.windows(s.len()).any(|w| w == s.as_bytes()));
    let text = String::from_utf8(raw).unwrap();
    assert!(text.contains("\"version\": 1"));
    let back = Baseline::load(&path).unwrap();
    assert_eq!(back, base);
}

#[test]
fn load_rejects_bad_files() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("b.json");
    std::fs::write(&p, r#"{"version":2,"key":"00","fingerprints":[]}"#).unwrap();
    assert!(Baseline::load(&p).is_err());
    std::fs::write(&p, r#"{"version":1,"key":"zz","fingerprints":[]}"#).unwrap();
    assert!(Baseline::load(&p).is_err());
    assert!(Baseline::load(&dir.path().join("missing.json")).is_err());
}
