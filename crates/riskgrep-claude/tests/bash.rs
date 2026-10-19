//! Drives `bash_targets` through every case in `fixtures/bash_cases.json`.
//!
//! Each case names the files to create in a fresh temporary directory, the
//! command to analyse with that directory as the working directory, and the
//! files (relative to it) the command is expected to read.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use riskgrep_claude::bash::{bash_targets, BashTargets};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    command: String,
    cwd_files: Vec<String>,
    expect_files: Vec<String>,
    expect_unresolved: bool,
}

fn load_cases() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bash_cases.json");
    let text = std::fs::read_to_string(&path).expect("read bash_cases.json");
    serde_json::from_str(&text).expect("parse bash_cases.json")
}

fn populate(dir: &Path, files: &[String]) {
    for rel in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture directory");
        }
        std::fs::write(&path, b"").expect("create fixture file");
    }
}

/// The returned files as strings relative to the canonical `root`; anything
/// outside it is kept absolute so a failure message shows where it pointed.
fn relative_set(targets: &BashTargets, root: &Path) -> BTreeSet<String> {
    targets
        .files
        .iter()
        .map(|p| {
            let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
            match canon.strip_prefix(root) {
                Ok(rel) => rel.to_string_lossy().into_owned(),
                Err(_) => canon.to_string_lossy().into_owned(),
            }
        })
        .collect()
}

fn run_case(case: &Case) -> Result<(), String> {
    let tmp = tempfile::tempdir().expect("tempdir");
    populate(tmp.path(), &case.cwd_files);
    let root = std::fs::canonicalize(tmp.path()).expect("canonical tempdir");
    let got = bash_targets(&case.command, tmp.path());
    let got_files = relative_set(&got, &root);
    let want_files: BTreeSet<String> = case.expect_files.iter().cloned().collect();
    if got_files == want_files && got.unresolved == case.expect_unresolved {
        Ok(())
    } else {
        Err(format!(
            "{}\n    command: {:?}\n    files: got {:?}, want {:?}\n    unresolved: got {}, want {}",
            case.name, case.command, got_files, want_files, got.unresolved, case.expect_unresolved
        ))
    }
}

#[test]
fn fixture_cases() {
    let cases = load_cases();
    assert!(cases.len() >= 100, "fixture set shrank to {}", cases.len());
    let failures: Vec<String> = cases.iter().filter_map(|c| run_case(c).err()).collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn returned_paths_are_absolute() {
    let tmp = tempfile::tempdir().expect("tempdir");
    populate(tmp.path(), &["a.txt".to_string()]);
    let got = bash_targets("cat a.txt", tmp.path());
    assert_eq!(got.files.len(), 1);
    assert!(got.files[0].is_absolute());
}

#[test]
fn absolute_path_is_tested_as_given() {
    let tmp = tempfile::tempdir().expect("tempdir");
    populate(tmp.path(), &["abs.txt".to_string()]);
    let other = tempfile::tempdir().expect("second tempdir");
    let abs = std::fs::canonicalize(tmp.path().join("abs.txt")).expect("canonical");
    let command = format!("cat '{}'", abs.display());
    let got = bash_targets(&command, other.path());
    assert_eq!(got.files, vec![abs]);
    assert!(!got.unresolved);
}

#[test]
fn tilde_expands_with_home() {
    // The only test that sets HOME; no fixture case uses `~`, so nothing else
    // in this binary reads it.
    let home = tempfile::tempdir().expect("home tempdir");
    populate(home.path(), &[".netrc".to_string()]);
    std::env::set_var("HOME", home.path());
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let got = bash_targets("cat ~/.netrc", cwd.path());
    let want = std::fs::canonicalize(home.path().join(".netrc")).expect("canonical");
    assert_eq!(got.files, vec![want]);
    assert!(!got.unresolved);
}

#[test]
fn glob_walk_limit_stops_and_marks_unresolved() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for i in 0..10_001 {
        std::fs::write(tmp.path().join(format!("f{i:05}.log")), b"").expect("create file");
    }
    let got = bash_targets("cat *.log", tmp.path());
    assert!(got.unresolved);
    assert!(
        got.files.len() <= 10_000,
        "returned {} files",
        got.files.len()
    );
}

#[test]
fn deep_nesting_does_not_overflow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut command = "cat x".to_string();
    for _ in 0..200 {
        command = format!("echo $({command})");
    }
    let got = bash_targets(&command, tmp.path());
    assert!(got.unresolved);
}

#[test]
fn nesting_at_the_parse_limit_still_parses() {
    // 64 levels is the deepest nesting `bash_targets` hands to the parser;
    // this runs on a test thread's default stack.
    let tmp = tempfile::tempdir().expect("tempdir");
    populate(tmp.path(), &["x".to_string()]);
    let mixed = format!("{}cat x{}", "( { ".repeat(32), " ; } )".repeat(32));
    let got = bash_targets(&mixed, tmp.path());
    assert!(!got.unresolved, "64 nested subshells and groups fell back");
    assert_eq!(got.files.len(), 1);
    let groups = format!("{}cat x;{}", "{ ".repeat(64), " }".repeat(64));
    let got = bash_targets(&groups, tmp.path());
    assert!(!got.unresolved, "64 nested groups fell back");
    assert_eq!(got.files.len(), 1);
}

#[test]
fn garbage_input_never_panics() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for command in [
        "",
        "(((",
        "$(",
        "<<",
        "'",
        "\"",
        "`",
        "a | | b",
        "if then fi",
        "\0\u{1}",
        "{a,",
        "$'\\x",
        "cat <(",
        "case",
    ] {
        let _ = bash_targets(command, tmp.path());
    }
}

/// Median wall time of `bash_targets` over the fixture set (files created
/// beforehand, so the figure includes the filesystem checks but not setup).
/// Run with `cargo test --release -p riskgrep-claude --test bash -- --ignored --nocapture`.
#[test]
#[ignore]
fn timing_median_over_cases() {
    let cases = load_cases();
    let mut samples: Vec<Duration> = Vec::new();
    for case in &cases {
        let tmp = tempfile::tempdir().expect("tempdir");
        populate(tmp.path(), &case.cwd_files);
        let mut best = Duration::MAX;
        for _ in 0..20 {
            let start = Instant::now();
            let _ = bash_targets(&case.command, tmp.path());
            best = best.min(start.elapsed());
        }
        samples.push(best);
    }
    samples.sort();
    let median = samples[samples.len() / 2];
    println!(
        "cases: {}, median per command: {:?}, max: {:?}",
        samples.len(),
        median,
        samples[samples.len() - 1]
    );
}
