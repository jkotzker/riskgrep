//! The path the rules see, and gitleaks' global path allowlist: which form
//! `path` takes (relative to the repository root, else absolute), the report
//! fields that say the allowlist applied, and the setting that turns it off.
//! Secrets are generated at run time and never printed.

use riskgrep_core::config::Config;
use riskgrep_core::model::{Category, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::synth;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn shared_cache() -> PathBuf {
    static D: OnceLock<TempDir> = OnceLock::new();
    D.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let mut g = RiskGrep::with_cache_dir(Config::default(), None, Some(d.path().into()))
            .expect("scanner builds");
        g.scan_bytes("warm", b"nothing here\n");
        d
    })
    .path()
    .to_path_buf()
}

fn scanner_with(cfg: Config) -> RiskGrep {
    RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap()
}

fn scanner() -> RiskGrep {
    scanner_with(Config::default())
}

fn allowlist_off() -> Config {
    Config {
        path_allowlist: false,
        ..Config::default()
    }
}

fn secret(t: &TargetReport) -> f64 {
    t.scores[&Category("secret".into())]
}

/// `api_key = "…"`: found by the converted `generic_api_key` (80), which
/// skips allowlisted paths.
fn api_key_line(seed: u64) -> String {
    format!(
        "{}\n",
        synth::fake_secret("generic_api_key_assignment", seed)
    )
}

/// `<ApiKey>…</ApiKey>`: found by `xml_credential_element` (80), which does
/// not use the allowlist.
fn xml_key(seed: u64) -> String {
    let line = synth::fake_secret("generic_api_key_assignment", seed);
    let value = line.split('"').nth(1).unwrap();
    format!("<Config>\n  <ApiKey>{value}</ApiKey>\n</Config>\n")
}

/// Set a file's mtime into the past so a fresh stat entry is not racy.
fn age(p: &Path) {
    let f = File::options().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
}

/// Write `rel` under `dir`, creating its parents.
fn put(dir: &Path, rel: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, bytes).unwrap();
    age(&p);
    p
}

/// A directory holding a `.git` directory: a repository root.
fn repo_at(dir: &Path) {
    fs::create_dir_all(dir.join(".git")).unwrap();
}

fn only(r: &Report) -> &TargetReport {
    assert_eq!(r.targets.len(), 1);
    &r.targets[0]
}

fn scan(g: &mut RiskGrep, p: &Path) -> TargetReport {
    only(&g.scan_paths(&[p.to_path_buf()])).clone()
}

fn json(t: &TargetReport) -> serde_json::Value {
    serde_json::to_value(t).unwrap()
}

// ---- The path the rules see ------------------------------------------------

#[test]
fn inside_a_repository_the_rules_see_the_path_from_its_root() {
    // The repository sits in a directory whose name the allowlist lists, so
    // a rule seeing the absolute path would skip the file; the path from
    // the repository root (`settings.ini`) is not allowlisted.
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("node_modules/app");
    repo_at(&root);
    let p = put(&root, "settings.ini", api_key_line(1));
    let t = scan(&mut scanner(), &p);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert!(secret(&t) >= 80.0, "{:?}", t.scores);
    assert!(!t.path_allowlisted);

    // Below the root, the allowlisted directory is part of the path.
    let q = put(&root, "node_modules/pkg/settings.ini", api_key_line(2));
    let t = scan(&mut scanner(), &q);
    assert_eq!(secret(&t), 0.0);
    assert!(t.path_allowlisted);
}

#[test]
fn outside_any_repository_the_rules_see_the_absolute_path() {
    let d = tempfile::tempdir().unwrap();
    let p = put(d.path(), "node_modules/pkg/settings.ini", api_key_line(3));
    let t = scan(&mut scanner(), &p);
    assert_eq!(secret(&t), 0.0);
    assert!(t.path_allowlisted);

    let q = put(d.path(), "plain/settings.ini", api_key_line(4));
    let t = scan(&mut scanner(), &q);
    assert!(secret(&t) >= 80.0, "{:?}", t.scores);
    assert!(!t.path_allowlisted);
}

#[test]
fn a_git_file_marks_a_repository_root_too() {
    // As for the configuration's repository: a `.git` file (a worktree or a
    // submodule) marks a root. The ownership check is shared with that
    // search (`repo::find_repo_root`) and tested there.
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("node_modules/app");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join(".git"), "gitdir: elsewhere\n").unwrap();
    let p = put(&root, "settings.ini", api_key_line(5));
    let t = scan(&mut scanner(), &p);
    assert!(secret(&t) >= 80.0, "{:?}", t.scores);
}

// ---- The report says when the allowlist applied ----------------------------

#[test]
fn the_field_is_present_only_when_the_allowlist_applied() {
    let d = tempfile::tempdir().unwrap();
    repo_at(d.path());
    let skipped = put(d.path(), "settings.png", api_key_line(6));
    let read = put(d.path(), "settings.txt", api_key_line(6));

    let t = scan(&mut scanner(), &skipped);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(secret(&t), 0.0);
    assert!(t.path_allowlisted);
    assert_eq!(json(&t)["path_allowlisted"], serde_json::json!(true));

    let t = scan(&mut scanner(), &read);
    assert!(secret(&t) >= 80.0);
    assert!(!t.path_allowlisted);
    assert!(json(&t).get("path_allowlisted").is_none());

    // A rule that does not use the allowlist still applies on such a path,
    // and the field still says the converted rules did not.
    let svg = put(d.path(), "config.svg", xml_key(7));
    let t = scan(&mut scanner(), &svg);
    assert!(secret(&t) >= 80.0, "{:?}", t.scores);
    assert!(t.path_allowlisted);
}

#[test]
fn a_cached_result_keeps_the_field() {
    let d = tempfile::tempdir().unwrap();
    repo_at(d.path());
    let p = put(d.path(), "yarn.lock", api_key_line(8));
    let mut g = scanner();
    let first = scan(&mut g, &p);
    let second = scan(&mut g, &p);
    assert!(first.path_allowlisted);
    assert_eq!(first, second);
}

#[test]
fn zip_members_report_the_allowlist_without_naming_clean_members() {
    let d = tempfile::tempdir().unwrap();
    repo_at(d.path());
    let z = synth::zip(&[
        ("notes.txt", api_key_line(9).into_bytes()),
        ("notes.png", api_key_line(10).into_bytes()),
        ("config.svg", xml_key(11).into_bytes()),
        ("node_modules/x/settings.ini", api_key_line(12).into_bytes()),
    ]);
    let p = put(d.path(), "notes.zip", z);
    for g in [&mut scanner(), &mut scanner()] {
        // The second scan is answered from the cache.
        let t = scan(g, &p);
        assert_eq!(t.status, TargetStatus::Scanned);
        assert!(t.path_allowlisted, "at least one member was allowlisted");
        let c = t.container.as_ref().expect("container");
        assert_eq!(c.path_allowlisted, 3, "{c:?}");
        // `notes.txt` and `config.svg` have evidence and are listed; the
        // allowlisted members without evidence are not.
        let listed: Vec<(&str, bool)> = c
            .listed
            .iter()
            .map(|m| (m.path.as_str(), m.path_allowlisted))
            .collect();
        assert_eq!(listed, vec![("config.svg", true), ("notes.txt", false)]);
        let j = json(&t);
        assert_eq!(j["container"]["path_allowlisted"], serde_json::json!(3));
        assert!(j["container"]["listed"][1]
            .get("path_allowlisted")
            .is_none());
    }
}

// ---- The setting -----------------------------------------------------------

#[test]
fn with_the_setting_off_the_converted_rules_read_allowlisted_paths() {
    let d = tempfile::tempdir().unwrap();
    repo_at(d.path());
    let p = put(d.path(), "node_modules/pkg/settings.ini", api_key_line(13));
    let z = put(
        d.path(),
        "notes.zip",
        synth::zip(&[("notes.png", api_key_line(14).into_bytes())]),
    );

    // On, off, and on again through one cache: the setting is part of the
    // cache key, so no result is answered for the other setting.
    for (cfg, on) in [
        (Config::default(), true),
        (allowlist_off(), false),
        (Config::default(), true),
    ] {
        let mut g = scanner_with(cfg);
        let t = scan(&mut g, &p);
        assert_eq!(t.path_allowlisted, on);
        assert_eq!(secret(&t) >= 80.0, !on, "{:?}", t.scores);
        let t = scan(&mut g, &z);
        assert_eq!(t.path_allowlisted, on);
        assert_eq!(
            t.container.as_ref().unwrap().path_allowlisted,
            u64::from(on)
        );
        assert_eq!(secret(&t) >= 80.0, !on, "{:?}", t.scores);
    }
}

#[test]
fn names_follow_the_same_path_rule() {
    // `scan_names` scores names with the path rules alone; a name is
    // resolved against the working directory and then formed like a file's.
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("node_modules/app");
    repo_at(&root);
    put(&root, ".env", "");
    let abs = fs::canonicalize(root.join(".env")).unwrap();
    let r = scanner().scan_names(&[abs.display().to_string()]);
    let t = only(&r);
    assert!(secret(t) >= 80.0, "{:?}", t.scores);
    assert!(!t.path_allowlisted);
}
