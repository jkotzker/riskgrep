//! The `RiskGrep` facade. Secrets are generated at run time and never
//! printed; assertions use statuses, scores, rule ids, and counts.

use riskgrep_core::config::{Config, Mode};
use riskgrep_core::model::{Category, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::{RiskGrep, AFTER_READ};
use riskgrep_core::synth;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tempfile::TempDir;

/// One cache directory for the whole test binary, warmed once, so each test
/// loads the compiled bundle instead of compiling it.
fn shared_cache() -> PathBuf {
    static D: OnceLock<TempDir> = OnceLock::new();
    D.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let mut g = RiskGrep::with_cache_dir(Config::default(), None, Some(d.path().into()))
            .expect("scanner builds");
        let r = g.scan_bytes("warm", b"nothing here\n");
        assert_eq!(r.targets[0].status, TargetStatus::Scanned);
        d
    })
    .path()
    .to_path_buf()
}

fn scanner_in(cache: &Path) -> RiskGrep {
    RiskGrep::with_cache_dir(Config::default(), None, Some(cache.into())).unwrap()
}

fn scanner() -> RiskGrep {
    scanner_in(&shared_cache())
}

fn secret() -> Category {
    Category("secret".into())
}

fn aws_line(seed: u64) -> String {
    format!(
        "    let id = \"{}\";\n",
        synth::fake_secret("aws_access_key", seed)
    )
}

/// Set a file's mtime well into the past so a fresh stat entry is not racy.
fn age(path: &Path) {
    let f = File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
}

fn only(r: &Report) -> &TargetReport {
    assert_eq!(r.targets.len(), 1, "one target");
    &r.targets[0]
}

fn skipped(reason: &str) -> TargetStatus {
    TargetStatus::Skipped {
        reason: reason.into(),
    }
}

#[test]
fn fifo_skipped_not_opened() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("pipe");
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let mut g = scanner();
    let t0 = Instant::now();
    let r = g.scan_paths(&[p]);
    assert!(t0.elapsed() < Duration::from_secs(1));
    assert_eq!(only(&r).status, skipped("not a regular file"));
}

#[test]
fn explicit_symlink_scanned() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("creds.rs");
    fs::write(&real, aws_line(11)).unwrap();
    let link = d.path().join("link.rs");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut g = scanner();
    let r = g.scan_paths(std::slice::from_ref(&link));
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores.get(&secret()).copied(), Some(95.0));
    assert!(t.evidence.iter().any(|e| e.rule == "aws_access_token"));
    assert_eq!(t.target, link.display().to_string());
    assert_eq!(r.summary.scores.get(&secret()).copied(), Some(95.0));
    assert_eq!(r.riskgrep_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(r.rules_bundle.len(), 64);
}

#[test]
fn walk_does_not_follow_symlinks() {
    let outside = tempfile::tempdir().unwrap();
    let secret_file = outside.path().join("creds.rs");
    fs::write(&secret_file, aws_line(12)).unwrap();
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("plain.txt"), "hello\n").unwrap();
    std::os::unix::fs::symlink(&secret_file, d.path().join("file_link.rs")).unwrap();
    std::os::unix::fs::symlink(outside.path(), d.path().join("dir_link")).unwrap();
    let mut g = scanner();
    let r = g.scan_paths(&[d.path().to_path_buf()]);
    let names: Vec<&str> = r.targets.iter().map(|t| t.target.as_str()).collect();
    assert!(!names.iter().any(|n| n.contains("dir_link/")), "{names:?}");
    for t in &r.targets {
        assert!(t.evidence.is_empty(), "no evidence through a symlink");
        if t.target.ends_with("_link.rs") || t.target.ends_with("dir_link") {
            assert_eq!(t.status, skipped("symlink not followed"));
        }
    }
    assert_eq!(r.targets.len(), 3);
    assert_eq!(r.summary.scores.get(&secret()).copied(), Some(0.0));
}

#[test]
fn walk_sorted_and_recursive() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("sub")).unwrap();
    fs::write(d.path().join("b.txt"), "b\n").unwrap();
    fs::write(d.path().join("a.txt"), "a\n").unwrap();
    fs::write(d.path().join("sub/c.rs"), aws_line(13)).unwrap();
    let mut g = scanner();
    let r = g.scan_paths(&[d.path().to_path_buf()]);
    let names: Vec<String> = r.targets.iter().map(|t| t.target.clone()).collect();
    let base = d.path().display().to_string();
    assert_eq!(
        names,
        vec![
            format!("{base}/a.txt"),
            format!("{base}/b.txt"),
            format!("{base}/sub/c.rs"),
        ]
    );
    assert_eq!(r.summary.scores.get(&secret()).copied(), Some(95.0));
}

#[test]
fn walk_limit_partial() {
    let d = tempfile::tempdir().unwrap();
    for i in 0..5 {
        fs::write(d.path().join(format!("f{i}.txt")), "x\n").unwrap();
    }
    let mut cfg = Config::default();
    cfg.limits.walk_files = 3;
    let mut g = RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap();
    let r = g.scan_paths(&[d.path().to_path_buf()]);
    let dir = r
        .targets
        .iter()
        .find(|t| t.target == d.path().display().to_string())
        .expect("directory target");
    assert!(matches!(dir.status, TargetStatus::Partial { .. }));
    let files = r
        .targets
        .iter()
        .filter(|t| t.status == TargetStatus::Scanned)
        .count();
    assert_eq!(files, 3);
    let scanned: Vec<String> = r
        .targets
        .iter()
        .filter(|t| t.status == TargetStatus::Scanned)
        .map(|t| t.target.clone())
        .collect();
    let base = d.path().display().to_string();
    assert_eq!(
        scanned,
        (0..3)
            .map(|i| format!("{base}/f{i}.txt"))
            .collect::<Vec<_>>()
    );
    assert_eq!(r.summary.partial, 1);
}

#[test]
fn walk_skips_fifo_and_completes() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.txt"), "a\n").unwrap();
    fs::write(d.path().join("z.txt"), "z\n").unwrap();
    let p = d.path().join("m_pipe");
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let t0 = Instant::now();
    let r = scanner().scan_paths(&[d.path().to_path_buf()]);
    assert!(t0.elapsed() < Duration::from_secs(1));
    let statuses: Vec<(String, TargetStatus)> = r
        .targets
        .iter()
        .map(|t| (t.target.clone(), t.status.clone()))
        .collect();
    let base = d.path().display().to_string();
    assert_eq!(
        statuses,
        vec![
            (format!("{base}/a.txt"), TargetStatus::Scanned),
            (format!("{base}/m_pipe"), skipped("not a regular file")),
            (format!("{base}/z.txt"), TargetStatus::Scanned),
        ]
    );
}

#[test]
fn cache_hit_loads_no_bundle() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("creds.rs");
    fs::write(&f, aws_line(14)).unwrap();
    age(&f);
    let first = scanner().scan_paths(std::slice::from_ref(&f));
    let mut g = scanner();
    let second = g.scan_paths(std::slice::from_ref(&f));
    assert_eq!(first, second);
    assert_eq!(only(&second).scores.get(&secret()).copied(), Some(95.0));
    assert!(!g.bundle_loaded(), "a cache hit must not load the bundle");
}

#[test]
fn content_hit_after_racy_stat_loads_no_bundle() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("creds.rs");
    fs::write(&f, aws_line(15)).unwrap();
    // mtime is now: the stat entry is racy, so the next run re-hashes.
    let first = scanner().scan_paths(std::slice::from_ref(&f));
    let mut g = scanner();
    let second = g.scan_paths(std::slice::from_ref(&f));
    assert_eq!(first, second);
    assert!(!g.bundle_loaded());
}

#[test]
fn missing_sidecar_falls_back_to_full_load() {
    let cache = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("creds.rs");
    fs::write(&f, aws_line(16)).unwrap();
    age(&f);
    // Copy the warmed bundle (not its sidecar) into a fresh cache.
    let bundles = cache.path().join("bundles");
    fs::create_dir_all(&bundles).unwrap();
    fs::set_permissions(
        cache.path(),
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(
        &bundles,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    for e in fs::read_dir(shared_cache().join("bundles")).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "yxb") {
            fs::copy(&p, bundles.join(p.file_name().unwrap())).unwrap();
        }
    }
    let first = scanner_in(cache.path()).scan_paths(std::slice::from_ref(&f));
    // The full load wrote the sidecar; remove it again.
    for e in fs::read_dir(&bundles).unwrap() {
        let p = e.unwrap().path();
        if p.to_string_lossy().ends_with(".meta.json") {
            fs::remove_file(p).unwrap();
        }
    }
    let mut g = scanner_in(cache.path());
    let second = g.scan_paths(std::slice::from_ref(&f));
    assert_eq!(first, second);
    assert!(
        g.bundle_loaded(),
        "no sidecar: scoring needs the full bundle"
    );
    let mut h = scanner_in(cache.path());
    assert_eq!(h.scan_paths(std::slice::from_ref(&f)), first);
    assert!(!h.bundle_loaded(), "the full load rewrote the sidecar");
}

static HOOK_TARGET: Mutex<Option<PathBuf>> = Mutex::new(None);
/// Path whose read time the hook records, and the recorded time.
static TIME_TARGET: Mutex<Option<(PathBuf, Option<SystemTime>)>> = Mutex::new(None);

/// The one `AFTER_READ` hook of this test binary.
fn test_hook(p: &Path) {
    if let Some((path, at)) = TIME_TARGET.lock().unwrap().as_mut() {
        if path == p {
            *at = Some(SystemTime::now());
        }
    }
    append_hook(p);
}

fn append_hook(p: &Path) {
    let mut t = HOOK_TARGET.lock().unwrap();
    if t.as_deref() == Some(p) {
        *t = None;
        let mut f = File::options().append(true).open(p).unwrap();
        f.write_all(aws_line(17).as_bytes()).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(30))
            .unwrap();
    }
}

#[test]
fn modified_during_scan_not_cached() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("notes.rs");
    fs::write(&f, "fn main() {}\n").unwrap();
    age(&f);
    let real = fs::canonicalize(&f).unwrap();
    *HOOK_TARGET.lock().unwrap() = Some(real);
    let _ = AFTER_READ.set(test_hook);
    let first = scanner().scan_paths(std::slice::from_ref(&f));
    assert_eq!(only(&first).status, TargetStatus::Scanned);
    assert_eq!(only(&first).scores.get(&secret()).copied(), Some(0.0));
    // The file now holds a key; a later scan must see it, not a stale hit.
    let second = scanner().scan_paths(std::slice::from_ref(&f));
    assert_eq!(only(&second).scores.get(&secret()).copied(), Some(95.0));
}

#[test]
fn stat_entry_time_is_taken_before_the_read() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("timed.rs");
    fs::write(&f, aws_line(26)).unwrap();
    age(&f);
    let real = fs::canonicalize(&f).unwrap();
    *TIME_TARGET.lock().unwrap() = Some((real.clone(), None));
    let _ = AFTER_READ.set(test_hook);
    let r = scanner().scan_paths(std::slice::from_ref(&f));
    assert_eq!(only(&r).scores[&secret()], 95.0);
    let read_at = TIME_TARGET
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .1
        .expect("hook ran");
    let read_at_ns = read_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let db = rusqlite::Connection::open(shared_cache().join("evidence.sqlite")).unwrap();
    let written: i64 = db
        .query_row(
            "SELECT written_at_ns FROM stat WHERE realpath = ?1",
            [std::os::unix::ffi::OsStrExt::as_bytes(real.as_os_str())],
            |row| row.get(0),
        )
        .expect("stat row written");
    assert!(
        written <= read_at_ns,
        "stat write time must precede the read, not follow the scan"
    );
}

#[test]
fn archive_unscanned() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("a.zip");
    fs::write(&f, b"PK\x03\x04rest of a zip").unwrap();
    let r = scanner().scan_paths(&[f]);
    assert_eq!(
        only(&r).status,
        TargetStatus::Unscanned {
            reason: "zip not scanned in v1".into()
        }
    );
    assert_eq!(r.summary.unscanned, 1);
}

#[test]
fn image_skipped() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("a.png");
    fs::write(&f, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    let r = scanner().scan_paths(&[f]);
    assert!(matches!(only(&r).status, TargetStatus::Skipped { .. }));
    assert!(only(&r).scores.is_empty());
}

#[test]
fn unreadable_reports_error_kind() {
    let d = tempfile::tempdir().unwrap();
    let r = scanner().scan_paths(&[d.path().join("missing.txt")]);
    match &only(&r).status {
        TargetStatus::Unscanned { reason } => assert!(reason.contains("NotFound"), "{reason}"),
        s => panic!("unexpected {s:?}"),
    }
}

#[test]
fn stdin_never_cached() {
    let text = aws_line(18);
    let r = scanner().scan_bytes("<stdin>", text.as_bytes());
    let t = only(&r);
    assert_eq!(t.target, "<stdin>");
    assert_eq!(t.scores.get(&secret()).copied(), Some(95.0));
    let mut g = scanner();
    let again = g.scan_bytes("<stdin>", text.as_bytes());
    assert_eq!(again, r);
    assert!(
        g.bundle_loaded(),
        "raw text is always scanned, never cached"
    );
}

#[test]
fn stdin_over_limit_partial() {
    let mut cfg = Config::default();
    cfg.limits.text_max = 1024;
    cfg.limits.sample = 256;
    let mut g = RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap();
    let r = g.scan_bytes("<stdin>", synth::source_text(4096, 1).as_bytes());
    assert!(matches!(only(&r).status, TargetStatus::Partial { .. }));
}

#[test]
fn blob_only_lines() {
    let text = format!("fn main() {{}}\n{}// end\n", aws_line(19));
    let mut g = scanner();
    let all = g.scan_blob("src/a.rs", b"blob-1", text.as_bytes(), None);
    assert_eq!(all.scores.get(&secret()).copied(), Some(95.0));
    let some = g.scan_blob(
        "src/a.rs",
        b"blob-1",
        text.as_bytes(),
        Some(std::slice::from_ref(&(5..=9))),
    );
    assert!(some.evidence.is_empty());
    assert_eq!(some.scores.get(&secret()).copied(), Some(0.0));
    let hit = g.scan_blob(
        "src/a.rs",
        b"blob-1",
        text.as_bytes(),
        Some(std::slice::from_ref(&(2..=2))),
    );
    assert_eq!(hit.scores.get(&secret()).copied(), Some(95.0));
}

#[test]
fn blob_cached_by_id() {
    let text = aws_line(20);
    let a = scanner().scan_blob("src/b.rs", b"blob-2", text.as_bytes(), None);
    let mut g = scanner();
    let b = g.scan_blob("src/b.rs", b"blob-2", text.as_bytes(), None);
    assert_eq!(a, b);
    assert!(!g.bundle_loaded());
}

#[test]
fn ignore_rules_suppress_before_scoring() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("creds.rs");
    fs::write(&f, aws_line(21)).unwrap();
    let ignore = riskgrep_core::suppress::IgnoreRules::new(riskgrep_core::suppress::IgnoreSpec {
        paths: vec![],
        rules: vec![riskgrep_core::suppress::RuleIgnore {
            path: "**/creds.rs".into(),
            rules: vec!["aws_access_token".into()],
        }],
    })
    .unwrap();
    let cfg = Config {
        ignore,
        ..Config::default()
    };
    let mut g = RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap();
    let r = g.scan_paths(&[f]);
    let t = only(&r);
    // The key line matches only `aws_access_token`; with it ignored, nothing
    // is left to score.
    assert!(t.evidence.is_empty());
    assert_eq!(t.suppressed, 1);
    assert_eq!(t.scores.get(&secret()).copied(), Some(0.0));
}

#[test]
fn weight_override_changes_score() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("creds.rs");
    fs::write(&f, aws_line(22)).unwrap();
    age(&f);
    let _ = scanner().scan_paths(std::slice::from_ref(&f));
    let mut cfg = Config::default();
    cfg.weight_overrides
        .insert("secrets_core:aws_access_token".into(), 10.0);
    let mut g = RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap();
    let r = g.scan_paths(&[f]);
    let t = only(&r);
    let ev = t
        .evidence
        .iter()
        .find(|e| e.rule == "aws_access_token")
        .unwrap();
    assert_eq!(ev.weight, 10.0);
    assert!(t.scores[&secret()] < 95.0);
}

#[test]
fn unknown_ruleset_is_an_error() {
    let cfg = Config {
        rulesets: vec!["no_such_ruleset".into()],
        ..Config::default()
    };
    let err = RiskGrep::with_cache_dir(cfg, None, Some(shared_cache()))
        .err()
        .expect("error");
    assert!(err.to_string().contains("no_such_ruleset"));
}

#[test]
fn category_filter_limits_scores() {
    let cfg = Config {
        categories: Some(vec![Category("biometric".into())]),
        ..Config::default()
    };
    let mut g = RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap();
    let r = g.scan_bytes("<stdin>", aws_line(23).as_bytes());
    let t = only(&r);
    assert!(t.evidence.is_empty());
    assert!(!t.scores.contains_key(&secret()));
}

#[test]
fn no_cache_directory_still_scans() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("creds.rs");
    fs::write(&f, aws_line(24)).unwrap();
    let mut g = RiskGrep::with_cache_dir(Config::default(), None, None).unwrap();
    let r = g.scan_paths(&[f]);
    assert_eq!(only(&r).scores.get(&secret()).copied(), Some(95.0));
}

/// Wall time of `RiskGrep::new` plus `scan_paths`, in-process. Run with
/// `cargo test --release -p riskgrep-core --test scanner -- --ignored --nocapture`.
#[test]
#[ignore]
fn perf_timings() {
    let cache = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    let small = d.path().join("small.rs");
    fs::write(&small, synth::source_text(4096, 2)).unwrap();
    age(&small);
    let t0 = Instant::now();
    let _ = scanner_in(cache.path()).scan_paths(std::slice::from_ref(&small));
    eprintln!("cold (bundle compile + 4 KB): {:?}", t0.elapsed());
    let mut cached = Vec::new();
    let mut uncached = Vec::new();
    for i in 0..50u64 {
        let t = Instant::now();
        let mut g = scanner_in(cache.path());
        let _ = g.scan_paths(std::slice::from_ref(&small));
        cached.push(t.elapsed());
        assert!(!g.bundle_loaded());
        let big = d.path().join(format!("big{i}.rs"));
        fs::write(&big, synth::source_text(65_536, 100 + i)).unwrap();
        let t = Instant::now();
        let mut g = scanner_in(cache.path());
        let _ = g.scan_paths(std::slice::from_ref(&big));
        uncached.push(t.elapsed());
    }
    for (name, mut v) in [("cached 4 KB", cached), ("uncached 64 KB", uncached)] {
        v.sort();
        eprintln!(
            "{name}: median {:?}, p95 {:?}",
            v[v.len() / 2],
            v[v.len() * 95 / 100]
        );
    }
}

#[test]
fn repository_baseline_suppresses() {
    let repo = tempfile::tempdir().unwrap();
    let f = repo.path().join("creds.rs");
    fs::write(&f, aws_line(25)).unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    let first = scanner().scan_paths(std::slice::from_ref(&f));
    assert_eq!(only(&first).scores[&secret()], 95.0);
    let rel = |t: &str| {
        fs::canonicalize(t)
            .unwrap()
            .strip_prefix(&root)
            .unwrap()
            .display()
            .to_string()
    };
    let b = riskgrep_core::suppress::Baseline::create(&first.targets, rel).unwrap();
    b.save(&repo.path().join(".riskgrep-baseline.json"))
        .unwrap();
    let mut g =
        RiskGrep::with_cache_dir(Config::default(), Some(repo.path()), Some(shared_cache()))
            .unwrap();
    let r = g.scan_paths(&[f]);
    let t = only(&r);
    assert!(t.evidence.is_empty());
    assert!(t.suppressed >= 1);
    assert_eq!(t.scores[&secret()], 0.0);
    assert_eq!(r.summary.suppressed, t.suppressed);
}

fn baseline_repo(seed: u64) -> (TempDir, PathBuf) {
    let repo = tempfile::tempdir().unwrap();
    let f = repo.path().join("creds.rs");
    fs::write(&f, aws_line(seed)).unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    let first = scanner().scan_paths(std::slice::from_ref(&f));
    let rel = |t: &str| {
        fs::canonicalize(t)
            .unwrap()
            .strip_prefix(&root)
            .unwrap()
            .display()
            .to_string()
    };
    let b = riskgrep_core::suppress::Baseline::create(&first.targets, rel).unwrap();
    b.save(&repo.path().join(".riskgrep-baseline.json"))
        .unwrap();
    (repo, f)
}

#[test]
fn untrusted_baseline_ignored_for_claude_code_honoured_for_git() {
    let (repo, f) = baseline_repo(27);
    let scan = |mode: Mode| {
        let cfg = Config {
            mode,
            ..Config::default()
        };
        let mut g = RiskGrep::with_cache_dir(cfg, Some(repo.path()), Some(shared_cache())).unwrap();
        g.scan_paths(std::slice::from_ref(&f))
    };
    let claude = scan(Mode::ClaudeCode);
    assert_eq!(only(&claude).scores[&secret()], 95.0);
    assert_eq!(only(&claude).suppressed, 0);
    let git = scan(Mode::Git);
    assert!(only(&git).evidence.is_empty());
    assert_eq!(only(&git).scores[&secret()], 0.0);
    // Trusted in the user config: Claude Code honours it too.
    let cfg = Config {
        mode: Mode::ClaudeCode,
        trusted_repos: vec![repo.path().to_path_buf()],
        ..Config::default()
    };
    let mut g = RiskGrep::with_cache_dir(cfg, Some(repo.path()), Some(shared_cache())).unwrap();
    let trusted = g.scan_paths(std::slice::from_ref(&f));
    assert_eq!(only(&trusted).scores[&secret()], 0.0);
}
