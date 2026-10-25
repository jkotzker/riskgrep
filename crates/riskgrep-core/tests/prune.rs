//! Pruning the cache directory as a whole: the daily marker, the bundle and
//! database steps together, and the guarantee that a scan never prunes.
//! Secrets are generated at run time and never printed.

use riskgrep_core::cache::Cache;
use riskgrep_core::config::Config;
use riskgrep_core::model::{Category, Evidence, Report};
use riskgrep_core::prune::{due, mark, prune, PruneOptions, INTERVAL, MARKER};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::synth;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const DAY: u64 = 86_400;

fn scanner(cache: &Path) -> RiskGrep {
    RiskGrep::with_cache_dir(Config::default(), None, Some(cache.into())).unwrap()
}

/// A work directory holding one file with a generated key, aged so a stat
/// entry for it is not racy.
fn key_file(dir: &Path) -> PathBuf {
    let p = dir.join("key.txt");
    let key = synth::fake_secret("aws_access_key", 5);
    fs::write(&p, format!("one\ntwo\nlet id = \"{key}\";\n")).unwrap();
    File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
    p
}

fn scan_file(cache: &Path, file: &Path) -> Report {
    let mut rg = scanner(cache);
    let r = rg.scan_paths(&[file.to_path_buf()]);
    rg.close_cache();
    r
}

fn stale_key() -> String {
    "9".repeat(64)
}

fn make_stale_bundle(cache: &Path, age_days: u64) -> PathBuf {
    let dir = cache.join("bundles");
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{}.yxb", stale_key()));
    fs::write(&p, vec![0u8; 1000]).unwrap();
    File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(age_days * DAY))
        .unwrap();
    p
}

fn evidence() -> Vec<Evidence> {
    vec![Evidence {
        rule: "r".into(),
        category: Category("secret".into()),
        weight: 1.0,
        count: 1,
        locations: vec![],
        shape: vec![],
        fingerprints: vec![[1; 32]],
        line_complete: false,
    }]
}

fn options(current: &str, dry_run: bool) -> PruneOptions {
    PruneOptions {
        max_age: Duration::from_secs(30 * DAY),
        max_db_bytes: u64::MAX,
        protected_keys: BTreeSet::from([current.to_string()]),
        dry_run,
    }
}

#[test]
fn due_when_the_marker_is_missing_or_a_day_old() {
    let d = tempfile::tempdir().unwrap();
    let now = SystemTime::now();
    assert!(due(d.path(), now));
    mark(d.path(), now).unwrap();
    assert!(!due(d.path(), now));
    assert!(!due(d.path(), now + INTERVAL - Duration::from_secs(60)));
    assert!(due(d.path(), now + INTERVAL + Duration::from_secs(60)));
    // A marker dated far in the future (clock change) does not block pruning forever.
    mark(d.path(), now + Duration::from_secs(10 * DAY)).unwrap();
    assert!(due(d.path(), now));
}

#[test]
fn the_marker_is_a_private_file() {
    let d = tempfile::tempdir().unwrap();
    let cache = d.path().join("cache");
    mark(&cache, SystemTime::now()).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&cache), 0o700);
    assert_eq!(mode(&cache.join(MARKER)), 0o600);
}

#[test]
fn prune_removes_a_stale_bundle_and_its_rows_and_keeps_the_current_ones() {
    let d = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let file = key_file(work.path());
    let first = scan_file(d.path(), &file);
    let current = first.rules_bundle.clone();
    let stale = make_stale_bundle(d.path(), 60);
    {
        let c = Cache::open(d.path()).unwrap();
        c.put_evidence([7; 32], &format!("{}:x.txt", stale_key()), &evidence());
    }
    let dry = prune(d.path(), &options(&current, true), SystemTime::now()).unwrap();
    assert_eq!((dry.bundles_removed, dry.bundles_kept), (1, 1));
    assert_eq!(dry.database.as_ref().unwrap().evidence_stranded, 1);
    assert!(stale.exists(), "a dry run deletes nothing");
    assert!(Cache::open(d.path())
        .unwrap()
        .evidence([7; 32], &format!("{}:x.txt", stale_key()))
        .is_some());

    let real = prune(d.path(), &options(&current, false), SystemTime::now()).unwrap();
    assert_eq!(real.bundles_removed, 1);
    assert_eq!(real.database.as_ref().unwrap().evidence_stranded, 1);
    assert!(!stale.exists());
    assert!(d
        .path()
        .join("bundles")
        .join(format!("{current}.yxb"))
        .exists());

    // The rows for the current bundle survive: the next scan is served from
    // the cache without compiling.
    let mut rg = scanner(d.path());
    let again = rg.scan_paths(&[file]);
    assert!(!rg.bundle_loaded(), "evidence cache hit needs no engine");
    assert_eq!(
        serde_json::to_string(&first.targets).unwrap(),
        serde_json::to_string(&again.targets).unwrap()
    );
}

#[test]
fn an_emptied_cache_gives_the_same_scores() {
    let d = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let file = key_file(work.path());
    let first = scan_file(d.path(), &file);
    // Size cap 1 byte, age 0: everything pruneable goes.
    let o = PruneOptions {
        max_age: Duration::ZERO,
        max_db_bytes: 1,
        protected_keys: BTreeSet::new(),
        dry_run: false,
    };
    let r = prune(d.path(), &o, SystemTime::now() + Duration::from_secs(5)).unwrap();
    let db = r.database.unwrap();
    assert_eq!((db.evidence_rows, db.stat_rows), (0, 0));
    assert_eq!(r.bundles_removed, 1);
    let again = scan_file(d.path(), &file);
    assert_eq!(
        serde_json::to_string(&first.targets).unwrap(),
        serde_json::to_string(&again.targets).unwrap()
    );
}

#[test]
fn a_scan_never_prunes() {
    // The Claude Code hook scans through this same API.
    let d = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let file = key_file(work.path());
    let stale = make_stale_bundle(d.path(), 400);
    scan_file(d.path(), &file);
    scan_file(d.path(), &file);
    assert!(stale.exists());
    assert!(!d.path().join(MARKER).exists());
}

#[test]
fn prune_without_a_database_touches_nothing_else() {
    let d = tempfile::tempdir().unwrap();
    let r = prune(d.path(), &options("k", false), SystemTime::now()).unwrap();
    assert!(r.database.is_none());
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
}
