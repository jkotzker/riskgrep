use riskgrep_core::cache::{Cache, StatKey};
use riskgrep_core::model::{Category, Evidence, Location};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const OLD_NS: i128 = 1_000_000_000; // mtime far in the past

fn key(path: &str, mtime_ns: i128) -> StatKey {
    StatKey {
        realpath: PathBuf::from(path),
        dev: 1,
        ino: 2,
        size: 3,
        mtime_ns,
        ctime_ns: mtime_ns,
    }
}

fn later(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn ev(rule: &str, fp: [u8; 32]) -> Evidence {
    Evidence {
        rule: rule.into(),
        category: Category("secrets".into()),
        weight: 1.5,
        count: 1,
        locations: vec![Location {
            start: 1,
            end: 5,
            line_start: 1,
            line_end: 1,
        }],
        shape: vec![],
        fingerprints: vec![fp],
        line_complete: false,
    }
}

fn open(dir: &Path) -> Cache {
    Cache::open(dir).expect("cache opens")
}

#[test]
fn hit_after_put() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let k = key("/a", OLD_NS);
    c.put_stat(&k, [7; 32], later(1000));
    assert_eq!(c.content_hash_for(&k, later(1001)), Some([7; 32]));
    let e = vec![ev("r", [9; 32])];
    c.put_evidence([7; 32], "b1", &e);
    let got = c.evidence([7; 32], "b1").unwrap();
    assert_eq!(got, e);
    assert_eq!(got[0].fingerprints, vec![[9u8; 32]]);
}

#[test]
fn mtime_change_misses() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let k = key("/a", OLD_NS);
    c.put_stat(&k, [7; 32], later(1000));
    assert_eq!(
        c.content_hash_for(&key("/a", OLD_NS + 1), later(1001)),
        None
    );
    let mut k2 = k.clone();
    k2.size = 4;
    assert_eq!(c.content_hash_for(&k2, later(1001)), None);
}

#[test]
fn racy_entry_misses() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    // written 1 s after mtime: racy
    let k = key("/a", 1000 * 1_000_000_000);
    c.put_stat(&k, [7; 32], later(1001));
    assert_eq!(c.content_hash_for(&k, later(2000)), None);
    // written exactly 2 s after mtime: trusted
    c.put_stat(&k, [7; 32], later(1002));
    assert_eq!(c.content_hash_for(&k, later(2000)), Some([7; 32]));
}

#[test]
fn bundle_change_misses() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    c.put_evidence([1; 32], "b1", &[ev("r", [0; 32])]);
    assert!(c.evidence([1; 32], "b2").is_none());
    assert!(c.evidence([2; 32], "b1").is_none());
    assert!(c.evidence([1; 32], "b1").is_some());
}

#[test]
fn corrupt_db_bypassed() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("evidence.sqlite"),
        b"this is not a database at all, just garbage bytes ".repeat(40),
    )
    .unwrap();
    assert!(Cache::open(d.path()).is_none());
}

#[test]
fn schema_version_mismatch_recreates() {
    let d = tempfile::tempdir().unwrap();
    {
        let c = open(d.path());
        c.put_evidence([1; 32], "b1", &[ev("r", [0; 32])]);
    }
    {
        let conn = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    let c = open(d.path());
    assert!(c.evidence([1; 32], "b1").is_none());
    c.put_evidence([1; 32], "b1", &[ev("r", [0; 32])]);
    assert!(c.evidence([1; 32], "b1").is_some());
}

#[test]
fn schema_v1_rows_are_dropped() {
    // Pre-release databases (user_version 1) may hold tensor names in their
    // evidence rows; opening the database must discard them.
    let d = tempfile::tempdir().unwrap();
    {
        let c = open(d.path());
        c.put_evidence([2; 32], "b1", &[ev("r", [0; 32])]);
    }
    {
        let conn = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
    }
    let c = open(d.path());
    assert!(c.evidence([2; 32], "b1").is_none());
    drop(c);
    let conn = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
}

#[test]
fn schema_v2_rows_are_dropped_for_the_written_at_column() {
    // Version 2 evidence rows carry no write time, so pruning could not age
    // them; the database is rebuilt (a cache miss, never a wrong result).
    let d = tempfile::tempdir().unwrap();
    {
        let conn = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE evidence(hash BLOB NOT NULL, bundle TEXT NOT NULL, json TEXT NOT NULL,
               PRIMARY KEY(hash, bundle));
             INSERT INTO evidence VALUES (x'00', 'b1', '[]');
             PRAGMA user_version = 2;",
        )
        .unwrap();
    }
    let c = open(d.path());
    assert!(c.evidence([0; 32], "b1").is_none());
    c.put_evidence([1; 32], "b1", &[ev("r", [0; 32])]);
    assert!(c.evidence([1; 32], "b1").is_some());
}

#[test]
fn files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    c.put_evidence([1; 32], "b1", &[ev("r", [0; 32])]);
    for name in [
        "evidence.sqlite",
        "evidence.sqlite-wal",
        "evidence.sqlite-shm",
    ] {
        let p = d.path().join(name);
        if p.exists() {
            let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m & 0o077, 0, "{name} mode {m:o}");
        }
    }
    assert!(d.path().join("evidence.sqlite-wal").exists());
}

#[test]
fn concurrent_writers() {
    let d = tempfile::tempdir().unwrap();
    drop(open(d.path()));
    let dir = d.path().to_path_buf();
    let hs: Vec<_> = (0..8u8)
        .map(|t| {
            let dir = dir.clone();
            std::thread::spawn(move || {
                let c = Cache::open(&dir).expect("open");
                for i in 0..50u8 {
                    let h = [t; 32];
                    let bundle = format!("b{i}");
                    let e = vec![ev(&format!("r{t}-{i}"), [i; 32])];
                    c.put_evidence(h, &bundle, &e);
                    assert_eq!(c.evidence(h, &bundle), Some(e), "thread {t} item {i}");
                    let k = key(&format!("/f{t}"), OLD_NS);
                    c.put_stat(&k, [i; 32], later(1000));
                    assert_eq!(c.content_hash_for(&k, later(1001)), Some([i; 32]));
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
}

#[test]
fn no_values_in_db() {
    let d = tempfile::tempdir().unwrap();
    let secret = riskgrep_core::synth::fake_secret("aws_access_key", 11);
    let fp = *blake3::hash(secret.as_bytes()).as_bytes();
    let c = open(d.path());
    c.put_evidence([5; 32], "b1", &[ev("aws", fp)]);
    c.put_stat(&key("/x", OLD_NS), [5; 32], later(1000));
    let mut seen = 0;
    for name in [
        "evidence.sqlite",
        "evidence.sqlite-wal",
        "evidence.sqlite-shm",
    ] {
        if let Ok(bytes) = std::fs::read(d.path().join(name)) {
            seen += 1;
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "secret found in {name}"
            );
        }
    }
    assert!(seen >= 1);
}

#[test]
fn refuses_foreign_directory() {
    // A directory owned by another user is refused. As a normal user `/` is
    // root-owned on macOS and Linux; as root, a temp directory is handed to
    // `nobody` (65534) instead.
    use std::os::unix::fs::MetadataExt;
    let probe = tempfile::tempdir().unwrap();
    if std::fs::metadata(probe.path()).unwrap().uid() == 0 {
        let d = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(d.path(), Some(65534), Some(65534)).unwrap();
        assert!(Cache::open(d.path()).is_none());
    } else {
        assert!(Cache::open(Path::new("/")).is_none());
    }
}

#[test]
fn first_error_disables_the_handle() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let k = key("/a", OLD_NS);
    c.put_stat(&k, [7; 32], later(1000));
    assert_eq!(c.content_hash_for(&k, later(1001)), Some([7; 32]));
    let other = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
    other.execute_batch("DROP TABLE evidence;").unwrap();
    drop(other);
    assert!(!c.is_disabled());
    assert_eq!(c.evidence([7; 32], "b1"), None);
    assert!(c.is_disabled());
    // The stat table is intact, but the handle no longer reads it.
    assert_eq!(c.content_hash_for(&k, later(1001)), None);
}

#[test]
fn concurrent_first_open_all_succeed() {
    for round in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = path.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    Cache::open(&p).is_some()
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().unwrap(), "round {round}: a concurrent open failed");
        }
    }
}

// ---- pruning ----

use riskgrep_core::cache::{DbPrune, DbPruneOptions};
use std::collections::BTreeSet;

const DAY: u64 = 86_400;

fn keys(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn prune(
    c: &Cache,
    live: &[&str],
    max_age_days: u64,
    max_bytes: u64,
    now: u64,
    dry_run: bool,
) -> DbPrune {
    let live = keys(live);
    c.prune(
        &DbPruneOptions {
            live_keys: &live,
            max_age: Duration::from_secs(max_age_days * DAY),
            max_bytes,
            dry_run,
        },
        later(now),
    )
    .unwrap()
}

#[test]
fn prune_removes_evidence_of_keys_without_a_bundle() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    for (h, b) in [
        (1, "live:a.rs"),
        (2, "live:b.rs"),
        (3, "old:a.rs"),
        (4, "gone:c.rs"),
    ] {
        c.put_evidence_at([h; 32], b, &[ev("r", [9; 32])], later(now - 10));
    }
    let r = prune(&c, &["live"], 30, u64::MAX, now, false);
    assert_eq!(r.evidence_stranded, 2);
    assert_eq!(r.evidence_rows, 2);
    assert!(c.evidence([1; 32], "live:a.rs").is_some());
    assert!(c.evidence([2; 32], "live:b.rs").is_some());
    assert!(c.evidence([3; 32], "old:a.rs").is_none());
    assert!(c.evidence([4; 32], "gone:c.rs").is_none());
}

#[test]
fn prune_removes_evidence_older_than_the_age() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    c.put_evidence_at([1; 32], "k:old", &[ev("r", [9; 32])], later(now - 31 * DAY));
    c.put_evidence_at([2; 32], "k:new", &[ev("r", [9; 32])], later(now - 29 * DAY));
    let r = prune(&c, &["k"], 30, u64::MAX, now, false);
    assert_eq!((r.evidence_aged, r.evidence_rows), (1, 1));
    assert!(c.evidence([1; 32], "k:old").is_none());
    assert!(c.evidence([2; 32], "k:new").is_some());
}

#[test]
fn prune_removes_stat_rows_of_missing_paths() {
    let d = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    let present = work.path().join("present.txt");
    std::fs::write(&present, "x").unwrap();
    let gone = work.path().join("gone.txt");
    let kp = key(present.to_str().unwrap(), OLD_NS);
    let kg = key(gone.to_str().unwrap(), OLD_NS);
    c.put_stat(&kp, [1; 32], later(now - 5));
    c.put_stat(&kg, [2; 32], later(now - 5));
    let r = prune(&c, &[], 30, u64::MAX, now, false);
    assert_eq!((r.stat_missing, r.stat_aged, r.stat_rows), (1, 0, 1));
    assert_eq!(c.content_hash_for(&kp, later(now)), Some([1; 32]));
    assert_eq!(c.content_hash_for(&kg, later(now)), None);
}

#[test]
fn prune_removes_stat_rows_not_written_for_the_age() {
    let d = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    let (a, b) = (work.path().join("a"), work.path().join("b"));
    std::fs::write(&a, "x").unwrap();
    std::fs::write(&b, "x").unwrap();
    let (ka, kb) = (
        key(a.to_str().unwrap(), OLD_NS),
        key(b.to_str().unwrap(), OLD_NS),
    );
    c.put_stat(&ka, [1; 32], later(now - 31 * DAY));
    c.put_stat(&kb, [2; 32], later(now - 29 * DAY));
    let r = prune(&c, &[], 30, u64::MAX, now, false);
    assert_eq!((r.stat_aged, r.stat_missing, r.stat_rows), (1, 0, 1));
    assert_eq!(c.content_hash_for(&ka, later(now)), None);
    assert_eq!(c.content_hash_for(&kb, later(now)), Some([2; 32]));
}

/// Evidence rows with a payload of about `payload` bytes each.
fn fat(rule: &str, payload: usize) -> Vec<Evidence> {
    let mut e = ev(rule, [9; 32]);
    e.locations = vec![e.locations[0].clone(); payload / 60];
    vec![e]
}

#[test]
fn prune_caps_the_database_size_keeping_the_newest_rows() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    for i in 0..400u32 {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        // Row i is written i seconds after the first; higher i is newer.
        c.put_evidence_at(h, "k:f", &fat("r", 2000), later(now - 1000 + u64::from(i)));
    }
    // 400 rows of about 2 kB take about 860 kB once vacuumed.
    let cap = 430_000;
    let r = prune(&c, &["k"], 30, cap, now, false);
    assert!(r.evidence_size > 0, "{r:?}");
    assert!(r.bytes_after <= cap, "{} > {cap}", r.bytes_after);
    let mut newest = [0u8; 32];
    newest[..4].copy_from_slice(&399u32.to_le_bytes());
    let mut oldest = [0u8; 32];
    oldest[..4].copy_from_slice(&0u32.to_le_bytes());
    assert!(c.evidence(newest, "k:f").is_some());
    assert!(c.evidence(oldest, "k:f").is_none());
}

#[test]
fn prune_does_not_remove_rows_when_vacuum_alone_gets_under_the_size_cap() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    for i in 0..400u32 {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        c.put_evidence_at(h, "k:f", &fat("r", 2000), later(now - 5));
    }
    // The file with its write-ahead log is far larger than the rows need.
    let cap = c.file_bytes() / 2;
    let r = prune(&c, &["k"], 30, cap, now, false);
    assert_eq!((r.evidence_size, r.evidence_rows), (0, 400), "{r:?}");
    assert!(r.bytes_after <= cap);
}

#[test]
fn prune_dry_run_reports_the_same_counts_and_changes_nothing() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    for i in 0..50u8 {
        c.put_evidence_at([i; 32], "gone:f", &fat("r", 200), later(now - 5));
        c.put_evidence_at([i; 32], "k:f", &fat("r", 200), later(now - 40 * DAY));
    }
    c.put_stat(
        &key("/nonexistent/riskgrep-prune-test", OLD_NS),
        [1; 32],
        later(now - 5),
    );
    let dry = prune(&c, &["k"], 30, u64::MAX, now, true);
    assert_eq!(dry.evidence_stranded, 50);
    assert_eq!(dry.evidence_aged, 50);
    assert_eq!(dry.stat_missing, 1);
    // Nothing changed.
    assert!(c.evidence([1; 32], "gone:f").is_some());
    assert!(c.evidence([1; 32], "k:f").is_some());
    let again = prune(&c, &["k"], 30, u64::MAX, now, true);
    assert_eq!(dry, again);
    let real = prune(&c, &["k"], 30, u64::MAX, now, false);
    for (a, b) in [
        (dry.evidence_stranded, real.evidence_stranded),
        (dry.evidence_aged, real.evidence_aged),
        (dry.stat_missing, real.stat_missing),
        (dry.evidence_rows, real.evidence_rows),
        (dry.stat_rows, real.stat_rows),
    ] {
        assert_eq!(a, b);
    }
    assert!(c.evidence([1; 32], "gone:f").is_none());
}

#[test]
fn pruned_rows_are_misses_and_retained_rows_are_unchanged() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let now = 100 * DAY;
    let kept = vec![ev("kept", [3; 32])];
    c.put_evidence_at([1; 32], "k:a", &kept, later(now - 1));
    c.put_evidence_at(
        [2; 32],
        "k:b",
        &[ev("aged", [4; 32])],
        later(now - 99 * DAY),
    );
    prune(&c, &["k"], 30, u64::MAX, now, false);
    assert_eq!(c.evidence([1; 32], "k:a"), Some(kept));
    assert_eq!(c.evidence([2; 32], "k:b"), None);
    assert!(!c.is_disabled());
}

#[test]
fn evidence_rows_get_the_time_they_were_written() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    // A hit does not rewrite the row: still aged by its original time.
    c.put_evidence_at([1; 32], "k:a", &[ev("r", [3; 32])], later(10 * DAY));
    for _ in 0..3 {
        assert!(c.evidence([1; 32], "k:a").is_some());
    }
    let r = prune(&c, &["k"], 30, u64::MAX, 100 * DAY, false);
    assert_eq!(r.evidence_aged, 1);
}

#[test]
fn prune_removes_a_malformed_stat_row_instead_of_failing() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    {
        let conn = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO stat VALUES ('text-path', 1, 2, 3, 4, 5, x'00', ?1)",
            [i64::try_from(99 * DAY * 1_000_000_000).unwrap()],
        )
        .unwrap();
    }
    let r = prune(&c, &[], 30, u64::MAX, 100 * DAY, false);
    assert_eq!((r.stat_missing, r.stat_rows), (1, 0));
}

#[test]
fn open_existing_creates_nothing() {
    let d = tempfile::tempdir().unwrap();
    assert!(Cache::open_existing(d.path()).is_none());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn prune_reports_a_busy_database_with_a_recognisable_error() {
    let d = tempfile::tempdir().unwrap();
    let c = open(d.path());
    let other = rusqlite::Connection::open(d.path().join("evidence.sqlite")).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let live = keys(&[]);
    let err = c
        .prune(
            &DbPruneOptions {
                live_keys: &live,
                max_age: Duration::from_secs(30 * DAY),
                max_bytes: u64::MAX,
                dry_run: false,
            },
            later(100 * DAY),
        )
        .unwrap_err();
    assert_eq!(err, riskgrep_core::cache::PRUNE_BUSY);
}
