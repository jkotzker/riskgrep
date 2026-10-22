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
    assert_eq!(v, 2);
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
