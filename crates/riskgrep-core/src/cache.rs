//! SQLite evidence cache: lets a caller skip rescanning unchanged files.
//!
//! Two tables. `stat` maps a file's identity (realpath plus stat fields) to
//! the BLAKE3 of its content; `evidence` maps (content hash, rules bundle) to
//! the evidence produced by scanning it. Rows hold rule ids, offsets,
//! structural facts, and digests only, never matched bytes. Every failure
//! degrades to a cache miss or a swallowed write with one stderr line, after
//! which the handle stops using the database for the rest of its life.

use crate::model::Evidence;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::fs::{Metadata, OpenOptions, Permissions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: i64 = 1;
const DB_NAME: &str = "evidence.sqlite";
/// A stat entry written less than this long after the file's mtime may predate
/// a further edit within the same timestamp granularity; it is not trusted.
const RACY_WINDOW_NS: i128 = 2_000_000_000;

/// File identity used to detect change without reading content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatKey {
    pub realpath: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

impl StatKey {
    pub fn from_metadata(path: &Path, m: &Metadata) -> StatKey {
        let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
        StatKey {
            realpath: path.to_path_buf(),
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime_ns: ns(m.mtime(), m.mtime_nsec()),
            ctime_ns: ns(m.ctime(), m.ctime_nsec()),
        }
    }
}

/// Row payload. `Evidence` skips its fingerprints when serialized, so they are
/// carried alongside as hex.
#[derive(Serialize, Deserialize)]
struct CachedEvidence {
    evidence: Evidence,
    fingerprints: Vec<String>,
}

pub struct Cache {
    conn: Connection,
    /// Set by the first read or write error; every later call is a no-op.
    failed: Cell<bool>,
}

/// How long a first open waits for another process holding the database.
const BUSY_WAIT: std::time::Duration = std::time::Duration::from_millis(2000);

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(
                f.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn ns_since_epoch(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

impl Cache {
    /// Open or create `dir/evidence.sqlite`. `None` (with one stderr line) on
    /// any failure: the caller proceeds uncached.
    pub fn open(dir: &Path) -> Option<Cache> {
        match Self::try_open(dir) {
            Ok(c) => Some(c),
            Err(reason) => {
                eprintln!("riskgrep: cache bypassed: {reason}");
                None
            }
        }
    }

    fn try_open(dir: &Path) -> Result<Cache, String> {
        crate::paths::ensure_private_dir(dir).map_err(|e| format!("directory: {e}"))?;
        let meta = std::fs::metadata(dir).map_err(|e| format!("directory: {e}"))?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err("directory is not owned by the current user".into());
        }
        let file = dir.join(DB_NAME);
        // Create the file private before SQLite does; the -wal/-shm siblings
        // inherit the main file's mode.
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&file)
            .map_err(|e| format!("database file: {e}"))?;
        std::fs::set_permissions(&file, Permissions::from_mode(0o600))
            .map_err(|e| format!("database file mode: {e}"))?;
        let conn = Connection::open(&file).map_err(|e| format!("open: {e}"))?;
        // Wait for other first-time openers. The busy handler does not cover
        // every step of the WAL switch, so a busy error also retries the setup.
        conn.busy_timeout(BUSY_WAIT)
            .map_err(|e| format!("open: {e}"))?;
        let started = std::time::Instant::now();
        loop {
            match Self::init(&conn) {
                Ok(()) => break,
                Err(e) if is_busy(&e) && started.elapsed() < BUSY_WAIT => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => return Err(format!("schema: {e}")),
            }
        }
        Ok(Cache {
            conn,
            failed: Cell::new(false),
        })
    }

    /// Report the first error (one stderr line) and stop using the cache.
    fn warn(&self, what: &str, reason: impl std::fmt::Display) {
        if !self.failed.replace(true) {
            eprintln!("riskgrep: cache {what}: {reason}; cache bypassed for the rest of this run");
        }
    }

    /// True once an error has disabled this handle.
    pub fn is_disabled(&self) -> bool {
        self.failed.get()
    }

    fn init(conn: &Connection) -> rusqlite::Result<()> {
        // Reads the header first, so a non-database file fails here.
        conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let r = (|| {
                let again: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
                if again != SCHEMA_VERSION {
                    conn.execute_batch(
                        "DROP TABLE IF EXISTS stat; DROP TABLE IF EXISTS evidence;
                         CREATE TABLE stat(
                           realpath BLOB NOT NULL, dev INTEGER NOT NULL, ino INTEGER NOT NULL,
                           size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                           ctime_ns INTEGER NOT NULL, hash BLOB NOT NULL,
                           written_at_ns INTEGER NOT NULL, PRIMARY KEY(realpath));
                         CREATE TABLE evidence(
                           hash BLOB NOT NULL, bundle TEXT NOT NULL, json TEXT NOT NULL,
                           PRIMARY KEY(hash, bundle));",
                    )?;
                    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => conn.execute_batch("COMMIT")?,
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// The content hash recorded for `key`, if the file is unchanged and the
    /// entry is not racy (written within 2 s of the file's mtime).
    pub fn content_hash_for(&self, key: &StatKey, _now: SystemTime) -> Option<[u8; 32]> {
        if self.failed.get() {
            return None;
        }
        let (mtime, ctime) = (
            i64::try_from(key.mtime_ns).ok()?,
            i64::try_from(key.ctime_ns).ok()?,
        );
        let row = self
            .conn
            .query_row(
                "SELECT hash, written_at_ns FROM stat WHERE realpath=?1 AND dev=?2 AND ino=?3
                 AND size=?4 AND mtime_ns=?5 AND ctime_ns=?6",
                params![
                    key.realpath.as_os_str().as_bytes(),
                    key.dev as i64,
                    key.ino as i64,
                    key.size as i64,
                    mtime,
                    ctime
                ],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional();
        let (hash, written) = match row {
            Ok(Some(r)) => r,
            Ok(None) => return None,
            Err(e) => {
                self.warn("read", e);
                return None;
            }
        };
        if i128::from(written) - key.mtime_ns < RACY_WINDOW_NS {
            return None;
        }
        hash.try_into().ok()
    }

    pub fn put_stat(&self, key: &StatKey, hash: [u8; 32], now: SystemTime) {
        if self.failed.get() {
            return;
        }
        let (Ok(mtime), Ok(ctime), Ok(written)) = (
            i64::try_from(key.mtime_ns),
            i64::try_from(key.ctime_ns),
            i64::try_from(ns_since_epoch(now)),
        ) else {
            return;
        };
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO stat(realpath, dev, ino, size, mtime_ns, ctime_ns, hash, written_at_ns)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                key.realpath.as_os_str().as_bytes(),
                key.dev as i64,
                key.ino as i64,
                key.size as i64,
                mtime,
                ctime,
                &hash[..],
                written
            ],
        ) {
            self.warn("write", e);
        }
    }

    /// Cached evidence for (`hash`, `bundle`); `None` on a miss or an
    /// unreadable row.
    pub fn evidence(&self, hash: [u8; 32], bundle: &str) -> Option<Vec<Evidence>> {
        if self.failed.get() {
            return None;
        }
        let json: String = match self
            .conn
            .query_row(
                "SELECT json FROM evidence WHERE hash=?1 AND bundle=?2",
                params![&hash[..], bundle],
                |r| r.get(0),
            )
            .optional()
        {
            Ok(Some(j)) => j,
            Ok(None) => return None,
            Err(e) => {
                self.warn("read", e);
                return None;
            }
        };
        let rows: Vec<CachedEvidence> = match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(_) => {
                self.warn("read", "stored evidence is unreadable");
                return None;
            }
        };
        rows.into_iter()
            .map(|c| {
                let fps = c
                    .fingerprints
                    .iter()
                    .map(|h| unhex(h))
                    .collect::<Option<Vec<_>>>()?;
                let mut e = c.evidence;
                e.fingerprints = fps;
                Some(e)
            })
            .collect::<Option<Vec<_>>>()
            .or_else(|| {
                self.warn("read", "stored fingerprints are unreadable");
                None
            })
    }

    pub fn put_evidence(&self, hash: [u8; 32], bundle: &str, ev: &[Evidence]) {
        if self.failed.get() {
            return;
        }
        let rows: Vec<CachedEvidence> = ev
            .iter()
            .map(|e| CachedEvidence {
                fingerprints: e.fingerprints.iter().map(hex).collect(),
                evidence: e.clone(),
            })
            .collect();
        let json = match serde_json::to_string(&rows) {
            Ok(j) => j,
            Err(_) => {
                self.warn("write", "evidence could not be encoded");
                return;
            }
        };
        if let Err(e) = self.conn.execute(
            "INSERT OR REPLACE INTO evidence(hash, bundle, json) VALUES (?1,?2,?3)",
            params![&hash[..], bundle, json],
        ) {
            self.warn("write", e);
        }
    }
}
