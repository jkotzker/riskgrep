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
use std::collections::BTreeSet;
use std::fs::{Metadata, OpenOptions, Permissions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Version 2 drops pre-release rows that could hold tensor names. Version 3
/// adds the time an `evidence` row was written, which pruning needs.
const SCHEMA_VERSION: i64 = 3;
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
    file: PathBuf,
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
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        // One stat on the common path (the directory exists); create it only
        // when missing.
        let meta = match std::fs::metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                crate::paths::ensure_private_dir(dir).map_err(|e| format!("directory: {e}"))?;
                std::fs::metadata(dir)
            }
            other => other,
        }
        .map_err(|e| format!("directory: {e}"))?;
        if !meta.is_dir() {
            return Err("directory: not a directory".into());
        }
        if meta.uid() != euid {
            return Err("directory is not owned by the current user".into());
        }
        if meta.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, Permissions::from_mode(0o700))
                .map_err(|e| format!("directory: {e}"))?;
        }
        let file = dir.join(DB_NAME);
        // Create the file private before SQLite does; the -wal/-shm siblings
        // inherit the main file's mode. An existing private file of ours
        // needs neither an open nor a chmod.
        let private = std::fs::symlink_metadata(&file)
            .is_ok_and(|m| m.file_type().is_file() && m.uid() == euid && m.mode() & 0o077 == 0);
        if !private {
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&file)
                .map_err(|e| format!("database file: {e}"))?;
            std::fs::set_permissions(&file, Permissions::from_mode(0o600))
                .map_err(|e| format!("database file mode: {e}"))?;
        }
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
            file,
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
                           written_at_ns INTEGER NOT NULL, PRIMARY KEY(hash, bundle));",
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
        self.put_evidence_at(hash, bundle, ev, SystemTime::now());
    }

    /// [`Cache::put_evidence`] recording `now` as the time the row was
    /// written. The time is set only here, on a miss; a cache hit never
    /// writes, so the Claude Code hook's cached-read path stays read-only.
    pub fn put_evidence_at(&self, hash: [u8; 32], bundle: &str, ev: &[Evidence], now: SystemTime) {
        if self.failed.get() {
            return;
        }
        let Ok(written) = i64::try_from(ns_since_epoch(now)) else {
            return;
        };
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
            "INSERT OR REPLACE INTO evidence(hash, bundle, json, written_at_ns) VALUES (?1,?2,?3,?4)",
            params![&hash[..], bundle, json, written],
        ) {
            self.warn("write", e);
        }
    }

    /// Open an existing database for pruning; `None` when there is no
    /// database file (nothing is created) or it cannot be opened.
    pub fn open_existing(dir: &Path) -> Option<Cache> {
        std::fs::symlink_metadata(dir.join(DB_NAME))
            .is_ok_and(|m| m.file_type().is_file())
            .then(|| Self::open(dir))
            .flatten()
    }

    /// Size on disk of the database and its write-ahead log.
    pub fn file_bytes(&self) -> u64 {
        let wal = {
            let mut w = self.file.as_os_str().to_owned();
            w.push("-wal");
            PathBuf::from(w)
        };
        [self.file.as_path(), wal.as_path()]
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    /// Remove rows the cache no longer needs; see [`DbPruneOptions`]. With
    /// `dry_run` every step runs inside a transaction that is rolled back, so
    /// the counts match a real run and nothing changes. A row that goes only
    /// costs a rescan; no score depends on a row being present.
    pub fn prune(&self, o: &DbPruneOptions<'_>, now: SystemTime) -> Result<DbPrune, String> {
        let sql = |e: rusqlite::Error| format!("prune: {e}");
        let mut r = DbPrune {
            bytes_before: self.file_bytes(),
            ..DbPrune::default()
        };
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(sql)?;
        let stepped = self.prune_steps(o, now, &mut r);
        let end = if o.dry_run || stepped.is_err() {
            "ROLLBACK"
        } else {
            "COMMIT"
        };
        let ended = self.conn.execute_batch(end).map_err(sql);
        stepped?;
        ended?;
        if o.dry_run {
            return Ok(r);
        }
        let max = i64::try_from(o.max_bytes).unwrap_or(i64::MAX);
        // Deleting leaves free pages inside the file; only VACUUM returns
        // them, so the size cap is judged on the real file after one. When it
        // is still over, remove the oldest rows by the real size and repeat.
        let mut vacuumed = false;
        if r.removed() > 0 {
            self.vacuum().map_err(sql)?;
            vacuumed = true;
        }
        for pass in 0..SIZE_PASSES {
            r.bytes_after = self.file_bytes();
            if i64::try_from(r.bytes_after).unwrap_or(i64::MAX) <= max {
                break;
            }
            if !vacuumed {
                self.vacuum().map_err(sql)?;
                vacuumed = true;
                r.bytes_after = self.file_bytes();
                if i64::try_from(r.bytes_after).unwrap_or(i64::MAX) <= max {
                    break;
                }
            }
            if pass + 1 == SIZE_PASSES {
                break;
            }
            self.conn.execute_batch("BEGIN IMMEDIATE").map_err(sql)?;
            let shrunk = self.shrink(
                i64::try_from(r.bytes_after).unwrap_or(i64::MAX),
                max,
                &mut r,
            );
            let end = if shrunk.is_ok() { "COMMIT" } else { "ROLLBACK" };
            self.conn.execute_batch(end).map_err(sql)?;
            shrunk.map_err(sql)?;
            self.vacuum().map_err(sql)?;
        }
        r.bytes_after = self.file_bytes();
        (r.evidence_rows, r.stat_rows) = self.row_counts().map_err(sql)?;
        Ok(r)
    }

    /// Rewrite the database file without its free pages and empty the
    /// write-ahead log.
    fn vacuum(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch("VACUUM")?;
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
    }

    fn row_counts(&self) -> rusqlite::Result<(u64, u64)> {
        let n = |t: &str| {
            self.conn
                .query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .map(|n| n as u64)
        };
        Ok((n("evidence")?, n("stat")?))
    }

    /// Approximate bytes held by the rows of both tables (payload plus a
    /// fixed per-row overhead), used to scale the file size to a smaller
    /// row set before VACUUM can show the real figure.
    fn row_bytes(&self) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT (SELECT COALESCE(SUM(length(json) + length(hash) + length(bundle) + 24), 0) FROM evidence)
                  + (SELECT COALESCE(SUM(length(realpath) + length(hash) + 64), 0) FROM stat)",
            [],
            |r| r.get(0),
        )
    }

    fn used_bytes(&self) -> rusqlite::Result<i64> {
        let pragma = |p: &str| {
            self.conn
                .query_row(&format!("PRAGMA {p}"), [], |r| r.get::<_, i64>(0))
        };
        Ok((pragma("page_count")? - pragma("freelist_count")?) * pragma("page_size")?)
    }

    fn prune_steps(
        &self,
        o: &DbPruneOptions<'_>,
        now: SystemTime,
        r: &mut DbPrune,
    ) -> Result<(), String> {
        let sql = |e: rusqlite::Error| format!("prune: {e}");
        let cutoff =
            i64::try_from(ns_since_epoch(now) - o.max_age.as_nanos() as i128).unwrap_or(i64::MIN);
        let used = self.used_bytes().map_err(sql)?;
        let rows_before = self.row_bytes().map_err(sql)?;

        // Rows written under a bundle key that has no bundle.
        let keys: Vec<String> = {
            let mut st = self
                .conn
                .prepare("SELECT DISTINCT substr(bundle, 1, instr(bundle || ':', ':') - 1) FROM evidence")
                .map_err(sql)?;
            let rows = st
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(sql)?;
            rows.collect::<rusqlite::Result<_>>().map_err(sql)?
        };
        for k in keys.iter().filter(|k| !o.live_keys.contains(*k)) {
            r.evidence_stranded += self
                .conn
                .execute(
                    "DELETE FROM evidence WHERE substr(bundle, 1, instr(bundle || ':', ':') - 1) = ?1",
                    params![k],
                )
                .map_err(sql)? as u64;
        }
        r.evidence_aged += self
            .conn
            .execute(
                "DELETE FROM evidence WHERE written_at_ns < ?1",
                params![cutoff],
            )
            .map_err(sql)? as u64;

        // Paths that were not written recently, or that no longer exist.
        let rows: Vec<(i64, Vec<u8>, i64)> = {
            let mut st = self
                .conn
                .prepare("SELECT rowid, realpath, written_at_ns FROM stat")
                .map_err(sql)?;
            let it = st
                .query_map([], |row| {
                    // A path is a blob; a malformed row of another type
                    // reads as an empty path, which does not exist.
                    let path = match row.get_ref(1)? {
                        rusqlite::types::ValueRef::Blob(b) | rusqlite::types::ValueRef::Text(b) => {
                            b.to_vec()
                        }
                        _ => Vec::new(),
                    };
                    Ok((row.get(0)?, path, row.get(2)?))
                })
                .map_err(sql)?;
            it.collect::<rusqlite::Result<_>>().map_err(sql)?
        };
        let mut del = self
            .conn
            .prepare("DELETE FROM stat WHERE rowid = ?1")
            .map_err(sql)?;
        for (id, path, written) in rows {
            if written < cutoff {
                r.stat_aged += 1;
            } else {
                let path = Path::new(std::ffi::OsStr::from_bytes(&path));
                // Any error but "not found" (permissions, a slow mount) keeps the row.
                let gone = std::fs::symlink_metadata(path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
                if !gone {
                    continue;
                }
                r.stat_missing += 1;
            }
            del.execute(params![id]).map_err(sql)?;
        }
        drop(del);

        // A dry run estimates the size cap from the file size scaled to the
        // rows that remain. A real run judges the cap on the file after VACUUM
        // instead (see [`Cache::prune`]), which a dry run cannot do.
        if o.dry_run {
            let rows_now = self.row_bytes().map_err(sql)?;
            let estimate = if rows_before > 0 {
                (used as f64 * rows_now as f64 / rows_before as f64) as i64
            } else {
                used
            };
            let max = i64::try_from(o.max_bytes).unwrap_or(i64::MAX);
            let after = self.shrink(estimate, max, r).map_err(sql)?;
            r.bytes_after = u64::try_from(after).unwrap_or(0);
        }
        (r.evidence_rows, r.stat_rows) = self.row_counts().map_err(sql)?;
        Ok(())
    }

    /// Delete the oldest rows so a file of `current` bytes shrinks to about
    /// 90 % of `max`. Returns the estimated size afterwards.
    fn shrink(&self, current: i64, max: i64, r: &mut DbPrune) -> rusqlite::Result<i64> {
        if current <= max || current <= 0 {
            return Ok(current);
        }
        let keep = (max as f64 * SIZE_TARGET / current as f64).clamp(0.0, 1.0);
        for (table, counter) in [
            ("evidence", &mut r.evidence_size),
            ("stat", &mut r.stat_size),
        ] {
            let n: i64 =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            let drop = n - (n as f64 * keep).floor() as i64;
            if drop > 0 {
                *counter += self.conn.execute(
                    &format!(
                        "DELETE FROM {table} WHERE rowid IN
                         (SELECT rowid FROM {table} ORDER BY written_at_ns ASC LIMIT ?1)"
                    ),
                    params![drop],
                )? as u64;
            }
        }
        Ok((current as f64 * keep) as i64)
    }
}

/// Passes [`Cache::prune`] may make to bring the file under its size cap.
const SIZE_PASSES: u32 = 3;
/// Fraction of the size cap a pass aims for, so the cap is not hit again by
/// the next few scans.
const SIZE_TARGET: f64 = 0.9;

/// Inputs to [`Cache::prune`].
pub struct DbPruneOptions<'a> {
    /// Bundle keys that have a bundle (or are in use); `evidence` rows
    /// written under any other key are removed.
    pub live_keys: &'a BTreeSet<String>,
    /// Rows written longer ago than this are removed.
    pub max_age: Duration,
    /// Target ceiling for the database file after VACUUM.
    pub max_bytes: u64,
    pub dry_run: bool,
}

/// What [`Cache::prune`] removed (or, in a dry run, would remove).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct DbPrune {
    pub evidence_stranded: u64,
    pub evidence_aged: u64,
    pub evidence_size: u64,
    pub stat_missing: u64,
    pub stat_aged: u64,
    pub stat_size: u64,
    /// Rows left in each table. In a dry run, the count after the deletes.
    pub evidence_rows: u64,
    pub stat_rows: u64,
    /// Database plus write-ahead log, before and after. In a dry run the
    /// second is an estimate scaled from the rows that would remain.
    pub bytes_before: u64,
    pub bytes_after: u64,
}

impl DbPrune {
    pub fn removed(&self) -> u64 {
        self.evidence_stranded
            + self.evidence_aged
            + self.evidence_size
            + self.stat_missing
            + self.stat_aged
            + self.stat_size
    }
}
