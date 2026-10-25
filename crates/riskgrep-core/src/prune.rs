//! Pruning of the cache directory: compiled bundles and evidence rows.
//!
//! Pruning is run by the command line (`riskgrep cache prune`, and at most
//! once a day from `riskgrep scan` and the git pre-commit hook). The Claude
//! Code hook never calls it: its cached-read path stays read-only and the
//! daily check, a single `stat` of the marker, lives in the callers.

use crate::bundle::{prune_bundles, BundlePrune};
use crate::cache::{Cache, DbPrune, DbPruneOptions};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Marker file in the cache directory; its modification time is the time of
/// the last automatic prune.
pub const MARKER: &str = "last-prune";
/// Automatic pruning runs when the marker is at least this old.
pub const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

pub struct PruneOptions {
    /// Bundles and rows older than this are removed.
    pub max_age: Duration,
    /// Target ceiling for the evidence database file.
    pub max_db_bytes: u64,
    /// Bundle keys in use by a configuration the caller knows about: their
    /// bundle files and rows are kept however old they are.
    pub protected_keys: BTreeSet<String>,
    /// Report what would go and change nothing.
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PruneReport {
    pub dry_run: bool,
    pub bundles_removed: u64,
    pub bundle_files_removed: u64,
    pub bundle_bytes_removed: u64,
    pub bundles_kept: u64,
    pub bundle_bytes_kept: u64,
    /// `None` when the cache directory holds no database.
    pub database: Option<DbPrune>,
}

impl PruneReport {
    fn new(dry_run: bool, b: &BundlePrune, database: Option<DbPrune>) -> PruneReport {
        PruneReport {
            dry_run,
            bundles_removed: b.removed_keys.len() as u64,
            bundle_files_removed: b.removed_files,
            bundle_bytes_removed: b.removed_bytes,
            bundles_kept: b.kept_keys.len() as u64,
            bundle_bytes_kept: b.kept_bytes,
            database,
        }
    }
}

/// True when the marker is missing or at least [`INTERVAL`] old. One `stat`;
/// a marker dated further ahead than [`INTERVAL`] (clock change) is stale.
pub fn due(cache_dir: &Path, now: SystemTime) -> bool {
    let Ok(modified) = std::fs::metadata(cache_dir.join(MARKER)).and_then(|m| m.modified()) else {
        return true;
    };
    match now.duration_since(modified) {
        Ok(age) => age >= INTERVAL,
        Err(ahead) => ahead.duration() > INTERVAL,
    }
}

/// Record a prune now: create the marker (mode 0600) or refresh its time.
pub fn mark(cache_dir: &Path, now: SystemTime) -> io::Result<()> {
    crate::paths::ensure_private_dir(cache_dir)?;
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(cache_dir.join(MARKER))?;
    f.set_modified(now)
}

/// Prune the bundles and the evidence database in `cache_dir`.
pub fn prune(cache_dir: &Path, o: &PruneOptions, now: SystemTime) -> Result<PruneReport, String> {
    let b = prune_bundles(cache_dir, &o.protected_keys, o.max_age, now, o.dry_run)
        .map_err(|e| format!("bundles: {e}"))?;
    let live: BTreeSet<String> = b.kept_keys.union(&o.protected_keys).cloned().collect();
    // A database from another version is rebuilt by the next scan; pruning
    // it would only rebuild it earlier, and a dry run must not.
    let database = if Cache::schema_matches(cache_dir) {
        let cache = Cache::open_existing(cache_dir)
            .ok_or_else(|| "the evidence database could not be opened".to_string())?;
        Some(cache.prune(
            &DbPruneOptions {
                live_keys: &live,
                max_age: o.max_age,
                max_bytes: o.max_db_bytes,
                dry_run: o.dry_run,
            },
            now,
        )?)
    } else {
        None
    };
    Ok(PruneReport::new(o.dry_run, &b, database))
}
