//! The `cache prune` command and the daily automatic prune.

use crate::cli::{CacheCommand, PruneArgs};
use crate::rules::{enabled, hook_rulesets};
use crate::scan::repo_root;
use crate::CliError;
use riskgrep_core::bundle::bundle_key;
use riskgrep_core::config::{self, Config, Mode, Overrides};
use riskgrep_core::paths::cache_dir;
use riskgrep_core::prune::{due, mark, prune, PruneOptions, PruneReport};
use riskgrep_core::ruleset::Ruleset;
use riskgrep_core::scanner::resolve_rulesets;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub fn run(cmd: CacheCommand) -> Result<i32, CliError> {
    match cmd {
        CacheCommand::Prune(a) => prune_command(a),
    }
}

fn key_of(sets: &[Ruleset]) -> String {
    let refs: Vec<&Ruleset> = sets.iter().collect();
    bundle_key(&refs)
}

/// The configuration and the bundle keys that stay however old they are:
/// those of the rulesets this command line resolves here, of the Claude Code
/// hook outside a trusted repository, and of the hook in this repository.
fn protected() -> Result<(Config, BTreeSet<String>), CliError> {
    let (cfg, sets) = enabled()?;
    let mut keys = BTreeSet::from([key_of(&sets), key_of(&hook_rulesets()?)]);
    if let Some(root) = repo_root() {
        let hook = config::load(Mode::ClaudeCode, Some(&root), Overrides::default())?;
        keys.insert(key_of(&resolve_rulesets(&hook, Some(&root))?));
    }
    Ok((cfg, keys))
}

fn prune_command(a: PruneArgs) -> Result<i32, CliError> {
    let dir = cache_dir().ok_or_else(|| CliError("no absolute cache directory".into()))?;
    if !dir.is_dir() {
        outln!(
            "Cache directory {} does not exist; nothing to prune",
            dir.display()
        )?;
        return Ok(0);
    }
    let (cfg, protected_keys) = protected()?;
    let max_age_days = a.max_age_days.unwrap_or(cfg.cache.max_age_days);
    let max_size_mb = a.max_size_mb.unwrap_or(cfg.cache.max_size_mb);
    let now = SystemTime::now();
    let report = prune(
        &dir,
        &PruneOptions {
            max_age: Duration::from_secs(max_age_days.saturating_mul(86_400)),
            max_db_bytes: max_size_mb.saturating_mul(1_000_000),
            protected_keys,
            dry_run: a.dry_run,
        },
        now,
    )
    .map_err(CliError)?;
    if !a.dry_run {
        // An explicit prune stands in for the daily one.
        let _ = mark(&dir, now);
    }
    for line in render(&dir, &report, max_age_days, max_size_mb) {
        outln!("{line}")?;
    }
    Ok(0)
}

/// Prune at most once a day. The check is one `stat` of the marker file, so a
/// scan that has nothing to do pays nothing else. The marker is written
/// before pruning starts, which also keeps a second process from pruning at
/// the same time. Never run by the Claude Code hook. A failure is one line on
/// standard error and does not change the exit status.
pub fn auto_prune() {
    let Some(dir) = cache_dir() else { return };
    let now = SystemTime::now();
    if !due(&dir, now) || !dir.is_dir() {
        return;
    }
    // A configuration that does not resolve is reported by the scan itself.
    let Ok((cfg, protected_keys)) = protected() else {
        return;
    };
    if mark(&dir, now).is_err() {
        return;
    }
    let opts = PruneOptions {
        max_age: cfg.cache.max_age(),
        max_db_bytes: cfg.cache.max_db_bytes(),
        protected_keys,
        dry_run: false,
    };
    if let Err(e) = prune(&dir, &opts, now) {
        eprintln!("riskgrep: cache prune: {e}");
    }
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1_000_000 => format!("{:.1} MB", b as f64 / 1e6),
        b if b >= 1_000 => format!("{:.1} kB", b as f64 / 1e3),
        b => format!("{b} B"),
    }
}

fn render(dir: &Path, r: &PruneReport, max_age_days: u64, max_size_mb: u64) -> Vec<String> {
    let mut out = vec![
        format!("Cache directory: {}", dir.display()),
        if r.dry_run {
            "Dry run: nothing was removed. A real run would remove:".into()
        } else {
            "Removed:".into()
        },
        format!(
            "  compiled bundles: {} ({}); {} kept ({})",
            r.bundles_removed,
            size(r.bundle_bytes_removed),
            r.bundles_kept,
            size(r.bundle_bytes_kept)
        ),
    ];
    match &r.database {
        None => out.push("  evidence database: none".into()),
        Some(d) => {
            out.push(format!(
                "  evidence rows: {} ({} under a bundle that is gone, {} older than {max_age_days} days, {} over the {max_size_mb} MB limit); {} kept",
                d.evidence_stranded + d.evidence_aged + d.evidence_size,
                d.evidence_stranded,
                d.evidence_aged,
                d.evidence_size,
                d.evidence_rows
            ));
            out.push(format!(
                "  file rows: {} ({} for files that no longer exist, {} older than {max_age_days} days, {} over the limit); {} kept",
                d.stat_missing + d.stat_aged + d.stat_size,
                d.stat_missing,
                d.stat_aged,
                d.stat_size,
                d.stat_rows
            ));
            out.push(format!(
                "  evidence database: {} -> {}{}",
                size(d.bytes_before),
                size(d.bytes_after),
                if r.dry_run { " (estimate)" } else { "" }
            ));
        }
    }
    out
}
