//! The `scan` and `baseline` commands.

use crate::cli::{threshold_map, BaselineArgs, Format, OnError, ScanArgs};
use crate::{text, CliError};
use riskgrep_core::config::{self, Config, Mode, Overrides};
use riskgrep_core::scanner::resolve_rulesets;
use riskgrep_core::suppress::{Baseline, IgnoreRules};
use riskgrep_core::{Category, Report, RiskGrep, TargetStatus};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const STDIN_NAME: &str = "<stdin>";
/// Standard input beyond this many bytes is not read.
const STDIN_MAX: u64 = 64 << 20;

pub const EXIT_OK: i32 = 0;
pub const EXIT_THRESHOLD: i32 = 1;
pub const EXIT_UNSCANNED: i32 = 2;

/// `git rev-parse --show-toplevel` in the working directory; `None` when git
/// is missing or the directory is not in a work tree. Used where the exact
/// work tree matters (the pre-commit hook, which runs git anyway).
pub fn repo_root_git() -> Option<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim_end_matches('\n');
    (!s.is_empty()).then(|| PathBuf::from(s))
}

/// The repository root of the working directory, found without spawning git
/// (a spawn costs about 7 ms, a third of a small scan); see
/// [`riskgrep_core::repo`] for the rules. With `GIT_DIR` or `GIT_WORK_TREE`
/// set the layout is not discoverable by walking up, so git is asked.
pub fn repo_root() -> Option<PathBuf> {
    if std::env::var_os("GIT_DIR").is_some() || std::env::var_os("GIT_WORK_TREE").is_some() {
        return repo_root_git();
    }
    riskgrep_core::repo::repo_root_from_env(&std::env::current_dir().ok()?)
}

/// Load the layered configuration for the CLI.
pub fn load_config(overrides: Overrides) -> Result<(Config, Option<PathBuf>), CliError> {
    let root = repo_root();
    let cfg = config::load(Mode::Cli, root.as_deref(), overrides)?;
    Ok((cfg, root))
}

/// Category names scored by the rulesets this configuration enables, ignoring
/// any category filter.
fn known_categories(cfg: &Config, root: Option<&Path>) -> Result<BTreeSet<String>, CliError> {
    let mut all = cfg.clone();
    all.categories = None;
    let cwd = std::env::current_dir().ok();
    let base = root.map(Path::to_path_buf).or(cwd);
    let sets = resolve_rulesets(&all, base.as_deref())?;
    Ok(sets
        .iter()
        .flat_map(|r| r.categories.iter().map(|c| c.0.clone()))
        .collect())
}

fn check_known<'a>(
    known: &BTreeSet<String>,
    names: impl Iterator<Item = &'a String>,
) -> Result<(), CliError> {
    for n in names {
        if !known.contains(n) {
            let list: Vec<&str> = known.iter().map(String::as_str).collect();
            return Err(CliError(format!(
                "unknown category `{n}` (known: {})",
                list.join(", ")
            )));
        }
    }
    Ok(())
}

fn read_stdin() -> io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    io::stdin()
        .lock()
        .take(STDIN_MAX + 1)
        .read_to_end(&mut buf)?;
    let truncated = buf.len() as u64 > STDIN_MAX;
    buf.truncate(STDIN_MAX as usize);
    Ok((buf, truncated))
}

pub fn scan(a: ScanArgs) -> Result<i32, CliError> {
    let thresholds = threshold_map(&a.fail_above);
    let on_error = a.on_error.unwrap_or(if thresholds.is_empty() {
        OnError::Allow
    } else {
        OnError::Block
    });
    let overrides = Overrides {
        categories: (!a.category.is_empty())
            .then(|| a.category.iter().cloned().map(Category).collect()),
        rulesets: (!a.ruleset.is_empty()).then(|| a.ruleset.clone()),
        no_cache: a.no_cache,
    };
    let (cfg, root) = load_config(overrides)?;
    let known = known_categories(&cfg, root.as_deref())?;
    check_known(&known, a.category.iter().chain(thresholds.keys()))?;

    let stdin = a.paths.iter().any(|p| p == "-");
    let mut paths: Vec<PathBuf> = a
        .paths
        .iter()
        .filter(|p| *p != "-")
        .map(PathBuf::from)
        .collect();
    if paths.is_empty() && !stdin {
        paths.push(PathBuf::from("."));
    }

    let mut rg = RiskGrep::new(cfg, root.as_deref())?;
    let mut parts: Vec<Report> = Vec::new();
    if stdin {
        let (bytes, truncated) = read_stdin()?;
        let mut r = rg.scan_bytes(STDIN_NAME, &bytes);
        if truncated {
            if let Some(t) = r.targets.first_mut() {
                if t.status == TargetStatus::Scanned {
                    t.status = TargetStatus::Partial {
                        not_read: format!("standard input beyond {STDIN_MAX} bytes"),
                    };
                    r.summary.scanned -= 1;
                    r.summary.partial += 1;
                }
            }
        }
        parts.push(r);
    }
    if !paths.is_empty() {
        parts.push(rg.scan_paths(&paths));
    }
    let report = merge(parts);

    let mut stdout = io::stdout().lock();
    let written = match a.format {
        Format::Json => serde_json::to_writer_pretty(&mut stdout, &report)
            .map_err(io::Error::from)
            .and_then(|()| writeln!(stdout)),
        Format::Text => stdout.write_all(text::render(&report).as_bytes()),
    };
    let code = exit_code(&report, &thresholds, on_error);
    match written.and_then(|()| stdout.flush()) {
        // The reader closed the pipe on purpose: no message, and the exit
        // code the scan computed still applies (a gate must not pass).
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => std::process::exit(code),
        r => r?,
    }
    Ok(code)
}

fn merge(mut parts: Vec<Report>) -> Report {
    if parts.len() == 1 {
        return parts.remove(0);
    }
    let (version, bundle) = (
        parts[0].riskgrep_version.clone(),
        parts[0].rules_bundle.clone(),
    );
    let targets = parts.into_iter().flat_map(|r| r.targets).collect();
    Report::from_targets(&version, &bundle, targets)
}

/// 1 when a score is strictly above its threshold, else 2 when a target is
/// unscanned and `on_error` blocks, else 0.
pub fn exit_code(report: &Report, thresholds: &BTreeMap<String, f64>, on_error: OnError) -> i32 {
    let exceeded = report.targets.iter().any(|t| {
        thresholds
            .iter()
            .any(|(cat, n)| t.scores.get(&Category(cat.clone())).is_some_and(|s| s > n))
    });
    if exceeded {
        return EXIT_THRESHOLD;
    }
    if on_error == OnError::Block && report.summary.unscanned > 0 {
        return EXIT_UNSCANNED;
    }
    EXIT_OK
}

/// The path suppression and baselines use for a target: its canonical path
/// relative to the repository root (else the working directory).
fn relative_to(base: Option<&Path>, target: &str) -> String {
    let real = std::fs::canonicalize(target).unwrap_or_else(|_| PathBuf::from(target));
    base.and_then(|b| real.strip_prefix(b).ok())
        .filter(|r| !r.as_os_str().is_empty())
        .unwrap_or(&real)
        .display()
        .to_string()
}

pub fn baseline(a: BaselineArgs) -> Result<i32, CliError> {
    let (mut cfg, root) = load_config(Overrides::default())?;
    // Existing ignores and baselines must not hide findings from the new one.
    // `Mode::ClaudeCode` with no trusted repositories loads no baseline.
    cfg.ignore = IgnoreRules::default();
    cfg.mode = Mode::ClaudeCode;
    cfg.trusted_repos.clear();

    let paths: Vec<PathBuf> = if a.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        a.paths.iter().map(PathBuf::from).collect()
    };
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let base = root
        .as_deref()
        .map(canon)
        .or_else(|| std::env::current_dir().ok().map(|d| canon(&d)));
    let out = match &a.out {
        Some(p) => p.clone(),
        None => root
            .clone()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(config::BASELINE_FILE),
    };

    let mut rg = RiskGrep::new(cfg, root.as_deref())?;
    let report = rg.scan_paths(&paths);
    let b = Baseline::create(&report.targets, |t| relative_to(base.as_deref(), t))?;
    b.save(&out)?;
    if report.summary.unscanned > 0 {
        eprintln!(
            "riskgrep: {} target(s) could not be scanned and are not in the baseline",
            report.summary.unscanned
        );
    }
    if root.is_none() {
        eprintln!("riskgrep: not in a git repository: scans apply a baseline only inside one");
    }
    outln!(
        "wrote {} fingerprint{} to {}",
        b.fingerprints.len(),
        if b.fingerprints.len() == 1 { "" } else { "s" },
        out.display()
    )?;
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::TargetReport;

    fn t(status: TargetStatus, secret: f64) -> TargetReport {
        TargetReport {
            target: "x".into(),
            status,
            scores: BTreeMap::from([(Category("secret".into()), secret)]),
            evidence: vec![],
            suppressed: 0,
        }
    }

    fn th(n: f64) -> BTreeMap<String, f64> {
        BTreeMap::from([("secret".to_string(), n)])
    }

    #[test]
    fn exit_codes() {
        let un = TargetStatus::Unscanned { reason: "r".into() };
        let r = Report::from_targets("0", "b", vec![t(TargetStatus::Scanned, 80.0)]);
        assert_eq!(exit_code(&r, &th(80.0), OnError::Block), 0);
        assert_eq!(exit_code(&r, &th(79.9), OnError::Block), 1);
        assert_eq!(exit_code(&r, &BTreeMap::new(), OnError::Block), 0);
        let r = Report::from_targets("0", "b", vec![t(un.clone(), 0.0)]);
        assert_eq!(exit_code(&r, &th(80.0), OnError::Block), 2);
        assert_eq!(exit_code(&r, &th(80.0), OnError::Allow), 0);
        let r = Report::from_targets("0", "b", vec![t(un, 0.0), t(TargetStatus::Scanned, 90.0)]);
        assert_eq!(exit_code(&r, &th(80.0), OnError::Block), 1);
    }

    #[test]
    fn relative_paths() {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let inside = base.join("riskgrep-no-such-file");
        assert_eq!(
            relative_to(Some(&base), inside.to_str().unwrap()),
            "riskgrep-no-such-file"
        );
        assert_eq!(relative_to(None, "/x/y"), "/x/y");
    }
}
