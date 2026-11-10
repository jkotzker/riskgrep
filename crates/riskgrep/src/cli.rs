//! Command-line definition and argument parsing.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Exit status for usage and configuration errors.
pub const EXIT_USAGE: i32 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "riskgrep",
    version,
    about = "Score files 0-100 per sensitive-data category",
    long_about = "Score files 0-100 per sensitive-data category (secrets, biometric embeddings).\n\n\
Exit codes: 0 no --fail-at threshold met; 1 a threshold was met; \
2 a target could not be scanned and --on-error is block (or part of a target's content was \
not read and --on-partial blocks), or `show` refused; 3 usage or configuration error. \
A closed standard output ends the output quietly and keeps the exit code the scan computed."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan files, directories, or standard input
    Scan(ScanArgs),
    /// Record the current findings so later scans treat them as known
    Baseline(BaselineArgs),
    /// Print a file with every match of every rule masked, or a structural
    /// summary of a file that is not text and was scanned whole
    #[command(
        long_about = "Print a file with every match of every rule replaced by a marker \
(`<redacted>`), or, for a file that is not text (tensor files, key stores, archives) and was scanned \
whole, a structural summary: format, tensor data types and shapes, member counts, and scores, never \
names or values.\n\n\
The file is read once and scanned whole by every built-in rule and any rules \
`extra_ruleset_dirs` adds (a repository's only when it is in `trusted_repos`); categories, rulesets, weight overrides, ignore entries, \
baselines, and path allowlists (`path_allowlist`) never narrow the mask. The masked text is scanned again before it is printed. \
Values the rules do not detect are printed.\n\n\
Exit codes: 0 printed; 2 refused, with the reason on standard error and nothing on \
standard output (the file is larger than `[show] max_bytes`, 64 MiB by default, a scan \
failed, timed out, or read only part of it, including a format it cannot read, a rule \
matched without a location, or no rule matched a text file's content, so there is \
nothing to mask); 3 usage or configuration error."
    )]
    Show(ShowArgs),
    /// Git integration: pre-commit check and hook installation
    Git {
        #[command(subcommand)]
        command: GitCommand,
    },
    /// Inspect, compile, and test rulesets
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Maintain the cache of compiled rules and per-file evidence
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Json,
    Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OnError {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OnPartial {
    /// Follow --on-error
    Error,
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Files and directories to scan; `-` reads standard input as `<stdin>`.
    /// With none, the current directory is scanned.
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,
    /// Score only these categories (repeatable)
    #[arg(long = "category", value_name = "C")]
    pub category: Vec<String>,
    /// Enable only these rulesets, by id (repeatable)
    #[arg(long = "ruleset", value_name = "R")]
    pub ruleset: Vec<String>,
    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    pub format: Format,
    /// Exit 1 when a target's score for CATEGORY, rounded to one decimal, is
    /// at or above N (0-100); comma-separated or repeated
    #[arg(
        long = "fail-at",
        value_name = "CAT=N,...",
        value_delimiter = ',',
        value_parser = parse_threshold
    )]
    pub fail_at: Vec<(String, f64)>,
    /// What an unscanned target does to the exit status: `block` exits 2.
    /// Default: block when --fail-at is given, otherwise allow
    #[arg(long, value_enum)]
    pub on_error: Option<OnError>,
    /// What a target with content that was not read (status partial: text
    /// sampled at its ends, a key store or tensor header past its limit,
    /// standard input past 64 MiB, an archive with a member not read whole,
    /// or an `.npz` member that cannot be read) does to the exit status,
    /// unless a score already met --fail-at: `block` exits 2; `error` follows
    /// --on-error
    #[arg(long, value_enum, default_value = "error")]
    pub on_partial: OnPartial,
    /// Whether rulesets' path allowlists apply (gitleaks' global path
    /// allowlist: vendored code, lock files, image and document names), which
    /// the converted secret rules skip. Default: the `path_allowlist` setting
    /// (on)
    #[arg(long, value_enum, value_name = "on|off")]
    pub path_allowlist: Option<Switch>,
    /// Do not read or write the evidence cache
    #[arg(long)]
    pub no_cache: bool,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// The file to show
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Print only lines FIRST to LAST (from 1) of the masked text; masking
    /// keeps the file's line numbers
    #[arg(long, value_name = "FIRST:LAST", value_parser = riskgrep_core::show::parse_lines)]
    pub lines: Option<(u64, u64)>,
    /// Name the ruleset and rule ids that matched in each marker
    /// (`<redacted: ruleset:rule>`) instead of `<redacted>`
    #[arg(long)]
    pub rule_ids: bool,
}

#[derive(Args, Debug)]
pub struct BaselineArgs {
    /// Files and directories to baseline (default: the current directory)
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,
    /// Baseline file to write (default: .riskgrep-baseline.json in the
    /// repository root, else the current directory)
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum GitCommand {
    /// Exit 1 when the staged changes score at or above a `[git] block_at`
    /// threshold
    PreCommit(PreCommitArgs),
    /// Write .git/hooks/pre-commit (honouring core.hooksPath)
    InstallHook(HookArgs),
}

#[derive(Args, Debug)]
pub struct PreCommitArgs {
    /// Score whole staged files instead of only the added lines
    #[arg(long)]
    pub full_files: bool,
}

#[derive(Args, Debug)]
pub struct HookArgs {
    /// Replace an existing hook
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand, Debug)]
pub enum RulesCommand {
    /// List every enabled rule: namespace, rule id, category, weight
    List,
    /// Compile the rulesets the Claude Code hook uses, validate every rule's
    /// post-processors, and store the bundle in the cache (warm-up)
    Compile {
        /// Use the rulesets of this repository's `.riskgrep.toml` as well
        /// (default: the user configuration only, as the hook resolves them
        /// outside a trusted repository)
        #[arg(long)]
        repo: bool,
    },
    /// Run the cases in each embedded ruleset's tests.toml
    Test,
}

#[derive(Subcommand, Debug)]
pub enum CacheCommand {
    /// Remove compiled rules and cache rows that are no longer used: bundles
    /// of other rule sets older than the maximum age, evidence written under
    /// them, rows older than the maximum age, rows for deleted files, and the
    /// oldest rows when the database is over its maximum size
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Report what would be removed and the sizes, and change nothing
    #[arg(long)]
    pub dry_run: bool,
    /// Maximum age in days (default: `[cache] max_age_days`, 30)
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_age_days: Option<u64>,
    /// Maximum database size in megabytes (default: `[cache] max_size_mb`, 256)
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
    pub max_size_mb: Option<u64>,
}

fn parse_threshold(s: &str) -> Result<(String, f64), String> {
    let (cat, n) = s
        .split_once('=')
        .ok_or_else(|| format!("`{s}` is not CATEGORY=N"))?;
    if cat.is_empty() {
        return Err(format!("`{s}` has no category"));
    }
    let n: f64 = n
        .parse()
        .map_err(|_| format!("`{n}` is not a number in `{s}`"))?;
    if !(0.0..=100.0).contains(&n) {
        return Err(format!("threshold {n} in `{s}` is outside 0..=100"));
    }
    Ok((cat.to_string(), n))
}

/// Thresholds by category; a repeated category keeps the last value.
pub fn threshold_map(pairs: &[(String, f64)]) -> BTreeMap<String, f64> {
    pairs.iter().cloned().collect()
}

/// Parse the process arguments. Help and version exit 0; any other parse
/// failure prints clap's message and exits 3.
pub fn parse() -> Cli {
    match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { EXIT_USAGE } else { 0 };
            let _ = e.print();
            std::process::exit(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_parse() {
        assert_eq!(parse_threshold("secret=80"), Ok(("secret".into(), 80.0)));
        assert_eq!(parse_threshold("a=0.5"), Ok(("a".into(), 0.5)));
        assert!(parse_threshold("secret").is_err());
        assert!(parse_threshold("=5").is_err());
        assert!(parse_threshold("secret=x").is_err());
        assert!(parse_threshold("secret=101").is_err());
        assert!(parse_threshold("secret=NaN").is_err());
    }

    #[test]
    fn last_threshold_wins() {
        let m = threshold_map(&[("a".into(), 1.0), ("a".into(), 2.0)]);
        assert_eq!(m["a"], 2.0);
    }
}
