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
Exit codes: 0 nothing above a --fail-above threshold; 1 a threshold was exceeded; \
2 a target could not be scanned and --on-error is block; 3 usage or configuration error."
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
    /// Inspect, compile, and test rulesets
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
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
    /// Exit 1 when a target's unrounded score for CATEGORY is strictly greater
    /// than N (0-100); comma-separated or repeated
    #[arg(
        long = "fail-above",
        value_name = "CAT=N,...",
        value_delimiter = ',',
        value_parser = parse_threshold
    )]
    pub fail_above: Vec<(String, f64)>,
    /// What an unscanned target does to the exit status: `block` exits 2.
    /// Default: block when --fail-above is given, otherwise allow
    #[arg(long, value_enum)]
    pub on_error: Option<OnError>,
    /// Do not read or write the evidence cache
    #[arg(long)]
    pub no_cache: bool,
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
pub enum RulesCommand {
    /// List every enabled rule: namespace, rule id, category, weight
    List,
    /// Compile all enabled rulesets and validate every rule's post-processors
    Compile,
    /// Run the cases in each embedded ruleset's tests.toml
    Test,
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
