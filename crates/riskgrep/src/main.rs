//! `riskgrep`: scan files for sensitive data and score them per category.

/// `println!` returning `Result<(), CliError>`: a closed standard output
/// ends the process quietly (see [`stdout_result`]).
macro_rules! outln {
    ($($arg:tt)*) => {
        $crate::stdout_result(::std::io::Write::write_fmt(
            &mut ::std::io::stdout().lock(),
            format_args!("{}\n", format_args!($($arg)*)),
        ))
    };
}

mod cli;
mod git;
mod rules;
mod scan;
mod spec;
mod text;

use std::fmt;

/// A failure reported on stderr with exit status 3.
#[derive(Debug)]
pub struct CliError(pub String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<riskgrep_core::config::ConfigError> for CliError {
    fn from(e: riskgrep_core::config::ConfigError) -> Self {
        CliError(e.0)
    }
}

impl From<riskgrep_core::RiskGrepError> for CliError {
    fn from(e: riskgrep_core::RiskGrepError) -> Self {
        CliError(e.0)
    }
}

impl From<riskgrep_core::suppress::SuppressError> for CliError {
    fn from(e: riskgrep_core::suppress::SuppressError) -> Self {
        CliError(e.0)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError(e.to_string())
    }
}

/// The result of a write to standard output. A closed pipe (`riskgrep
/// rules list | head -1`) means the reader stopped on purpose: the process
/// exits at once with status 0 and prints nothing. Other errors are
/// returned.
pub fn stdout_result<T>(r: std::io::Result<T>) -> Result<T, CliError> {
    match r {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        r => Ok(r?),
    }
}

fn main() {
    let args = cli::parse();
    let code = match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("riskgrep: {e}");
            cli::EXIT_USAGE
        }
    };
    std::process::exit(code);
}

fn run(args: cli::Cli) -> Result<i32, CliError> {
    match args.command {
        cli::Command::Scan(a) => scan::scan(a),
        cli::Command::Baseline(a) => scan::baseline(a),
        cli::Command::Git { command } => git::run(command),
        cli::Command::Rules { command } => rules::run(command),
    }
}
