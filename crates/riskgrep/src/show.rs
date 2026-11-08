//! `riskgrep show`: print a file masked (see [`riskgrep_core::show`]).

use crate::cli::ShowArgs;
use crate::{stdout_result, CliError};
use riskgrep_core::config;
use riskgrep_core::show::{show_file, Marker, ShowOptions, Shown};
use std::io::Write;

/// Exit status when the view is refused.
pub const EXIT_REFUSED: i32 = 2;

/// `s` with control characters written as escapes, so a file name cannot
/// move the cursor or hide text in the terminal.
fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn show(a: ShowArgs) -> Result<i32, CliError> {
    let root = crate::scan::repo_root();
    let cfg = config::load_show(root.as_deref())?;
    let opts = ShowOptions {
        marker: if a.rule_ids {
            Marker::RuleIds
        } else {
            Marker::Fixed
        },
        lines: a.lines,
    };
    let bytes = match show_file(&cfg, &a.file, &opts, riskgrep_core::paths::cache_dir()) {
        Ok(Shown::Masked { text, .. }) => text,
        Ok(Shown::Summary(s)) => s.into_bytes(),
        Err(r) => {
            let name = escape_controls(&a.file.display().to_string());
            eprintln!("riskgrep show: {name}: not shown: {r}");
            return Ok(EXIT_REFUSED);
        }
    };
    let mut out = std::io::stdout().lock();
    stdout_result(out.write_all(&bytes))?;
    stdout_result(out.flush())?;
    Ok(0)
}
