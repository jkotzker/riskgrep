//! `riskgrep show`: print a file masked (see [`riskgrep_core::show`]).

use crate::cli::ShowArgs;
use crate::{stdout_result, CliError};
use riskgrep_core::config;
use riskgrep_core::show::{show_file, Marker, ShowOptions, Shown};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

/// Exit status when the view is refused.
pub const EXIT_REFUSED: i32 = 2;

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
            let name = crate::git::display(a.file.as_os_str().as_bytes());
            eprintln!("riskgrep show: {name}: not shown: {r}");
            return Ok(EXIT_REFUSED);
        }
    };
    let mut out = std::io::stdout().lock();
    stdout_result(out.write_all(&bytes))?;
    stdout_result(out.flush())?;
    Ok(0)
}
