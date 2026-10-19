//! Cache locations and private-directory handling.

use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Per-user cache directory: `~/Library/Caches/riskgrep` on macOS,
/// `$XDG_CACHE_HOME/riskgrep` or `~/.cache/riskgrep` elsewhere.
pub fn cache_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        return home.join("Library/Caches/riskgrep");
    }
    match std::env::var_os("XDG_CACHE_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x).join("riskgrep"),
        _ => home.join(".cache/riskgrep"),
    }
}

/// Create `p` (and missing parents) with mode 0700; tighten an existing
/// directory whose mode grants group or other access.
pub fn ensure_private_dir(p: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(p)?;
    let mode = fs::metadata(p)?.permissions().mode();
    if mode & 0o077 != 0 {
        fs::set_permissions(p, Permissions::from_mode(0o700))?;
    }
    Ok(())
}
