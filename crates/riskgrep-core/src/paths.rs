//! Cache locations and private-directory handling.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Per-user cache directory: `~/Library/Caches/riskgrep` on macOS,
/// `$XDG_CACHE_HOME/riskgrep` or `~/.cache/riskgrep` elsewhere. `None` when no
/// absolute location can be derived; the result is never a relative path.
pub fn cache_dir() -> Option<PathBuf> {
    cache_dir_for(
        std::env::var_os("HOME"),
        std::env::var_os("XDG_CACHE_HOME"),
        cfg!(target_os = "macos"),
    )
}

/// Pure form of [`cache_dir`] taking the environment values explicitly.
pub fn cache_dir_for(
    home: Option<OsString>,
    xdg: Option<OsString>,
    macos: bool,
) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    if !macos {
        if let Some(x) = absolute(xdg) {
            return Some(x.join("riskgrep"));
        }
    }
    let home = absolute(home)?;
    Some(if macos {
        home.join("Library/Caches/riskgrep")
    } else {
        home.join(".cache/riskgrep")
    })
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
