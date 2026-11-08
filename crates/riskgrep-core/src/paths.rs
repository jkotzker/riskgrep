//! Cache locations, private-directory handling, and path helpers shared by
//! the agent integrations.

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

/// `p` made absolute against `cwd` when it is relative.
pub fn absolute(p: &str, cwd: &Path) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// `p` with a leading `~` or `~/` replaced by `home`, untrimmed. `~user` is
/// left as it is, as is `~` when `home` is unset or empty.
pub fn expand_tilde(p: &str, home: Option<&str>) -> String {
    let rest = match p.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
        _ => return p.to_string(),
    };
    match home.filter(|h| !h.is_empty()) {
        Some(home) => format!("{home}{rest}"),
        None => p.to_string(),
    }
}

/// `path` unless it names a directory or nothing, which a read fails on. A
/// path that exists but cannot be inspected is kept: the scan reports why.
pub fn readable_file(path: PathBuf) -> Option<PathBuf> {
    match fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => None,
        Ok(_) => Some(path),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            None
        }
        Err(_) => Some(path),
    }
}
