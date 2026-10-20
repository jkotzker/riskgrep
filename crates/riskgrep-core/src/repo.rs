//! Repository-root detection without spawning git, shared by the command
//! line and the Claude Code hook.
//!
//! The nearest ancestor of the working directory (itself included) that holds
//! a `.git` entry, a directory or, for worktrees and submodules, a file. The
//! walk applies the checks of `git rev-parse --show-toplevel` that decide
//! whether a repository's configuration may be trusted:
//!
//! - it does not ascend into a directory listed in `GIT_CEILING_DIRECTORIES`;
//! - it stops before the parent of `$HOME`;
//! - a working directory inside a `.git` directory has no root (git refuses
//!   to report a work tree there);
//! - both the work-tree root and its `.git` entry must be owned by the
//!   effective user, else there is no root (git's `ensure_valid_ownership`
//!   without a `safe.directory` entry), so a repository planted by another
//!   user never supplies configuration;
//! - it does not cross a filesystem boundary (a parent on another device than
//!   the starting directory) unless `GIT_DISCOVERY_ACROSS_FILESYSTEM` is set
//!   to a true value.
//!
//! Not replicated: `safe.directory` entries, `core.worktree`, and git's
//! validation that a `.git` entry is really a repository.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Everything the search reads from the environment, explicit for tests.
pub struct Search<'a> {
    /// Directories not to ascend into (canonical).
    pub ceilings: &'a [PathBuf],
    /// The parent of `$HOME` (canonical), where the walk stops.
    pub home_parent: Option<&'a Path>,
    /// The effective user id.
    pub uid: u32,
    /// `GIT_DISCOVERY_ACROSS_FILESYSTEM` is true.
    pub across_filesystems: bool,
    /// The device of a directory.
    pub dev_of: &'a dyn Fn(&Path) -> Option<u64>,
}

/// The search with every input explicit; see the module documentation.
pub fn find_repo_root(cwd: &Path, search: &Search<'_>) -> Option<PathBuf> {
    let cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    if cwd.components().any(|c| c.as_os_str() == ".git") {
        return None;
    }
    let start_dev = (search.dev_of)(&cwd);
    for dir in cwd.ancestors() {
        if dir != cwd {
            if !search.across_filesystems && (search.dev_of)(dir) != start_dev {
                break;
            }
            if search.ceilings.iter().any(|c| c == dir) {
                break;
            }
        }
        if search.home_parent == Some(dir) {
            break;
        }
        if let Ok(entry) = fs::symlink_metadata(dir.join(".git")) {
            let owned =
                entry.uid() == search.uid && fs::metadata(dir).is_ok_and(|m| m.uid() == search.uid);
            return owned.then(|| dir.to_path_buf());
        }
    }
    None
}

/// [`find_repo_root`] with the ceilings from `GIT_CEILING_DIRECTORIES`, the
/// stop from `$HOME`, `GIT_DISCOVERY_ACROSS_FILESYSTEM`, and the effective
/// user id of this process.
pub fn repo_root_from_env(cwd: &Path) -> Option<PathBuf> {
    let canon = |p: PathBuf| fs::canonicalize(&p).unwrap_or(p);
    let ceilings: Vec<PathBuf> = std::env::var_os("GIT_CEILING_DIRECTORIES")
        .map(|v| std::env::split_paths(&v).map(canon).collect())
        .unwrap_or_default();
    let home_parent = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(canon)
        .and_then(|h| h.parent().map(Path::to_path_buf));
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let across_filesystems =
        std::env::var("GIT_DISCOVERY_ACROSS_FILESYSTEM").is_ok_and(|v| is_true(&v));
    find_repo_root(
        cwd,
        &Search {
            ceilings: &ceilings,
            home_parent: home_parent.as_deref(),
            uid,
            across_filesystems,
            dev_of: &|p| fs::metadata(p).ok().map(|m| m.dev()),
        },
    )
}

/// Git's `git_env_bool`: `true`, `yes`, `on` (any case), or any non-zero
/// integer.
fn is_true(v: &str) -> bool {
    if matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "on") {
        return true;
    }
    v.trim().parse::<i64>().is_ok_and(|n| n != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn top() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    fn same_dev(_: &Path) -> Option<u64> {
        Some(1)
    }

    fn find(
        cwd: &Path,
        ceilings: &[PathBuf],
        home_parent: Option<&Path>,
        uid: u32,
    ) -> Option<PathBuf> {
        find_repo_root(
            cwd,
            &Search {
                ceilings,
                home_parent,
                uid,
                across_filesystems: false,
                dev_of: &same_dev,
            },
        )
    }

    #[test]
    fn walks_up_for_a_git_entry() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(find(&sub, &[], None, uid()), None);
        fs::create_dir(top.join(".git")).unwrap();
        assert_eq!(find(&sub, &[], None, uid()), Some(top.clone()));
    }

    #[test]
    fn a_git_file_counts() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::write(top.join("a/.git"), "gitdir: elsewhere\n").unwrap();
        assert_eq!(find(&sub, &[], None, uid()), Some(top.join("a")));
    }

    #[test]
    fn ceilings_hide_what_is_above_them() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(top.join(".git")).unwrap();
        assert_eq!(find(&sub, &[top.join("a")], None, uid()), None);
        // The starting directory is always examined.
        fs::create_dir(sub.join(".git")).unwrap();
        assert_eq!(
            find(&sub, std::slice::from_ref(&sub), None, uid()),
            Some(sub.clone())
        );
    }

    #[test]
    fn the_parent_of_home_is_a_stop() {
        let (_d, top) = top();
        let home = top.join("users/me");
        let sub = home.join("proj");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(top.join(".git")).unwrap();
        assert_eq!(find(&sub, &[], home.parent(), uid()), None);
        assert_eq!(find(&sub, &[], None, uid()), Some(top));
    }

    #[test]
    fn a_working_directory_inside_git_has_no_root() {
        let (_d, top) = top();
        let inside = top.join(".git/hooks");
        fs::create_dir_all(&inside).unwrap();
        assert_eq!(find(&inside, &[], None, uid()), None);
        assert_eq!(find(&top.join(".git"), &[], None, uid()), None);
    }

    #[test]
    fn ownership_is_required_of_root_and_git_entry() {
        let (_d, top) = top();
        let sub = top.join("a");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(top.join(".git")).unwrap();
        // Both are owned by the real uid; under a different effective uid
        // neither is, so there is no root. A mixed case (one owned, one not)
        // needs two users; the code requires both (`&&`).
        assert_eq!(find(&sub, &[], None, uid() + 1), None);
        assert_eq!(find(&sub, &[], None, uid()), Some(top));
    }

    #[test]
    fn a_filesystem_boundary_stops_the_walk() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(top.join(".git")).unwrap();
        // `top` is on another device than the starting directory.
        let boundary = top.clone();
        let dev = move |p: &Path| Some(if p == boundary { 2 } else { 1 });
        let search = |across| Search {
            ceilings: &[],
            home_parent: None,
            uid: uid(),
            across_filesystems: across,
            dev_of: &dev,
        };
        assert_eq!(find_repo_root(&sub, &search(false)), None);
        assert_eq!(find_repo_root(&sub, &search(true)), Some(top));
    }

    #[test]
    fn git_boolean_spellings() {
        for v in ["1", "2", "-1", "true", "TRUE", "yes", "On"] {
            assert!(is_true(v), "{v}");
        }
        for v in ["0", "false", "", "no", "off", "x"] {
            assert!(!is_true(v), "{v}");
        }
    }
}
