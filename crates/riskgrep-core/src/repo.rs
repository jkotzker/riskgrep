//! Repository-root detection without spawning git, shared by the command
//! line and the Claude Code hook.
//!
//! The nearest ancestor of the working directory (itself included) that holds
//! a `.git` entry, a directory or, for worktrees and submodules, a file. The
//! walk is deliberately no laxer than `git rev-parse --show-toplevel`:
//!
//! - it does not ascend into a directory listed in `GIT_CEILING_DIRECTORIES`;
//! - it stops before the parent of `$HOME`;
//! - a working directory inside a `.git` directory has no root (git refuses
//!   to report a work tree there);
//! - the root, or its `.git` entry, must be owned by the effective user,
//!   else there is no root (the analogue of git's `safe.directory` check),
//!   so a repository planted by another user never supplies configuration.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The search with every input explicit; see the module documentation.
/// `ceilings` and `home_parent` are compared against canonical directories.
pub fn find_repo_root(
    cwd: &Path,
    ceilings: &[PathBuf],
    home_parent: Option<&Path>,
    uid: u32,
) -> Option<PathBuf> {
    let cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    if cwd.components().any(|c| c.as_os_str() == ".git") {
        return None;
    }
    for dir in cwd.ancestors() {
        if dir != cwd && ceilings.iter().any(|c| c == dir) {
            break;
        }
        if home_parent == Some(dir) {
            break;
        }
        let dot_git = dir.join(".git");
        if let Ok(entry) = fs::symlink_metadata(&dot_git) {
            let owned = entry.uid() == uid || fs::metadata(dir).is_ok_and(|m| m.uid() == uid);
            return owned.then(|| dir.to_path_buf());
        }
    }
    None
}

/// [`find_repo_root`] with the ceilings from `GIT_CEILING_DIRECTORIES`, the
/// stop from `$HOME`, and the effective user id of this process.
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
    find_repo_root(cwd, &ceilings, home_parent.as_deref(), uid)
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

    #[test]
    fn walks_up_for_a_git_entry() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(find_repo_root(&sub, &[], None, uid()), None);
        fs::create_dir(top.join(".git")).unwrap();
        assert_eq!(find_repo_root(&sub, &[], None, uid()), Some(top.clone()));
    }

    #[test]
    fn a_git_file_counts() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::write(top.join("a/.git"), "gitdir: elsewhere\n").unwrap();
        assert_eq!(find_repo_root(&sub, &[], None, uid()), Some(top.join("a")));
    }

    #[test]
    fn ceilings_hide_what_is_above_them() {
        let (_d, top) = top();
        let sub = top.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(top.join(".git")).unwrap();
        assert_eq!(find_repo_root(&sub, &[top.join("a")], None, uid()), None);
        // The starting directory is always examined.
        fs::create_dir(sub.join(".git")).unwrap();
        assert_eq!(
            find_repo_root(&sub, std::slice::from_ref(&sub), None, uid()),
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
        assert_eq!(
            find_repo_root(&sub, &[], home.parent(), uid()),
            None,
            "a repository above $HOME's parent is not found"
        );
        assert_eq!(find_repo_root(&sub, &[], None, uid()), Some(top));
    }

    #[test]
    fn a_working_directory_inside_git_has_no_root() {
        let (_d, top) = top();
        let inside = top.join(".git/hooks");
        fs::create_dir_all(&inside).unwrap();
        assert_eq!(find_repo_root(&inside, &[], None, uid()), None);
        assert_eq!(find_repo_root(&top.join(".git"), &[], None, uid()), None);
    }

    #[test]
    fn a_root_owned_by_another_user_is_not_a_root() {
        let (_d, top) = top();
        let sub = top.join("a");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir(top.join(".git")).unwrap();
        // Same tree, different effective uid: nothing is owned by it.
        assert_eq!(find_repo_root(&sub, &[], None, uid() + 1), None);
        assert_eq!(find_repo_root(&sub, &[], None, uid()), Some(top));
    }
}
