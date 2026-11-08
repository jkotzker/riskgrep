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

use std::collections::HashMap;
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

/// [`find_repo_root`] for a canonical directory, sharing answers with every
/// directory searched before through `memo` (canonical directory to its
/// root). A directory without a `.git` entry that is not the stop below
/// `$HOME` has its parent's answer, unless that parent is a ceiling or on
/// another device, where the search stops; so each directory is examined
/// once however many files below it are looked up.
pub fn find_repo_root_cached(
    dir: &Path,
    search: &Search<'_>,
    memo: &mut HashMap<PathBuf, Option<PathBuf>>,
) -> Option<PathBuf> {
    if dir.components().any(|c| c.as_os_str() == ".git") {
        return None;
    }
    // Directories whose answer is their parent's, nearest first.
    let mut pending: Vec<&Path> = Vec::new();
    let mut cur = dir;
    // The device of `cur`, once its parent's was read.
    let mut cur_dev = None;
    let found = loop {
        if let Some(r) = memo.get(cur) {
            break r.clone();
        }
        if search.home_parent == Some(cur) {
            memo.insert(cur.to_path_buf(), None);
            break None;
        }
        if let Ok(entry) = fs::symlink_metadata(cur.join(".git")) {
            let owned =
                entry.uid() == search.uid && fs::metadata(cur).is_ok_and(|m| m.uid() == search.uid);
            let r = owned.then(|| cur.to_path_buf());
            memo.insert(cur.to_path_buf(), r.clone());
            break r;
        }
        let Some(parent) = cur.parent() else {
            memo.insert(cur.to_path_buf(), None);
            break None;
        };
        let mut parent_dev = None;
        if !search.across_filesystems {
            let d = cur_dev.unwrap_or_else(|| (search.dev_of)(cur));
            parent_dev = Some((search.dev_of)(parent));
            if parent_dev != Some(d) {
                memo.insert(cur.to_path_buf(), None);
                break None;
            }
        }
        if search.ceilings.iter().any(|c| c == parent) {
            memo.insert(cur.to_path_buf(), None);
            break None;
        }
        pending.push(cur);
        cur = parent;
        cur_dev = parent_dev;
    };
    for d in pending {
        memo.insert(d.to_path_buf(), found.clone());
    }
    found
}

/// The environment's inputs to [`find_repo_root`], read once: the ceilings
/// from `GIT_CEILING_DIRECTORIES`, the stop from `$HOME`,
/// `GIT_DISCOVERY_ACROSS_FILESYSTEM`, and the effective user id of this
/// process.
#[derive(Debug, Clone)]
pub struct SearchEnv {
    ceilings: Vec<PathBuf>,
    home_parent: Option<PathBuf>,
    uid: u32,
    across_filesystems: bool,
}

impl SearchEnv {
    pub fn from_env() -> SearchEnv {
        let canon = |p: PathBuf| fs::canonicalize(&p).unwrap_or(p);
        SearchEnv {
            ceilings: std::env::var_os("GIT_CEILING_DIRECTORIES")
                .map(|v| std::env::split_paths(&v).map(canon).collect())
                .unwrap_or_default(),
            home_parent: std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(canon)
                .and_then(|h| h.parent().map(Path::to_path_buf)),
            // SAFETY: geteuid has no preconditions and cannot fail.
            uid: unsafe { libc::geteuid() },
            across_filesystems: std::env::var("GIT_DISCOVERY_ACROSS_FILESYSTEM")
                .is_ok_and(|v| is_true(&v)),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&Search<'_>) -> T) -> T {
        f(&Search {
            ceilings: &self.ceilings,
            home_parent: self.home_parent.as_deref(),
            uid: self.uid,
            across_filesystems: self.across_filesystems,
            dev_of: &|p| fs::metadata(p).ok().map(|m| m.dev()),
        })
    }

    /// [`find_repo_root`] from `dir` under this environment.
    pub fn repo_root(&self, dir: &Path) -> Option<PathBuf> {
        self.with(|s| find_repo_root(dir, s))
    }

    /// [`find_repo_root_cached`] from the canonical `dir` under this
    /// environment.
    pub fn repo_root_cached(
        &self,
        dir: &Path,
        memo: &mut HashMap<PathBuf, Option<PathBuf>>,
    ) -> Option<PathBuf> {
        self.with(|s| find_repo_root_cached(dir, s, memo))
    }
}

/// [`find_repo_root`] with the ceilings from `GIT_CEILING_DIRECTORIES`, the
/// stop from `$HOME`, `GIT_DISCOVERY_ACROSS_FILESYSTEM`, and the effective
/// user id of this process.
pub fn repo_root_from_env(cwd: &Path) -> Option<PathBuf> {
    SearchEnv::from_env().repo_root(cwd)
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

    /// Every directory of a tree, in walk order.
    fn dirs(top: &Path) -> Vec<PathBuf> {
        let mut out = vec![top.to_path_buf()];
        let mut i = 0;
        while i < out.len() {
            let mut kids: Vec<PathBuf> = fs::read_dir(&out[i])
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.is_dir())
                .collect();
            kids.sort();
            out.extend(kids);
            i += 1;
        }
        out
    }

    #[test]
    fn the_cached_search_answers_as_the_search_does() {
        let (_d, top) = top();
        for sub in [
            "r/a/b/c",
            "r/n/.git/hooks",
            "r/n/x/y",
            "h/me/p/q",
            "c/z/w",
            "dev/k/l",
        ] {
            fs::create_dir_all(top.join(sub)).unwrap();
        }
        fs::create_dir(top.join("r/.git")).unwrap();
        fs::write(top.join("r/a/b/.git"), "gitdir: x\n").unwrap();
        fs::create_dir(top.join("c/.git")).unwrap();
        fs::create_dir(top.join("dev/.git")).unwrap();
        let home_parent = top.join("h");
        let ceilings = [top.join("c/z")];
        let boundary = top.join("dev/k");
        let dev = move |p: &Path| Some(if p.starts_with(&boundary) { 2 } else { 1 });
        for uid in [uid(), uid() + 1] {
            for across in [false, true] {
                let search = Search {
                    ceilings: &ceilings,
                    home_parent: Some(&home_parent),
                    uid,
                    across_filesystems: across,
                    dev_of: &dev,
                };
                // Deepest first and in walk order, so both orders of filling
                // the memo are checked.
                let all = dirs(&top);
                for order in [all.clone(), all.into_iter().rev().collect()] {
                    let mut memo = HashMap::new();
                    for d in &order {
                        assert_eq!(
                            find_repo_root_cached(d, &search, &mut memo),
                            find_repo_root(d, &search),
                            "{} (uid {uid}, across {across})",
                            d.display()
                        );
                    }
                }
            }
        }
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
