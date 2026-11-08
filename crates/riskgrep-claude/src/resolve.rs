//! Which files a tool call would read.

use crate::input::HookInput;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::WalkBuilder;
use riskgrep_core::paths::{absolute, expand_tilde, readable_file};
use std::path::{Path, PathBuf};

/// Directories Claude Code 2.1.301 excludes from every `Grep` search: it
/// passes `--glob !NAME` for each, ahead of the call's own globs.
pub const GREP_VCS_EXCLUDES: [&str; 6] = [".git", ".svn", ".hg", ".bzr", ".jj", ".sl"];

/// Files a `Grep` call would search.
#[derive(Debug, Default)]
pub struct GrepFiles {
    pub files: Vec<PathBuf>,
    /// The walk stopped at the file limit; `files` is incomplete.
    pub limit_hit: bool,
}

/// The globs a `Grep` call's `glob` field adds, split as Claude Code
/// 2.1.301 splits it: on whitespace, then each piece on commas unless the
/// piece holds both `{` and `}`. Empty pieces are dropped.
pub fn split_grep_glob(glob: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for piece in glob.split_whitespace() {
        if piece.contains('{') && piece.contains('}') {
            out.push(piece);
        } else {
            out.extend(piece.split(',').filter(|g| !g.is_empty()));
        }
    }
    out
}

/// A `Grep` call's `path`, trimmed, with a leading `~` or `~/` replaced by
/// `home`. Claude Code resolves these for `Grep` itself, whereas `Read`
/// paths arrive already expanded. `~user` is left as it is, as is `~` when
/// `home` is unset or empty.
pub fn grep_path(p: &str, home: Option<&str>) -> String {
    expand_tilde(p.trim(), home)
}

/// The file a `Read` or `NotebookRead` call names. A path that does not
/// exist, or that names a directory, is dropped: the tool fails on it and
/// reads nothing.
pub fn read_target(input: &HookInput, cwd: &Path) -> Option<PathBuf> {
    let field = match input.tool_name.as_str() {
        "NotebookRead" => input
            .str_field("notebook_path")
            .or_else(|| input.str_field("file_path")),
        _ => input.str_field("file_path"),
    }?;
    readable_file(absolute(field, cwd))
}

/// The files `Grep` would search under `path` (default `cwd`), mirroring
/// the ripgrep call of Claude Code 2.1.301: hidden entries included, the
/// [`GREP_VCS_EXCLUDES`] directories excluded, `.gitignore` honoured,
/// links not followed. `glob` (split by [`split_grep_glob`]) and `kind` (a
/// ripgrep file type) filter the walk; at most `limit` files are returned.
/// A glob or type that ripgrep would reject leaves nothing to search.
pub fn grep_files(
    input: &HookInput,
    cwd: &Path,
    glob: Option<&str>,
    kind: Option<&str>,
    limit: usize,
) -> GrepFiles {
    let home = std::env::var("HOME").ok();
    let root = input.str_field("path").map_or_else(
        || cwd.to_path_buf(),
        |p| absolute(&grep_path(p, home.as_deref()), cwd),
    );
    let Ok(meta) = std::fs::metadata(&root) else {
        return GrepFiles::default();
    };
    if meta.is_file() {
        return GrepFiles {
            files: vec![root],
            limit_hit: false,
        };
    }
    let mut walk = WalkBuilder::new(&root);
    walk.follow_links(false).hidden(false);
    let mut ov = OverrideBuilder::new(&root);
    let excludes = GREP_VCS_EXCLUDES.iter().map(|d| format!("!{d}"));
    let own = glob
        .into_iter()
        .flat_map(split_grep_glob)
        .map(str::to_string);
    for g in excludes.chain(own) {
        if ov.add(&g).is_err() {
            return GrepFiles::default();
        }
    }
    match ov.build() {
        Ok(o) => walk.overrides(o),
        Err(_) => return GrepFiles::default(),
    };
    if let Some(k) = kind {
        let mut tb = TypesBuilder::new();
        tb.add_defaults();
        tb.select(k);
        match tb.build() {
            Ok(t) => walk.types(t),
            Err(_) => return GrepFiles::default(),
        };
    }
    let mut out = GrepFiles::default();
    for entry in walk.build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        if out.files.len() >= limit {
            out.limit_hit = true;
            break;
        }
        out.files.push(entry.into_path());
    }
    out
}

/// A `Glob` call's search root and pattern: `path` (default `cwd`, `~`
/// expanded), or for an absolute pattern the directory before its first
/// segment with a glob character, and the pattern's remainder. Leading `.`
/// and `..` segments of a relative pattern move into the root (`..` as the
/// root's lexical parent), since a walk below the root cannot match them.
pub fn glob_root(input: &HookInput, cwd: &Path, home: Option<&str>) -> Option<(PathBuf, String)> {
    let pattern = input.str_field("pattern")?.trim();
    let mut base = input
        .str_field("path")
        .map_or_else(|| cwd.to_path_buf(), |p| absolute(&grep_path(p, home), cwd));
    if !pattern.starts_with('/') {
        let mut rest = pattern;
        loop {
            if let Some(r) = rest.strip_prefix("./") {
                rest = r;
            } else if let Some(r) = rest.strip_prefix("../") {
                if let Some(parent) = base.parent() {
                    base = parent.to_path_buf();
                }
                rest = r;
            } else {
                return Some((base, rest.to_string()));
            }
        }
    }
    let segs: Vec<&str> = pattern.split('/').collect();
    let first = segs
        .iter()
        .position(|s| s.contains(['*', '?', '[', '{']))
        .unwrap_or(segs.len() - 1);
    let root = segs[..first].join("/");
    Some((
        PathBuf::from(if root.is_empty() { "/" } else { &root }),
        segs[first..].join("/"),
    ))
}

/// What [`walk_entries`] collects.
#[derive(Debug, Default)]
pub struct Walk {
    pub entries: Vec<PathBuf>,
    /// The root whose walk reached the entry limit; `entries` is then
    /// incomplete.
    pub limit_at: Option<PathBuf>,
}

/// The entries under each of `roots`, for MCP content searches (`files`:
/// regular files only, so a link below a root is never scanned) and for
/// names a listing reveals: hidden entries included, ignore
/// files not honoured, the [`GREP_VCS_EXCLUDES`] directories skipped, links
/// below a root not followed. A root that is a link to a directory is
/// walked; a root that is a file, or a link to nothing, is itself the
/// entry. `glob` filters file names (directories are then left out, as
/// `Glob` returns files); `max_depth` 1 is a root's own entries. Stops
/// after `limit` entries.
pub fn walk_entries(
    roots: &[PathBuf],
    glob: Option<&str>,
    max_depth: Option<usize>,
    files: bool,
    limit: usize,
) -> Walk {
    let mut out = Walk::default();
    let keep = |t: Option<std::fs::FileType>| match t {
        Some(t) if files => t.is_file(),
        Some(t) if glob.is_some() => !t.is_dir(),
        Some(_) => true,
        None => false,
    };
    for root in roots {
        let is_dir = match std::fs::metadata(root) {
            Ok(meta) => meta.is_dir(),
            Err(_) if std::fs::symlink_metadata(root).is_ok() => false,
            Err(_) => continue,
        };
        if !is_dir {
            if out.entries.len() >= limit {
                out.limit_at = Some(root.clone());
                return out;
            }
            out.entries.push(root.clone());
            continue;
        }
        let mut walk = WalkBuilder::new(root);
        walk.standard_filters(false)
            .follow_links(false)
            .max_depth(max_depth);
        let mut ov = OverrideBuilder::new(root);
        let excludes = GREP_VCS_EXCLUDES.iter().map(|d| format!("!{d}"));
        for g in excludes.chain(glob.map(str::to_string)) {
            if ov.add(&g).is_err() {
                return out;
            }
        }
        match ov.build() {
            Ok(o) => walk.overrides(o),
            Err(_) => return out,
        };
        for entry in walk.build().flatten() {
            if entry.depth() == 0 {
                continue;
            }
            if !keep(entry.file_type()) {
                continue;
            }
            if out.entries.len() >= limit {
                out.limit_at = Some(root.clone());
                return out;
            }
            out.entries.push(entry.into_path());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_split_matches_claude_code() {
        assert_eq!(split_grep_glob("*.md,*.env"), ["*.md", "*.env"]);
        assert_eq!(split_grep_glob("*.md *.env"), ["*.md", "*.env"]);
        assert_eq!(split_grep_glob("*.{md,env}"), ["*.{md,env}"]);
        assert_eq!(
            split_grep_glob(" a,,b\t*.{x,y} c "),
            ["a", "b", "*.{x,y}", "c"]
        );
        // Only a piece with both braces is kept whole.
        assert_eq!(split_grep_glob("*.{md,env"), ["*.{md", "env"]);
        assert!(split_grep_glob(" , ").is_empty());
    }

    fn hook(input: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: "Glob".into(),
            tool_input: input,
            cwd: None,
            event: None,
        }
    }

    #[test]
    fn glob_root_splits_absolute_patterns() {
        use serde_json::json;
        let cwd = Path::new("/w");
        let g = |v| glob_root(&hook(v), cwd, Some("/h"));
        let r = |a: &str, b: &str| Some((PathBuf::from(a), b.to_string()));
        assert_eq!(g(json!({"pattern": "**/*.p12"})), r("/w", "**/*.p12"));
        assert_eq!(g(json!({"pattern": "*", "path": "~/k"})), r("/h/k", "*"));
        assert_eq!(g(json!({"pattern": "/a/b/*.key"})), r("/a/b", "*.key"));
        assert_eq!(g(json!({"pattern": "/a/**/x"})), r("/a", "**/x"));
        assert_eq!(g(json!({"pattern": "/*"})), r("/", "*"));
        assert_eq!(g(json!({"pattern": "/a/b"})), r("/a", "b"));
        // Leading `.` and `..` segments move into the root.
        assert_eq!(g(json!({"pattern": "./k/*.p12"})), r("/w", "k/*.p12"));
        assert_eq!(g(json!({"pattern": "../k/*"})), r("/", "k/*"));
        assert_eq!(
            g(json!({"pattern": ".././../x/*", "path": "/a/b/c"})),
            r("/a", "x/*")
        );
        assert_eq!(g(json!({"pattern": "../*", "path": "/"})), r("/", "*"));
        assert_eq!(g(json!({"path": "x"})), None);
    }

    #[test]
    fn grep_path_expands_leading_tilde() {
        let h = Some("/h");
        assert_eq!(grep_path("~", h), "/h");
        assert_eq!(grep_path("~/p", h), "/h/p");
        assert_eq!(grep_path("  ~/p \n", h), "/h/p");
        assert_eq!(grep_path("~bob/p", h), "~bob/p");
        assert_eq!(grep_path("a/~/p", h), "a/~/p");
        assert_eq!(grep_path("~/p", None), "~/p");
        assert_eq!(grep_path("~/p", Some("")), "~/p");
    }
}
