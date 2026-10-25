//! Which files a tool call would read.

use crate::input::HookInput;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::WalkBuilder;
use serde_json::Value;
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

fn absolute(p: &str, cwd: &Path) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
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
    let p = p.trim();
    let rest = match p.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
        _ => return p.to_string(),
    };
    match home.filter(|h| !h.is_empty()) {
        Some(home) => format!("{home}{rest}"),
        None => p.to_string(),
    }
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
    let path = absolute(field, cwd);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_dir() => None,
        Ok(_) => Some(path),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            None
        }
        // It exists but cannot be inspected; the scan reports why.
        Err(_) => Some(path),
    }
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

/// The paths in the `tool_input` fields `fields` of an MCP call, made
/// absolute against `cwd` with a leading `~` or `~/` expanded from `home`
/// (the filesystem server expands it). `None` when they cannot be
/// determined: no listed field is present, or a present one is neither a
/// string nor a list of strings.
pub fn mcp_paths(
    input: &HookInput,
    fields: &[String],
    cwd: &Path,
    home: Option<&str>,
) -> Option<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut found = false;
    for f in fields {
        let Some(v) = input.tool_input.get(f.as_str()) else {
            continue;
        };
        found = true;
        let items: Vec<&str> = match v {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().map(Value::as_str).collect::<Option<_>>()?,
            _ => return None,
        };
        out.extend(
            items
                .into_iter()
                .map(|p| absolute(&grep_path(p, home), cwd)),
        );
    }
    found.then_some(out)
}

/// The existing files among `paths`, as [`read_target`] treats one path.
pub fn existing_files(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter(|p| match std::fs::metadata(p) {
            Ok(meta) => !meta.is_dir(),
            Err(e) => !matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ),
        })
        .collect()
}

/// A `Glob` call's search root and pattern: `path` (default `cwd`, `~`
/// expanded), or for an absolute pattern the directory before its first
/// segment with a glob character, and the pattern's remainder.
pub fn glob_root(input: &HookInput, cwd: &Path, home: Option<&str>) -> Option<(PathBuf, String)> {
    let pattern = input.str_field("pattern")?.trim();
    let base = input
        .str_field("path")
        .map_or_else(|| cwd.to_path_buf(), |p| absolute(&grep_path(p, home), cwd));
    if !pattern.starts_with('/') {
        return Some((base, pattern.to_string()));
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
    pub limit_hit: bool,
}

/// The entries under each of `roots`, for MCP content searches (`files`
/// only) and for names a listing reveals: hidden entries included, ignore
/// files not honoured, the [`GREP_VCS_EXCLUDES`] directories skipped, links
/// not followed. A root that is a file is itself the entry. `glob` filters
/// file names (directories are then left out, as `Glob` returns files);
/// `max_depth` 1 is a root's own entries. Stops after `limit` entries.
pub fn walk_entries(
    roots: &[PathBuf],
    glob: Option<&str>,
    max_depth: Option<usize>,
    files: bool,
    limit: usize,
) -> Walk {
    let mut out = Walk::default();
    let files = files || glob.is_some();
    for root in roots {
        let Ok(meta) = std::fs::symlink_metadata(root) else {
            continue;
        };
        if !meta.is_dir() {
            if out.entries.len() >= limit {
                out.limit_hit = true;
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
            let is_file = entry.file_type().is_some_and(|t| !t.is_dir());
            if files && !is_file {
                continue;
            }
            if out.entries.len() >= limit {
                out.limit_hit = true;
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

    fn mcp(input: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: "mcp__s__t".into(),
            tool_input: input,
            cwd: None,
            event: None,
        }
    }

    #[test]
    fn mcp_paths_reads_strings_and_lists() {
        use serde_json::json;
        let cwd = Path::new("/w");
        let f = |v, fields: &[&str]| {
            let fields: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
            mcp_paths(&mcp(v), &fields, cwd, Some("/h"))
        };
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(f(json!({"path": "a"}), &["path"]), Some(vec![p("/w/a")]));
        assert_eq!(
            f(json!({"paths": ["/x", "~/y"]}), &["paths"]),
            Some(vec![p("/x"), p("/h/y")])
        );
        assert_eq!(f(json!({"b": "x"}), &["a", "b"]), Some(vec![p("/w/x")]));
        assert_eq!(f(json!({"paths": []}), &["paths"]), Some(vec![]));
        for bad in [
            json!({}),
            json!({"path": 1}),
            json!({"path": ["a", 2]}),
            json!(null),
        ] {
            assert_eq!(f(bad.clone(), &["path"]), None, "{bad}");
        }
    }

    #[test]
    fn glob_root_splits_absolute_patterns() {
        use serde_json::json;
        let cwd = Path::new("/w");
        let g = |v| glob_root(&mcp(v), cwd, Some("/h"));
        let r = |a: &str, b: &str| Some((PathBuf::from(a), b.to_string()));
        assert_eq!(g(json!({"pattern": "**/*.p12"})), r("/w", "**/*.p12"));
        assert_eq!(g(json!({"pattern": "*", "path": "~/k"})), r("/h/k", "*"));
        assert_eq!(g(json!({"pattern": "/a/b/*.key"})), r("/a/b", "*.key"));
        assert_eq!(g(json!({"pattern": "/a/**/x"})), r("/a", "**/x"));
        assert_eq!(g(json!({"pattern": "/*"})), r("/", "*"));
        assert_eq!(g(json!({"pattern": "/a/b"})), r("/a", "b"));
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
