//! Which files a tool call would read.

use crate::input::HookInput;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

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

/// The file a `Read` or `NotebookRead` call names. A path that does not
/// exist is dropped: the tool fails on it and reads nothing.
pub fn read_target(input: &HookInput, cwd: &Path) -> Option<PathBuf> {
    let field = match input.tool_name.as_str() {
        "NotebookRead" => input
            .str_field("notebook_path")
            .or_else(|| input.str_field("file_path")),
        _ => input.str_field("file_path"),
    }?;
    let path = absolute(field, cwd);
    std::fs::symlink_metadata(&path).ok()?;
    Some(path)
}

/// The files `Grep` would search under `path` (default `cwd`), mirroring
/// ripgrep's defaults: hidden entries skipped, `.gitignore` honoured, links
/// not followed. `glob` and `kind` (a ripgrep file type) filter the walk;
/// at most `limit` files are returned. A glob or type that ripgrep would
/// reject leaves nothing to search.
pub fn grep_files(
    input: &HookInput,
    cwd: &Path,
    glob: Option<&str>,
    kind: Option<&str>,
    limit: usize,
) -> GrepFiles {
    let root = input
        .str_field("path")
        .map_or_else(|| cwd.to_path_buf(), |p| absolute(p, cwd));
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
    walk.follow_links(false);
    if let Some(g) = glob {
        let mut ov = OverrideBuilder::new(&root);
        if ov.add(g).is_err() {
            return GrepFiles::default();
        }
        match ov.build() {
            Ok(o) => walk.overrides(o),
            Err(_) => return GrepFiles::default(),
        };
    }
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
