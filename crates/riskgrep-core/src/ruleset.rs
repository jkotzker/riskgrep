//! Rulesets: a directory with `ruleset.toml`, `*.yar` sources, and optional
//! `stopwords/*.txt` lists.

use crate::model::Category;
use include_dir::{include_dir, Dir};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

static BUILTIN: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../rulesets");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq)]
pub struct Ruleset {
    pub id: String,
    pub version: String,
    pub licence: String,
    pub description: String,
    pub categories: Vec<Category>,
    /// `(file name, source text)`, sorted by file name.
    pub sources: Vec<(String, String)>,
    /// List name (file stem) to non-empty trimmed lines.
    pub stopwords: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct Manifest {
    id: String,
    version: String,
    licence: String,
    description: String,
    categories: Vec<String>,
}

impl Ruleset {
    pub fn load_dir(path: &Path) -> Result<Ruleset> {
        let io = |p: &Path, e: std::io::Error| Error(format!("{}: {e}", p.display()));
        let manifest_path = path.join("ruleset.toml");
        let manifest = fs::read_to_string(&manifest_path).map_err(|e| io(&manifest_path, e))?;
        let mut sources = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| io(path, e))? {
            let p = entry.map_err(|e| io(path, e))?.path();
            if p.extension().is_some_and(|x| x == "yar") {
                let text = fs::read_to_string(&p).map_err(|e| io(&p, e))?;
                sources.push((file_name(&p), text));
            }
        }
        let mut lists = Vec::new();
        let sw = path.join("stopwords");
        if sw.is_dir() {
            for entry in fs::read_dir(&sw).map_err(|e| io(&sw, e))? {
                let p = entry.map_err(|e| io(&sw, e))?.path();
                if p.extension().is_some_and(|x| x == "txt") {
                    let text = fs::read_to_string(&p).map_err(|e| io(&p, e))?;
                    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned());
                    lists.push((stem.unwrap_or_default(), text));
                }
            }
        }
        Self::assemble(&manifest, sources, lists)
            .map_err(|e| Error(format!("{}: {e}", path.display())))
    }

    fn assemble(
        manifest: &str,
        mut sources: Vec<(String, String)>,
        lists: Vec<(String, String)>,
    ) -> Result<Ruleset> {
        let m: Manifest =
            toml::from_str(manifest).map_err(|e| Error(format!("ruleset.toml: {e}")))?;
        sources.sort();
        let stopwords = lists
            .into_iter()
            .map(|(name, text)| {
                let words = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect();
                (name, words)
            })
            .collect();
        Ok(Ruleset {
            id: m.id,
            version: m.version,
            licence: m.licence,
            description: m.description,
            categories: m.categories.into_iter().map(Category).collect(),
            sources,
            stopwords,
        })
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Rulesets embedded from the repository's `rulesets/` directory: every
/// subdirectory that contains a `ruleset.toml`.
pub fn builtin_rulesets() -> Vec<Ruleset> {
    let mut out = Vec::new();
    for dir in BUILTIN.dirs() {
        let Some(manifest) = dir.get_file(dir.path().join("ruleset.toml")) else {
            continue;
        };
        let text = |f: &include_dir::File| String::from_utf8_lossy(f.contents()).into_owned();
        let sources = dir
            .files()
            .filter(|f| f.path().extension().is_some_and(|x| x == "yar"))
            .map(|f| (file_name(f.path()), text(f)))
            .collect();
        let lists = dir
            .get_dir(dir.path().join("stopwords"))
            .into_iter()
            .flat_map(|d| d.files())
            .filter(|f| f.path().extension().is_some_and(|x| x == "txt"))
            .map(|f| {
                let stem = f
                    .path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned());
                (stem.unwrap_or_default(), text(f))
            })
            .collect();
        out.push(
            Ruleset::assemble(&text(manifest), sources, lists)
                .unwrap_or_else(|e| panic!("embedded ruleset {}: {e}", dir.path().display())),
        );
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}
