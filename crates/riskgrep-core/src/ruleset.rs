//! Rulesets: a directory with `ruleset.toml`, `*.yar` sources, and optional
//! `stopwords/*.txt` lists.

use crate::model::Category;
use crate::ruleset_digest::files_digest;
use include_dir::{include_dir, Dir};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

static BUILTIN: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../rulesets");

include!(concat!(env!("OUT_DIR"), "/builtin_digests.rs"));

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
    /// `(file name, source text)`, sorted by file name. Built-in sources
    /// borrow the embedded text.
    pub sources: Vec<(String, Cow<'static, str>)>,
    /// List name (file stem) to non-empty trimmed lines.
    pub stopwords: BTreeMap<String, Vec<String>>,
    /// Digest of the files this ruleset was loaded from (manifest, sources,
    /// stopword lists), taken at load time; computed at build time for the
    /// built-in rulesets. Changing the public fields afterwards does not
    /// change it.
    digest: [u8; 32],
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
                sources.push((file_name(&p), Cow::Owned(text)));
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
                    lists.push((stem.unwrap_or_default(), Cow::Owned(text)));
                }
            }
        }
        Self::assemble(&manifest, sources, lists, None)
            .map_err(|e| Error(format!("{}: {e}", path.display())))
    }

    /// The digest of the files this ruleset was loaded from.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Build a ruleset from its files' text. `digest` is the files' digest
    /// when already known (built-ins); otherwise it is computed here.
    fn assemble(
        manifest: &str,
        mut sources: Vec<(String, Cow<'static, str>)>,
        lists: Vec<(String, Cow<'static, str>)>,
        digest: Option<[u8; 32]>,
    ) -> Result<Ruleset> {
        let m: Manifest =
            toml::from_str(manifest).map_err(|e| Error(format!("ruleset.toml: {e}")))?;
        sources.sort();
        let digest = digest.unwrap_or_else(|| {
            files_digest(
                std::iter::once(("ruleset.toml".to_string(), manifest.as_bytes()))
                    .chain(sources.iter().map(|(n, t)| (n.clone(), t.as_bytes())))
                    .chain(
                        lists
                            .iter()
                            .map(|(n, t)| (format!("stopwords/{n}.txt"), t.as_bytes())),
                    ),
            )
        });
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
            digest,
        })
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Embedded file text, borrowed unless it is not UTF-8.
fn embedded_text(f: &'static include_dir::File<'static>) -> Cow<'static, str> {
    String::from_utf8_lossy(f.contents())
}

/// The ruleset embedded in `dir` with `digest` (`None`: compute it from the
/// text), or `None` when `dir` holds no `ruleset.toml`.
fn embedded(dir: &'static Dir<'static>, digest: Option<[u8; 32]>) -> Option<Ruleset> {
    let manifest = dir.get_file(dir.path().join("ruleset.toml"))?;
    let sources = dir
        .files()
        .filter(|f| f.path().extension().is_some_and(|x| x == "yar"))
        .map(|f| (file_name(f.path()), embedded_text(f)))
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
            (stem.unwrap_or_default(), embedded_text(f))
        })
        .collect();
    Some(
        Ruleset::assemble(&embedded_text(manifest), sources, lists, digest)
            .unwrap_or_else(|e| panic!("embedded ruleset {}: {e}", dir.path().display())),
    )
}

/// The build script's digest of the embedded ruleset directory `name`.
fn build_digest(name: &str) -> Option<[u8; 32]> {
    BUILTIN_DIGESTS
        .iter()
        .find(|(d, _)| *d == name)
        .map(|(_, digest)| *digest)
}

/// Rulesets embedded from the repository's `rulesets/` directory: every
/// subdirectory that contains a `ruleset.toml`. Their digests come from the
/// build script, so nothing is hashed here.
pub fn builtin_rulesets() -> Vec<Ruleset> {
    let mut out: Vec<Ruleset> = BUILTIN
        .dirs()
        .filter(|dir| dir.get_file(dir.path().join("ruleset.toml")).is_some())
        .filter_map(|dir| {
            let name = dir.path().to_str().unwrap_or_default();
            let digest = build_digest(name)
                .unwrap_or_else(|| panic!("embedded ruleset {name} has no build-time digest"));
            embedded(dir, Some(digest))
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_digest_matches_the_build_time_one() {
        // The digest computed from the embedded text (as for a ruleset loaded
        // at run time) equals the build script's, for every built-in.
        let mut checked = 0;
        for dir in BUILTIN.dirs() {
            let Some(computed) = embedded(dir, None) else {
                continue;
            };
            let name = dir.path().to_str().unwrap();
            assert_eq!(Some(*computed.digest()), build_digest(name), "{name}");
            checked += 1;
        }
        assert_eq!(checked, BUILTIN_DIGESTS.len());
        assert!(checked >= 2);
    }
}
