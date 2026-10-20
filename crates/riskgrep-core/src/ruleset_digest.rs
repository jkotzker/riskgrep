//! The digest of a ruleset's files: everything that decides what its
//! compiled rules and post-processors do. Shared by `build.rs`, which
//! computes it for the built-in rulesets at build time, and by the library,
//! which computes it for rulesets loaded at run time.

use std::path::Path;

/// True for the files a ruleset loads, by path relative to its directory:
/// `ruleset.toml`, `*.yar`, and `stopwords/*.txt`. Used by `build.rs`.
#[allow(dead_code)]
pub fn is_ruleset_file(rel: &str) -> bool {
    let p = Path::new(rel);
    let ext = |want: &str| p.extension().is_some_and(|x| x == want);
    match p.parent().and_then(Path::to_str) {
        Some("") => rel == "ruleset.toml" || ext("yar"),
        Some("stopwords") => ext("txt"),
        _ => false,
    }
}

/// BLAKE3 over `(path relative to the ruleset directory, bytes)` pairs,
/// taken in path order, each part length-prefixed.
pub fn files_digest<'a>(files: impl IntoIterator<Item = (String, &'a [u8])>) -> [u8; 32] {
    let mut files: Vec<(String, &[u8])> = files.into_iter().collect();
    files.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"riskgrep ruleset files\0");
    for (path, bytes) in files {
        h.update(&(path.len() as u64).to_le_bytes());
        h.update(path.as_bytes());
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    *h.finalize().as_bytes()
}
