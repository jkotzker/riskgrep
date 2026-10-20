//! Computes the digest of each built-in ruleset (the repository's
//! `rulesets/` directory, which the library embeds) so that the rules-bundle
//! key needs no hashing of the embedded sources at run time.

#[path = "src/ruleset_digest.rs"]
mod ruleset_digest;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// `(path relative to dir, bytes)` of every file a ruleset in `dir` loads.
fn ruleset_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).expect("read ruleset directory") {
            let p = entry.expect("ruleset directory entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(dir)
                .expect("inside ruleset")
                .to_str()
                .expect("UTF-8 ruleset file name")
                .to_string();
            if ruleset_digest::is_ruleset_file(&rel) {
                out.push((rel, fs::read(&p).expect("read ruleset file")));
            }
        }
    }
    out
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let root = manifest.join("../../rulesets");
    println!("cargo:rerun-if-changed={}", root.display());
    println!("cargo:rerun-if-changed=src/ruleset_digest.rs");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .expect("read rulesets")
        .map(|e| e.expect("rulesets entry").path())
        .filter(|p| p.join("ruleset.toml").is_file())
        .collect();
    dirs.sort();
    let mut out = String::from(
        "/// Digest of each built-in ruleset's files, by directory name.\n\
         pub(crate) static BUILTIN_DIGESTS: &[(&str, [u8; 32])] = &[\n",
    );
    for d in dirs {
        let name = d
            .file_name()
            .and_then(|n| n.to_str())
            .expect("UTF-8 ruleset directory name");
        let files = ruleset_files(&d);
        let digest =
            ruleset_digest::files_digest(files.iter().map(|(p, b)| (p.clone(), b.as_slice())));
        writeln!(out, "    ({name:?}, {digest:?}),").expect("write to string");
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var("OUT_DIR").expect("out dir")).join("builtin_digests.rs");
    fs::write(dest, out).expect("write builtin_digests.rs");
}
