//! The gitleaks converter: regex rewriting, and the generated ruleset.

use riskgrep_core::bundle::load_or_compile;
use riskgrep_core::ruleset::Ruleset;
use std::fs;
use std::path::{Path, PathBuf};
use xtask::{convert_gitleaks, lazy_to_greedy, PINNED_TAG};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pinned_config() -> Vec<u8> {
    fs::read(repo().join("xtask/upstream/gitleaks.toml")).unwrap()
}

#[test]
fn lazy_counted_repetition_becomes_greedy() {
    assert_eq!(
        lazy_to_greedy("[\\w.-]{0,50}?(?:a|b)"),
        "[\\w.-]{0,50}(?:a|b)"
    );
}

#[test]
fn escaped_brace_is_not_a_quantifier() {
    assert_eq!(lazy_to_greedy(r"\{3}?"), r"\{3}?");
}

#[test]
fn class_contents_are_untouched() {
    assert_eq!(lazy_to_greedy("[?*]+?"), "[?*]+");
}

#[test]
fn other_lazy_forms() {
    assert_eq!(lazy_to_greedy("a*?b+?c??d{2,}?"), "a*b+c?d{2,}");
    // Group flags and a literal `{` that does not start a repetition.
    assert_eq!(lazy_to_greedy("(?i)(?:x)a{b}?"), "(?i)(?:x)a{b}?");
    // POSIX class and a leading `]` inside a class.
    assert_eq!(lazy_to_greedy("[[:alnum:]?]*?[]?]+?"), "[[:alnum:]?]*[]?]+");
    // An escaped backslash does not escape the next quantifier.
    assert_eq!(lazy_to_greedy(r"\\+?"), r"\\+");
}

fn rule_count(config: &[u8]) -> usize {
    let v: toml::Value = toml::from_str(std::str::from_utf8(config).unwrap()).unwrap();
    v["rules"].as_array().unwrap().len()
}

fn convert_to_temp() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    convert_gitleaks(&pinned_config(), PINNED_TAG, d.path()).unwrap();
    d
}

#[test]
fn converted_ruleset_compiles() {
    let d = convert_to_temp();
    fs::copy(
        repo().join("rulesets/secrets-core/ruleset.toml"),
        d.path().join("ruleset.toml"),
    )
    .unwrap();
    let rs = Ruleset::load_dir(d.path()).unwrap();
    assert_eq!(rs.id, "secrets_core");
    let cache = tempfile::tempdir().unwrap();
    let bundle = load_or_compile(&[&rs], cache.path()).unwrap();
    let public = bundle.rules.iter().filter(|r| !r.is_private()).count();
    assert_eq!(public, rule_count(&pinned_config()));
}

#[test]
fn committed_output_is_current() {
    let d = convert_to_temp();
    let shipped = repo().join("rulesets/secrets-core");
    for name in ["gitleaks.yar", "UPSTREAM.md"] {
        let want = fs::read(d.path().join(name)).unwrap();
        let got = fs::read(shipped.join(name)).unwrap();
        assert!(
            want == got,
            "{name} is stale: run cargo xtask convert-gitleaks"
        );
    }
    let list = |p: &Path| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = fs::read_dir(p.join("stopwords"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("secrets_core_")
            })
            .map(|p| {
                let n = p.file_name().unwrap().to_string_lossy().into_owned();
                (n, fs::read(&p).unwrap())
            })
            .collect();
        v.sort();
        v
    };
    let (want, got) = (list(d.path()), list(&shipped));
    let names = |v: &[(String, Vec<u8>)]| v.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
    assert_eq!(names(&want), names(&got), "stopword lists are stale");
    assert!(want == got, "stopword lists are stale");
}

#[test]
fn rerun_replaces_stale_stopword_lists() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join("stopwords")).unwrap();
    fs::write(d.path().join("stopwords/secrets_core_gone.txt"), "x\n").unwrap();
    fs::write(d.path().join("stopwords/other.txt"), "y\n").unwrap();
    convert_gitleaks(&pinned_config(), PINNED_TAG, d.path()).unwrap();
    assert!(!d.path().join("stopwords/secrets_core_gone.txt").exists());
    assert!(d.path().join("stopwords/other.txt").exists());
}

#[test]
fn unknown_config_key_is_an_error() {
    let cfg = b"title = \"t\"\nsurprise = 1\n[[rules]]\nid = \"a\"\nregex = 'x'\n";
    let d = tempfile::tempdir().unwrap();
    let err = convert_gitleaks(cfg, "v0", d.path()).unwrap_err();
    assert!(err.contains("surprise"), "{err}");
}

#[test]
fn go_literal_brace_is_escaped() {
    use xtask::go_to_rust;
    assert_eq!(go_to_rust(r"^\$(?:\d+|{\d+})$"), r"^\$(?:\d+|\{\d+})$");
    assert_eq!(go_to_rust(r"a{2,3}[{]\{x"), r"a{2,3}[{]\{x");
}
