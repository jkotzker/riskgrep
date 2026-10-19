use riskgrep_core::bundle::{bundle_key, load_or_compile};
use riskgrep_core::paths::ensure_private_dir;
use riskgrep_core::ruleset::{builtin_rulesets, Ruleset};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const RULE: &str = r#"rule tok { meta:
 category = "secrets"
 weight = 50
 strings: $a = "AKIA" condition: $a }"#;

fn write_ruleset(dir: &Path, id: &str, src: &str) -> Ruleset {
    fs::write(
        dir.join("ruleset.toml"),
        format!(
            "id = \"{id}\"\nversion = \"1\"\nlicence = \"MIT\"\ndescription = \"t\"\ncategories = [\"secrets\"]\n"
        ),
    )
    .unwrap();
    fs::write(dir.join("a.yar"), src).unwrap();
    fs::create_dir_all(dir.join("stopwords")).unwrap();
    fs::write(dir.join("stopwords/common.txt"), "foo\n\nbar\n").unwrap();
    Ruleset::load_dir(dir).unwrap()
}

#[test]
fn load_dir_reads_files() {
    let d = tempfile::tempdir().unwrap();
    let rs = write_ruleset(d.path(), "t1", RULE);
    assert_eq!(rs.id, "t1");
    assert_eq!(rs.categories[0].0, "secrets");
    assert_eq!(rs.sources.len(), 1);
    assert_eq!(rs.stopwords["common"], vec!["foo", "bar"]);
}

#[test]
fn builtin_rulesets_empty_for_now() {
    assert!(builtin_rulesets().is_empty());
}

#[test]
fn bundle_cached_second_load() {
    let d = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let rs = write_ruleset(d.path(), "t1", RULE);
    let b1 = load_or_compile(&[&rs], c.path()).unwrap();
    assert!(b1.compiled);
    assert!(b1.meta.contains_key("t1:tok"));
    assert_eq!(b1.stopwords["common"].len(), 2);
    let b2 = load_or_compile(&[&rs], c.path()).unwrap();
    assert!(!b2.compiled);
    assert_eq!(b1.hash, b2.hash);
    assert!(b2.meta.contains_key("t1:tok"));
    let file = c.path().join("bundles").join(format!("{}.yxb", b1.hash));
    assert_eq!(
        fs::metadata(file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn bundle_key_changes_with_source() {
    let d = tempfile::tempdir().unwrap();
    let rs1 = write_ruleset(d.path(), "t1", RULE);
    let rs2 = write_ruleset(d.path(), "t1", &RULE.replace("AKIA", "ASIA"));
    assert_ne!(bundle_key(&[&rs1]), bundle_key(&[&rs2]));
    assert_eq!(bundle_key(&[&rs1]), bundle_key(&[&rs1]));
}

#[test]
fn corrupt_bundle_recompiles() {
    let d = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let rs = write_ruleset(d.path(), "t1", RULE);
    let b1 = load_or_compile(&[&rs], c.path()).unwrap();
    let file = c.path().join("bundles").join(format!("{}.yxb", b1.hash));
    fs::write(&file, b"garbage").unwrap();
    let b2 = load_or_compile(&[&rs], c.path()).unwrap();
    assert!(b2.compiled);
    assert!(!load_or_compile(&[&rs], c.path()).unwrap().compiled);
}

#[test]
fn invalid_metadata_fails_load_naming_rule() {
    let d = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let rs = write_ruleset(d.path(), "t1", &RULE.replace("weight = 50", "weight = 500"));
    let e = load_or_compile(&[&rs], c.path()).err().unwrap();
    assert!(e.to_string().contains("tok"), "{e}");
}

#[test]
fn missing_stopword_list_fails_load() {
    let d = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let src = RULE.replace(
        "weight = 50",
        "weight = 50\n post = \"stopwords\"\n stopwords = \"nolist\"",
    );
    let rs = write_ruleset(d.path(), "t1", &src);
    let e = load_or_compile(&[&rs], c.path()).err().unwrap();
    assert!(e.to_string().contains("nolist"), "{e}");
}

#[test]
fn cache_dir_private() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("sub");
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    ensure_private_dir(&p).unwrap();
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let q = d.path().join("new/deeper");
    ensure_private_dir(&q).unwrap();
    assert_eq!(
        fs::metadata(&q).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
