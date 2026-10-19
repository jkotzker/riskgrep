//! End-to-end tests of `riskgrep git`. Each test builds its own temporary
//! repository with an isolated HOME; secrets and tensors are generated at run
//! time and never printed.

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use riskgrep_core::synth;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn shared_home() -> &'static Path {
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    HOME.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

struct Repo {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

fn isolate(c: &mut Command, root: &Path) {
    let home = shared_home();
    c.current_dir(root)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CEILING_DIRECTORIES", root.parent().unwrap())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
}

impl Repo {
    fn new() -> Repo {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap().join("repo");
        fs::create_dir(&root).unwrap();
        let r = Repo { _tmp: tmp, root };
        r.git(&["init", "-q"]);
        r.git(&["config", "user.name", "Test"]);
        r.git(&["config", "user.email", "test@example.com"]);
        r.git(&["config", "commit.gpgsign", "false"]);
        r.git(&["config", "tag.gpgsign", "false"]);
        r
    }

    fn git(&self, args: &[&str]) {
        let mut c = Command::new("git");
        isolate(&mut c, &self.root);
        let out = c.args(args).output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn write(&self, name: impl AsRef<OsStr>, bytes: impl AsRef<[u8]>) {
        let p = self.root.join(name.as_ref());
        fs::write(p, bytes).unwrap();
    }

    fn stage(&self, name: &str) {
        let mut c = Command::new("git");
        isolate(&mut c, &self.root);
        let out = c
            .args(["--literal-pathspecs", "add", "--"])
            .arg(OsStr::from_bytes(name.as_bytes()))
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    fn riskgrep(&self, args: &[&str]) -> AssertCommand {
        let home = shared_home();
        let mut c = AssertCommand::cargo_bin("riskgrep").unwrap();
        c.current_dir(&self.root)
            .env("HOME", home)
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CEILING_DIRECTORIES", self.root.parent().unwrap())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .args(args);
        c
    }

    fn pre_commit(&self) -> AssertCommand {
        self.riskgrep(&["git", "pre-commit"])
    }
}

fn key(seed: u64) -> String {
    synth::fake_secret("aws_access_key", seed)
}

fn keyed_text(key: &str) -> String {
    format!("one\ntwo\nthree\nfour\nfive\nsix\nid = \"{key}\"\neight\n")
}

#[test]
fn blocks_new_secret() {
    let r = Repo::new();
    let k = key(1);
    r.write("conf.txt", keyed_text(&k));
    r.stage("conf.txt");
    r.pre_commit()
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "riskgrep: conf.txt: secret 95.0 (aws_access_token, line 7)",
        ))
        .stderr(predicate::str::contains("riskgrep baseline"))
        .stderr(predicate::str::contains("[ignore] in .riskgrep.toml"))
        .stderr(predicate::str::contains(k.as_str()).not())
        .stdout("");
}

#[test]
fn allows_clean_commit() {
    let r = Repo::new();
    r.write("a.txt", "hello\nworld\n");
    r.stage("a.txt");
    r.pre_commit().assert().code(0).stdout("").stderr("");
}

#[test]
fn allows_empty_stage() {
    let r = Repo::new();
    r.pre_commit().assert().code(0).stdout("").stderr("");
}

#[test]
fn old_secret_in_touched_file_allowed() {
    let r = Repo::new();
    r.write("conf.txt", keyed_text(&key(2)));
    r.stage("conf.txt");
    r.git(&["commit", "-q", "--no-verify", "-m", "old"]);
    // Edit a different line.
    let edited = keyed_text(&key(2)).replace("three", "THREE");
    r.write("conf.txt", edited);
    r.stage("conf.txt");
    r.pre_commit().assert().code(0).stderr("");
    r.riskgrep(&["git", "pre-commit", "--full-files"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("conf.txt: secret 95.0"));
}

#[test]
fn edited_secret_line_is_blocked() {
    let r = Repo::new();
    r.write("conf.txt", keyed_text(&key(3)));
    r.stage("conf.txt");
    r.git(&["commit", "-q", "--no-verify", "-m", "old"]);
    r.write("conf.txt", keyed_text(&key(4)));
    r.stage("conf.txt");
    r.pre_commit()
        .assert()
        .code(1)
        .stderr(predicate::str::contains("(aws_access_token, line 7)"));
}

#[test]
fn deletions_only_allowed() {
    let r = Repo::new();
    r.write("conf.txt", keyed_text(&key(5)));
    r.stage("conf.txt");
    r.git(&["commit", "-q", "--no-verify", "-m", "old"]);
    r.write("conf.txt", "one\ntwo\nthree\nfour\nfive\nsix\neight\n");
    r.stage("conf.txt");
    r.pre_commit().assert().code(0).stderr("");
}

#[test]
fn rename_without_edits_allowed() {
    let r = Repo::new();
    r.write("old.txt", keyed_text(&key(6)));
    r.stage("old.txt");
    r.git(&["commit", "-q", "--no-verify", "-m", "old"]);
    r.git(&["mv", "old.txt", "new.txt"]);
    r.pre_commit().assert().code(0).stderr("");
}

#[test]
fn baseline_allows_known() {
    let r = Repo::new();
    r.write("conf.txt", keyed_text(&key(7)));
    r.riskgrep(&["baseline", "conf.txt"]).assert().code(0);
    r.stage("conf.txt");
    r.stage(".riskgrep-baseline.json");
    r.pre_commit().assert().code(0).stderr("");
}

#[test]
fn biometric_npy_blocked() {
    // The tensor rule scores 70; the filename rule lifts it to 79, which is
    // at or above the default block_at of 75.
    let r = Repo::new();
    r.write("voiceprints.npy", synth::npy("<f4", &[10, 192]));
    r.stage("voiceprints.npy");
    r.pre_commit()
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "riskgrep: voiceprints.npy: biometric 79.0 (",
        ));
}

#[test]
fn unnamed_npy_below_block_at_allowed() {
    let r = Repo::new();
    r.write("data.npy", synth::npy("<f4", &[10, 192]));
    r.stage("data.npy");
    r.pre_commit().assert().code(0).stderr("");
    r.write(".riskgrep.toml", "[git.block_at]\nbiometric = 70\n");
    r.pre_commit()
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "riskgrep: data.npy: biometric 70.0",
        ));
}

#[test]
fn image_allowed() {
    let r = Repo::new();
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png.extend((0..4096u32).map(|i| (i * 31 % 251) as u8));
    r.write("pic.png", png);
    r.stage("pic.png");
    r.pre_commit().assert().code(0).stderr("");
}

#[test]
fn paths_with_space_and_newline() {
    let r = Repo::new();
    r.write("a b.env", keyed_text(&key(8)));
    r.write("new\nline.env", keyed_text(&key(9)));
    r.stage("a b.env");
    r.stage("new\nline.env");
    r.pre_commit()
        .assert()
        .code(1)
        .stderr(predicate::str::contains("riskgrep: a b.env: secret 95.0"))
        .stderr(predicate::str::contains(
            "riskgrep: new\\nline.env: secret 95.0",
        ));
}

#[test]
fn non_utf8_path_reported() {
    // The filesystem may refuse such a name, so stage the blob by plumbing.
    let r = Repo::new();
    let mut c = Command::new("git");
    isolate(&mut c, &r.root);
    c.args(["hash-object", "-w", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    std::io::Write::write_all(
        child.stdin.as_mut().unwrap(),
        keyed_text(&key(10)).as_bytes(),
    )
    .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    let sha = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let mut c = Command::new("git");
    isolate(&mut c, &r.root);
    let mut spec = format!("100644,{sha},").into_bytes();
    spec.extend_from_slice(b"bad\xffname.env");
    assert!(c
        .args(["update-index", "--add", "--cacheinfo"])
        .arg(OsStr::from_bytes(&spec))
        .status()
        .unwrap()
        .success());
    r.pre_commit()
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "secret 95.0 (aws_access_token, line 7)",
        ));
}

#[test]
fn block_at_comes_from_repo_config() {
    let r = Repo::new();
    r.write(".riskgrep.toml", "[git.block_at]\nsecret = 100\n");
    r.write("conf.txt", keyed_text(&key(11)));
    r.stage("conf.txt");
    r.pre_commit().assert().code(0).stderr("");
}

#[test]
fn block_at_is_inclusive() {
    let r = Repo::new();
    r.write(".riskgrep.toml", "[git.block_at]\nsecret = 95\n");
    r.write("conf.txt", keyed_text(&key(12)));
    r.stage("conf.txt");
    r.pre_commit().assert().code(1);
}

#[test]
fn install_hook_refuses_overwrite() {
    let r = Repo::new();
    r.riskgrep(&["git", "install-hook"]).assert().code(0);
    let hook = r.root.join(".git/hooks/pre-commit");
    assert_eq!(
        fs::read_to_string(&hook).unwrap(),
        "#!/bin/sh\nexec riskgrep git pre-commit \"$@\"\n"
    );
    assert_eq!(
        fs::metadata(&hook).unwrap().permissions().mode() & 0o777,
        0o755
    );
    r.riskgrep(&["git", "install-hook"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("--force"));
    fs::write(&hook, "other").unwrap();
    r.riskgrep(&["git", "install-hook", "--force"])
        .assert()
        .code(0);
    assert!(fs::read_to_string(&hook)
        .unwrap()
        .contains("riskgrep git pre-commit"));
}

#[test]
fn install_hook_respects_hooks_path() {
    let r = Repo::new();
    r.git(&["config", "core.hooksPath", "myhooks"]);
    r.riskgrep(&["git", "install-hook"]).assert().code(0);
    assert!(r.root.join("myhooks/pre-commit").exists());
    assert!(!r.root.join(".git/hooks/pre-commit").exists());
}

#[test]
fn installed_hook_blocks_commit() {
    let r = Repo::new();
    r.riskgrep(&["git", "install-hook"]).assert().code(0);
    let bin = assert_cmd::cargo::cargo_bin("riskgrep");
    let path = format!(
        "{}:{}",
        bin.parent().unwrap().display(),
        std::env::var("PATH").unwrap()
    );
    r.write("conf.txt", keyed_text(&key(13)));
    r.stage("conf.txt");
    let mut c = Command::new("git");
    isolate(&mut c, &r.root);
    let out = c
        .env("PATH", &path)
        .args(["commit", "-q", "-m", "x"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("secret 95.0"));
    let mut c = Command::new("git");
    isolate(&mut c, &r.root);
    let log = c.args(["rev-parse", "--verify", "HEAD"]).output().unwrap();
    assert!(!log.status.success(), "commit must not have been created");
}

#[test]
fn outside_repository_is_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = fs::canonicalize(tmp.path()).unwrap().join("plain");
    fs::create_dir(&dir).unwrap();
    let mut c = AssertCommand::cargo_bin("riskgrep").unwrap();
    c.current_dir(&dir)
        .env("HOME", shared_home())
        .env("XDG_CACHE_HOME", shared_home().join(".cache"))
        .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .args(["git", "pre-commit"])
        .assert()
        .code(3);
}

#[test]
fn pre_commit_yaml_declares_hook() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.pre-commit-hooks.yaml");
    let t = fs::read_to_string(p).unwrap();
    for needle in [
        "id: riskgrep",
        "name: RiskGrep",
        "entry: riskgrep git pre-commit",
        "language: system",
        "pass_filenames: false",
        "stages: [pre-commit]",
    ] {
        assert!(t.contains(needle), "missing `{needle}`");
    }
}
