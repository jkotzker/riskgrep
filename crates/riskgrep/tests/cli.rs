//! End-to-end tests of the `riskgrep` binary. Every run gets a temporary
//! HOME so no real user configuration is read, and a cache directory inside
//! it. Secrets are generated at run time and never printed.

use assert_cmd::Command;
use predicates::prelude::*;
use riskgrep_core::synth;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// One HOME (and so one rules cache) shared by every test that reads no
/// user configuration.
fn shared_home() -> &'static Path {
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    HOME.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

/// Mode-000 files stay readable to root, so tests that rely on them skip.
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    let d = tempfile::tempdir().unwrap();
    let root = fs::metadata(d.path()).unwrap().uid() == 0;
    if root {
        eprintln!("skipped: running as root, mode-000 files are readable");
    }
    root
}

fn riskgrep_in(home: &Path, cwd: &Path) -> Command {
    let mut c = Command::cargo_bin("riskgrep").unwrap();
    c.current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("GIT_CEILING_DIRECTORIES", cwd.parent().unwrap())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    c
}

fn riskgrep(cwd: &Path) -> Command {
    riskgrep_in(shared_home(), cwd)
}

/// A work directory holding `key.txt`: a generated AWS key on line 7.
fn key_dir() -> (tempfile::TempDir, PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("aws_access_key", 11);
    let text = format!("one\ntwo\nthree\nfour\nfive\nsix\nlet id = \"{key}\";\neight\n");
    let file = dir.path().join("key.txt");
    fs::write(&file, text).unwrap();
    (dir, file, key)
}

#[test]
fn exit_0_below() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-at", "secret=99"])
        .assert()
        .code(0);
}

#[test]
fn exit_1_above() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-at", "secret=80"])
        .assert()
        .code(1);
}

/// A work directory holding `generic.txt`: a generated generic `api_key`
/// assignment, which scores secret 80.0.
fn generic_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let line = synth::fake_secret("generic_api_key_assignment", 5);
    fs::write(dir.path().join("generic.txt"), format!("{line}\n")).unwrap();
    dir
}

#[test]
fn fail_at_is_inclusive() {
    let dir = generic_dir();
    riskgrep(dir.path())
        .args(["scan", "generic.txt", "--format", "json"])
        .assert()
        .stdout(predicate::str::contains("\"secret\": 80.0"));
    riskgrep(dir.path())
        .args(["scan", "generic.txt", "--fail-at", "secret=80"])
        .assert()
        .code(1);
    riskgrep(dir.path())
        .args(["scan", "generic.txt", "--fail-at", "secret=80.1"])
        .assert()
        .code(0);
}

#[test]
fn fail_above_is_removed() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-above", "secret=80"])
        .assert()
        .code(3);
}

#[test]
fn no_threshold_exits_0_with_findings() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "key.txt"])
        .assert()
        .code(0);
}

#[test]
fn exit_2_unscanned_blocks() {
    if running_as_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("locked.txt");
    fs::write(&file, "hello\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    riskgrep(dir.path())
        .args(["scan", "locked.txt", "--fail-at", "secret=80"])
        .assert()
        .code(2);
    // Block is also selectable without a threshold.
    riskgrep(dir.path())
        .args(["scan", "locked.txt", "--on-error", "block"])
        .assert()
        .code(2);
    // Allow is the default without a threshold, and still names the target.
    riskgrep(dir.path())
        .args(["scan", "locked.txt"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            "locked.txt  unscanned: unreadable",
        ));
    riskgrep(dir.path())
        .args([
            "scan",
            "locked.txt",
            "--fail-at",
            "secret=80",
            "--on-error",
            "allow",
        ])
        .assert()
        .code(0);
}

#[test]
fn threshold_exceeded_wins_over_unscanned() {
    if running_as_root() {
        return;
    }
    let (dir, _, _) = key_dir();
    let locked = dir.path().join("locked.txt");
    fs::write(&locked, "x\n").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "locked.txt", "--fail-at", "secret=80"])
        .assert()
        .code(1);
}

#[test]
fn exit_3_bad_flag() {
    let dir = tempfile::tempdir().unwrap();
    riskgrep(dir.path())
        .args(["scan", "--no-such-flag"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("--no-such-flag"));
    riskgrep(dir.path())
        .args(["scan", "--format", "xml"])
        .assert()
        .code(3);
    riskgrep(dir.path()).args(["frobnicate"]).assert().code(3);
}

#[test]
fn exit_3_unknown_category() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-at", "nonsense=50"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("nonsense"));
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-at", "secret=lots"])
        .assert()
        .code(3);
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--category", "nonsense"])
        .assert()
        .code(3);
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--ruleset", "nonsense"])
        .assert()
        .code(3);
}

#[test]
fn exit_3_bad_config() {
    let home = tempfile::tempdir().unwrap();
    let cfg = home.path().join(".config/riskgrep");
    fs::create_dir_all(&cfg).unwrap();
    fs::write(cfg.join("config.toml"), "this is = not [valid\n").unwrap();
    let (dir, _, _) = key_dir();
    riskgrep_in(home.path(), dir.path())
        .args(["scan", "key.txt"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("config.toml"));
}

#[test]
fn stdin_dash() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("aws_access_key", 12);
    let out = riskgrep(dir.path())
        .args(["scan", "-", "--format", "json"])
        .write_stdin(format!("let id = \"{key}\";\n"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["targets"][0]["target"], "<stdin>");
    assert_eq!(v["targets"][0]["scores"]["secret"], 95.0);
    assert!(!String::from_utf8_lossy(&out).contains(&key));
}

#[test]
fn stdin_and_paths_together() {
    let (dir, _, _) = key_dir();
    let key = synth::fake_secret("aws_access_key", 13);
    let out = riskgrep(dir.path())
        .args(["scan", "-", "key.txt", "--format", "json"])
        .write_stdin(format!("let id = \"{key}\";\n"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let targets = v["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["target"], "<stdin>");
    assert_eq!(targets[1]["target"], "key.txt");
    assert_eq!(v["summary"]["targets"], 2);
}

#[test]
fn json_matches_model() {
    let (dir, file, key) = key_dir();
    let out = riskgrep(dir.path())
        .args(["scan", file.to_str().unwrap(), "--format", "json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let cli: serde_json::Value = serde_json::from_slice(&out).unwrap();

    let mut rg = riskgrep_core::RiskGrep::with_cache_dir(
        riskgrep_core::Config::default(),
        None,
        Some(shared_home().join("model-cache")),
    )
    .unwrap();
    let report = rg.scan_paths(std::slice::from_ref(&file));
    let model = serde_json::to_value(&report).unwrap();
    assert_eq!(cli, model);
    assert_eq!(cli["targets"][0]["evidence"][0]["rule"], "aws_access_token");
    assert!(!String::from_utf8_lossy(&out).contains(&key));
}

#[test]
fn scan_locates_every_private_key() {
    let dir = tempfile::tempdir().unwrap();
    for f in synth::two_key_files(41) {
        fs::write(dir.path().join(f.name), f.whole()).unwrap();
        let out = riskgrep(dir.path())
            .args(["scan", f.name, "--format", "json", "--no-cache"])
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let ev = v["targets"][0]["evidence"].as_array().unwrap();
        let pk: Vec<&serde_json::Value> =
            ev.iter().filter(|e| e["rule"] == "private_key").collect();
        assert_eq!(pk.len(), 1, "{}", f.name);
        assert_eq!(pk[0]["count"], 2, "{}", f.name);
        let lines: Vec<(u64, u64)> = pk[0]["locations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                (
                    l["line_start"].as_u64().unwrap(),
                    l["line_end"].as_u64().unwrap(),
                )
            })
            .collect();
        let want: Vec<(u64, u64)> = f.keys.iter().map(|&(a, b)| (a.into(), b.into())).collect();
        assert_eq!(lines, want, "{}", f.name);
    }
}

#[test]
fn text_format_line() {
    let (dir, _, key) = key_dir();
    let out = riskgrep(dir.path())
        .args(["scan", "key.txt"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text,
        "key.txt  secret 95.0  [aws_access_token ×1, lines 7]\n\
         1 targets: 1 scanned, 0 partial, 0 skipped, 0 unscanned; max biometric 0.0, secret 95.0\n"
    );
    assert!(!text.contains(&key));
}

#[test]
fn tail_line_is_unknown_in_text_and_0_in_json() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("aws_access_key", 12);
    let mut text = synth::source_text((8 << 20) + 4096, 3);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("id = \"{key}\"\n"));
    fs::write(dir.path().join("big.txt"), text).unwrap();
    let out = riskgrep(dir.path())
        .args(["scan", "big.txt"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.contains("big.txt  secret 95.0  [aws_access_token ×1, line unknown]"),
        "{out}"
    );
    assert!(!out.contains("lines 0"), "{out}");
    assert!(!out.contains(&key));
    let out = riskgrep(dir.path())
        .args(["scan", "big.txt", "--format", "json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let loc = &v["targets"][0]["evidence"][0]["locations"][0];
    assert_eq!(loc["line_start"], 0);
    assert_eq!(loc["line_end"], 0);
}

#[test]
fn text_omits_clean_targets() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), "nothing here\n").unwrap();
    riskgrep(dir.path())
        .args(["scan", "a.txt"])
        .assert()
        .code(0)
        .stdout("1 targets: 1 scanned, 0 partial, 0 skipped, 0 unscanned; max biometric 0.0, secret 0.0\n");
}

#[test]
fn category_filter() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--category", "biometric"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains("max biometric 0.0")
                .and(predicate::str::contains("secret").not()),
        );
}

#[test]
fn default_path_is_cwd() {
    let (dir, _, _) = key_dir();
    riskgrep(dir.path())
        .args(["scan", "--fail-at", "secret=80"])
        .assert()
        .code(1);
}

#[test]
fn baseline_roundtrip() {
    let (dir, _, _) = key_dir();
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .env("GIT_CEILING_DIRECTORIES", dir.path().parent().unwrap())
        .status()
        .unwrap();
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-at", "secret=80"])
        .assert()
        .code(1);
    riskgrep(dir.path())
        .args(["baseline", "key.txt"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 fingerprint"));
    assert!(dir.path().join(".riskgrep-baseline.json").is_file());
    riskgrep(dir.path())
        .args(["scan", "key.txt", "--fail-at", "secret=80"])
        .assert()
        .code(0);
    // Creating a baseline again still sees the baselined finding.
    riskgrep(dir.path())
        .args(["baseline", "key.txt", "--out", "second.json"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 fingerprint"));
}

#[test]
fn rules_list_names_both_rulesets() {
    let dir = tempfile::tempdir().unwrap();
    riskgrep(dir.path())
        .args(["rules", "list"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::is_match(r"(?m)^secrets_core +aws_access_token +secret +95$")
                .unwrap()
                .and(
                    predicate::str::is_match(
                        r"(?m)^biometric_embeddings +npy_embedding_tensor +biometric +70$",
                    )
                    .unwrap(),
                ),
        );
}

#[test]
fn rules_compile_reports_time() {
    let dir = tempfile::tempdir().unwrap();
    riskgrep(dir.path())
        .args(["rules", "compile"])
        .assert()
        .code(0)
        .stdout(predicate::str::is_match(r"compiled \d+ rules from 2 rulesets in \d+ ms").unwrap());
}

/// Every `*.yxb` and `*.meta.json` file under `dir`.
fn bundle_files(dir: &Path) -> (usize, usize) {
    let (mut yxb, mut meta) = (0, 0);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yxb") {
                yxb += 1;
            } else if p.to_string_lossy().ends_with(".meta.json") {
                meta += 1;
            }
        }
    }
    (yxb, meta)
}

#[test]
fn rules_compile_warms_the_bundle_cache() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    assert_eq!(bundle_files(home.path()), (0, 0));
    riskgrep_in(home.path(), cwd.path())
        .args(["rules", "compile"])
        .assert()
        .code(0);
    assert_eq!(
        bundle_files(home.path()),
        (1, 1),
        "bundle and sidecar written"
    );
    // A second run reuses the cached bundle and says so.
    riskgrep_in(home.path(), cwd.path())
        .args(["rules", "compile"])
        .assert()
        .code(0)
        .stdout(predicate::str::starts_with("already compiled "));
    assert_eq!(bundle_files(home.path()), (1, 1));
}

/// Runs `git` in `dir` with a clean environment, for fixtures.
#[test]
fn walk_limit_follows_on_error() {
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir_all(repo.path().join(".git")).unwrap();
    fs::write(
        repo.path().join(".riskgrep.toml"),
        "[limits]\nwalk_files = 2\n",
    )
    .unwrap();
    let dir = repo.path().join("d");
    fs::create_dir(&dir).unwrap();
    for i in 0..4 {
        fs::write(dir.join(format!("f{i}.txt")), "clean\n").unwrap();
    }
    let run = |extra: &[&str]| {
        let mut c = riskgrep(repo.path());
        c.env("GIT_CEILING_DIRECTORIES", repo.path().parent().unwrap())
            .args(["scan", "d"])
            .args(extra);
        c.assert()
    };
    run(&["--on-error", "block"])
        .code(2)
        .stdout(predicate::str::contains(
            "unscanned: directory walk stopped at the limit of 2 files",
        ));
    run(&["--on-error", "allow"]).code(0);
}

fn git_in(dir: &Path, args: &[&str]) {
    let st = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap())
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

const LOWER_AWS: &str = "[weight_overrides]\n\"secrets_core:aws_access_token\" = 50\n";
const AWS_ROW: &str = r"(?m)^secrets_core +aws_access_token +secret +(\d+)$";

fn aws_weight(out: &[u8]) -> String {
    let text = String::from_utf8_lossy(out);
    let re = regex::Regex::new(AWS_ROW).unwrap();
    re.captures(&text).expect("aws row")[1].to_string()
}

#[test]
fn repo_config_found_by_walking_up_without_git() {
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir_all(repo.path().join(".git")).unwrap();
    fs::create_dir_all(repo.path().join("a/b")).unwrap();
    fs::write(repo.path().join(".riskgrep.toml"), LOWER_AWS).unwrap();
    let out = riskgrep_in(shared_home(), &repo.path().join("a/b"))
        .env("GIT_CEILING_DIRECTORIES", repo.path().parent().unwrap())
        .args(["rules", "list"])
        .output()
        .unwrap();
    assert_eq!(aws_weight(&out.stdout), "50");
}

#[test]
fn git_dir_is_delegated_to_git() {
    // cwd is outside the work tree, so only `git rev-parse` can name the root.
    let repo = tempfile::tempdir().unwrap();
    git_in(repo.path(), &["init", "-q"]);
    fs::write(repo.path().join(".riskgrep.toml"), LOWER_AWS).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let out = riskgrep_in(shared_home(), elsewhere.path())
        .env("GIT_DIR", repo.path().join(".git"))
        .env("GIT_WORK_TREE", repo.path())
        .args(["rules", "list"])
        .output()
        .unwrap();
    assert_eq!(aws_weight(&out.stdout), "50");
    // Without them the same directory has no repository.
    let out = riskgrep_in(shared_home(), elsewhere.path())
        .args(["rules", "list"])
        .output()
        .unwrap();
    assert_eq!(aws_weight(&out.stdout), "95");
}

#[test]
fn rules_compile_defaults_to_the_hook_rulesets() {
    // The repository narrows the rulesets; `compile` ignores that unless
    // `--repo` is given.
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir_all(repo.path().join(".git")).unwrap();
    fs::write(
        repo.path().join(".riskgrep.toml"),
        "rulesets = [\"secrets_core\"]\n",
    )
    .unwrap();
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let o = riskgrep_in(home.path(), repo.path())
            .env("GIT_CEILING_DIRECTORIES", repo.path().parent().unwrap())
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    assert!(run(&["rules", "compile"]).contains("from 2 rulesets"));
    assert!(run(&["rules", "compile", "--repo"]).contains("from 1 rulesets"));
}

#[test]
fn rules_test_passes() {
    let dir = tempfile::tempdir().unwrap();
    riskgrep(dir.path())
        .args(["rules", "test"])
        .assert()
        .code(0)
        .stdout(
            predicate::str::contains(" 0 failed")
                .and(predicate::str::contains(
                    "ok  secrets_core  aws_access_token",
                ))
                .and(predicate::str::contains(
                    "ok  biometric_embeddings  npy_float_tensor",
                )),
        );
}

// ---- cache pruning ----

mod pruning {
    use super::*;
    use std::time::{Duration, SystemTime};

    const DAY: u64 = 86_400;

    /// A fresh HOME with a cache that holds the current bundle and one
    /// evidence row, made by scanning `key.txt` once.
    struct Home {
        home: tempfile::TempDir,
        work: tempfile::TempDir,
    }

    impl Home {
        fn new() -> Home {
            let (work, _, _) = key_dir();
            Home {
                home: tempfile::tempdir().unwrap(),
                work,
            }
        }

        fn run(&self, args: &[&str]) -> Command {
            let mut c = riskgrep_in(self.home.path(), self.work.path());
            c.args(args);
            c
        }

        fn cache(&self) -> PathBuf {
            riskgrep_core::paths::cache_dir_for(
                Some(self.home.path().into()),
                Some(self.home.path().join(".cache").into()),
                cfg!(target_os = "macos"),
            )
            .unwrap()
        }

        fn marker(&self) -> PathBuf {
            self.cache().join(riskgrep_core::prune::MARKER)
        }

        fn scan(&self) {
            self.run(&["scan", "key.txt"]).assert().success();
        }

        /// A bundle of a rule set nothing uses, last written `age_days` ago.
        fn stale_bundle(&self, age_days: u64) -> PathBuf {
            set_age(
                self.cache()
                    .join("bundles")
                    .join(format!("{}.yxb", "7".repeat(64))),
                age_days,
            )
        }

        fn current_bundle(&self) -> PathBuf {
            let dir = self.cache().join("bundles");
            fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.extension().is_some_and(|e| e == "yxb")
                        && !p.to_string_lossy().contains(&"7".repeat(64))
                })
                .expect("a current bundle")
        }
    }

    fn set_age(p: PathBuf, age_days: u64) -> PathBuf {
        if !p.exists() {
            fs::write(&p, vec![0u8; 2048]).unwrap();
        }
        fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(age_days * DAY))
            .unwrap();
        p
    }

    fn stdout(c: &mut Command) -> String {
        String::from_utf8(c.assert().success().get_output().stdout.clone()).unwrap()
    }

    #[test]
    fn dry_run_reports_and_removes_nothing_then_prune_removes() {
        let h = Home::new();
        h.scan();
        let stale = h.stale_bundle(60);
        let out = stdout(&mut h.run(&["cache", "prune", "--dry-run"]));
        assert!(out.contains("Dry run: nothing was removed"), "{out}");
        assert!(
            out.contains("compiled bundles: 1 (2.0 kB); 1 kept"),
            "{out}"
        );
        assert!(stale.exists());
        let out = stdout(&mut h.run(&["cache", "prune"]));
        assert!(out.contains("Removed:"), "{out}");
        assert!(
            out.contains("compiled bundles: 1 (2.0 kB); 1 kept"),
            "{out}"
        );
        assert!(!stale.exists());
    }

    #[test]
    fn the_bundle_in_use_is_kept_however_old() {
        let h = Home::new();
        h.scan();
        let current = set_age(h.current_bundle(), 400);
        let out = stdout(&mut h.run(&["cache", "prune"]));
        assert!(out.contains("compiled bundles: 0 (0 B); 1 kept"), "{out}");
        assert!(current.exists());
    }

    #[test]
    fn a_missing_cache_has_nothing_to_prune() {
        let h = Home::new();
        let out = stdout(&mut h.run(&["cache", "prune"]));
        assert!(out.contains("nothing to prune"), "{out}");
        assert!(!h.cache().exists());
    }

    #[test]
    fn limits_must_be_positive() {
        let h = Home::new();
        h.run(&["cache", "prune", "--max-age-days", "0"])
            .assert()
            .code(3);
        h.run(&["cache", "prune", "--max-size-mb", "0"])
            .assert()
            .code(3);
    }

    #[test]
    fn scan_prunes_at_most_once_a_day() {
        let h = Home::new();
        h.scan();
        assert!(h.marker().exists(), "the first scan records a prune");
        let stale = h.stale_bundle(60);
        h.scan();
        assert!(stale.exists(), "a second scan the same day does not prune");
        let before = fs::metadata(h.marker()).unwrap().modified().unwrap();
        // The marker is two days old: the next scan prunes and renews it.
        set_age(h.marker(), 2);
        h.scan();
        assert!(!stale.exists());
        let after = fs::metadata(h.marker()).unwrap().modified().unwrap();
        assert!(after > before);
        assert!(h.current_bundle().exists());
    }

    #[test]
    fn scan_output_and_status_are_unchanged_by_pruning() {
        let h = Home::new();
        let first = h
            .run(&["scan", "key.txt", "--fail-at", "secret=50"])
            .assert()
            .code(1)
            .get_output()
            .clone();
        h.stale_bundle(60);
        set_age(h.marker(), 2);
        let second = h
            .run(&["scan", "key.txt", "--fail-at", "secret=50"])
            .assert()
            .code(1)
            .get_output()
            .clone();
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(second.stderr, b"");
    }

    #[test]
    fn scan_without_the_cache_never_prunes() {
        let h = Home::new();
        h.scan();
        let stale = h.stale_bundle(60);
        set_age(h.marker(), 2);
        h.run(&["scan", "key.txt", "--no-cache"]).assert().success();
        assert!(stale.exists());
    }

    #[test]
    fn the_user_configuration_sets_the_limits() {
        let h = Home::new();
        h.scan();
        let conf = h.home.path().join(".config/riskgrep");
        fs::create_dir_all(&conf).unwrap();
        fs::write(conf.join("config.toml"), "[cache]\nmax_age_days = 1\n").unwrap();
        let stale = h.stale_bundle(2);
        set_age(h.marker(), 2);
        h.scan();
        assert!(!stale.exists(), "2 days is over a 1 day limit");
    }

    #[test]
    fn the_hook_bundle_of_another_trusted_repository_is_kept() {
        let h = Home::new();
        // Repository B selects one ruleset and is trusted, so the hook compiles
        // that selection when it runs there.
        let b = tempfile::tempdir().unwrap();
        fs::create_dir(b.path().join(".git")).unwrap();
        fs::write(
            b.path().join(".riskgrep.toml"),
            "rulesets = [\"secrets_core\"]\n",
        )
        .unwrap();
        fs::write(b.path().join("f.txt"), "nothing\n").unwrap();
        let conf = h.home.path().join(".config/riskgrep");
        fs::create_dir_all(&conf).unwrap();
        let b_path = fs::canonicalize(b.path()).unwrap();
        fs::write(
            conf.join("config.toml"),
            format!("trusted_repos = [{:?}]\n", b_path.to_str().unwrap()),
        )
        .unwrap();
        riskgrep_in(h.home.path(), &b_path)
            .args(["scan", "f.txt"])
            .assert()
            .success();
        h.scan();
        let all: Vec<PathBuf> = fs::read_dir(h.cache().join("bundles"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "yxb"))
            .collect();
        assert_eq!(all.len(), 2, "one bundle per ruleset selection");
        for p in &all {
            set_age(p.clone(), 400);
        }
        // Pruned from a directory that is not repository B.
        let out = stdout(&mut h.run(&["cache", "prune"]));
        assert!(out.contains("compiled bundles: 0 (0 B); 2 kept"), "{out}");
        assert!(all.iter().all(|p| p.exists()));
    }
}
