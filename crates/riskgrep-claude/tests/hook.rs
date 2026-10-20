//! End-to-end tests of the `riskgrep-claude` binary: hook input on stdin,
//! a temporary HOME, a cache inside it. Secrets and embeddings are generated
//! at run time.

use riskgrep_core::synth;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Out {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl Out {
    fn decision(&self) -> (String, String) {
        let v: Value = serde_json::from_str(&self.stdout).expect("stdout is JSON");
        let h = &v["hookSpecificOutput"];
        assert_eq!(h["hookEventName"], "PreToolUse");
        (
            h["permissionDecision"].as_str().unwrap().to_string(),
            h["permissionDecisionReason"].as_str().unwrap().to_string(),
        )
    }

    fn silent(&self) {
        assert_eq!(self.stdout, "", "stdout");
        assert_eq!(self.stderr, "", "stderr");
        assert_eq!(self.code, Some(0));
    }
}

struct Env {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

const CACHE_SUBDIRS: [&str; 2] = ["Library/Caches/riskgrep", ".cache/riskgrep"];

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// A HOME whose rules cache is already compiled. A cold cache compiles the
/// rules bundle in the first scan, which takes far longer than the hook's
/// default time budget; every test copies this cache instead.
fn warm_home() -> &'static Path {
    static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        let e = Env {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        e.user_config("[claude_code]\ntime_budget_ms = 600000\n");
        let f = e.write("warm.txt", b"warm\n");
        let out = e.run("Read", json!({ "file_path": f }));
        out.silent();
        e.home
    })
    .path()
}

impl Env {
    fn new() -> Env {
        let e = Env {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        for sub in CACHE_SUBDIRS {
            let from = warm_home().join(sub);
            if from.is_dir() {
                copy_tree(&from, &e.home.path().join(sub));
            }
        }
        e
    }

    fn dir(&self) -> PathBuf {
        fs::canonicalize(self.work.path()).unwrap()
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.dir().join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        p
    }

    fn user_config(&self, toml: &str) {
        let d = self.home.path().join(".config/riskgrep");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("config.toml"), toml).unwrap();
    }

    fn git_init(&self) {
        let ok = Command::new("git")
            .args(["init", "-q"])
            .current_dir(self.dir())
            .status()
            .unwrap()
            .success();
        assert!(ok);
    }

    fn run_raw(&self, stdin: &[u8]) -> Out {
        let mut child = Command::new(env!("CARGO_BIN_EXE_riskgrep-claude"))
            .current_dir(self.dir())
            .env("HOME", self.home.path())
            .env("XDG_CACHE_HOME", self.home.path().join(".cache"))
            .env("GIT_CEILING_DIRECTORIES", self.dir().parent().unwrap())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let o = child.wait_with_output().unwrap();
        Out {
            stdout: String::from_utf8(o.stdout).unwrap(),
            stderr: String::from_utf8(o.stderr).unwrap(),
            code: o.status.code(),
        }
    }

    fn run(&self, tool: &str, tool_input: Value) -> Out {
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
            "cwd": self.dir(),
        });
        self.run_raw(input.to_string().as_bytes())
    }
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

fn embedding() -> Vec<u8> {
    synth::safetensors(&[
        ("speaker_embedding", "F32", &[1, 192]),
        ("other", "F32", &[1, 128]),
    ])
}

fn aws_file() -> String {
    format!(
        "one\ntwo\nlet id = \"{}\";\nfour\n",
        synth::fake_secret("aws_access_key", 3)
    )
}

#[test]
fn read_biometric_denied() {
    let e = Env::new();
    let f = e.write("emb.safetensors", &embedding());
    let out = e.run("Read", json!({ "file_path": f }));
    assert_eq!(out.code, Some(0));
    let (d, reason) = out.decision();
    assert_eq!(d, "deny");
    assert!(
        reason.starts_with(&format!(
            "RiskGrep: {} scored biometric 85.0 (",
            f.display()
        )),
        "{reason}"
    );
    assert!(reason.contains("safetensors_named_embedding"), "{reason}");
    assert!(reason.ends_with("Threshold: deny at 75."), "{reason}");
    // Apart from the path, the only digits are the score and the threshold.
    let rest = reason.replace(&f.display().to_string(), "");
    assert_eq!(
        rest.chars().filter(char::is_ascii_digit).count(),
        5,
        "{rest}"
    );
}

#[test]
fn read_env_secret_asks() {
    let e = Env::new();
    let f = e.write("config.env", aws_file().as_bytes());
    let (d, reason) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "ask");
    assert!(reason.contains("scored secret 95.0"), "{reason}");
    assert!(reason.ends_with("Threshold: ask at 90."), "{reason}");
    assert!(!reason.contains("AKIA"), "{reason}");
}

#[test]
fn clean_read_prints_nothing() {
    let e = Env::new();
    let f = e.write("main.rs", synth::source_text(4000, 1).as_bytes());
    e.run("Read", json!({ "file_path": f })).silent();
}

#[test]
fn notebook_read_uses_notebook_path() {
    let e = Env::new();
    let f = e.write("n.ipynb", aws_file().as_bytes());
    let (d, _) = e
        .run("NotebookRead", json!({ "notebook_path": f }))
        .decision();
    assert_eq!(d, "ask");
}

#[test]
fn bash_cat_secret_asks() {
    let e = Env::new();
    e.write("config.env", aws_file().as_bytes());
    let (d, reason) = e
        .run("Bash", json!({ "command": "cat config.env" }))
        .decision();
    assert_eq!(d, "ask");
    assert!(reason.contains("config.env scored secret 95.0"), "{reason}");
}

#[test]
fn bash_unresolved_allows_by_default() {
    let e = Env::new();
    e.write("f", b"hello\n");
    e.run("Bash", json!({ "command": "cat \"$(printf f)\"" }))
        .silent();
}

#[test]
fn bash_unresolved_follows_config() {
    let e = Env::new();
    e.user_config("[claude_code]\non_unresolved = \"ask\"\n");
    let (d, reason) = e
        .run("Bash", json!({ "command": "cat \"$(printf f)\"" }))
        .decision();
    assert_eq!(d, "ask");
    assert_eq!(
        reason,
        "RiskGrep: command reads files that could not be determined"
    );
}

#[test]
fn bash_without_files_prints_nothing() {
    let e = Env::new();
    e.run("Bash", json!({ "command": "echo hi" })).silent();
}

#[test]
fn grep_dir_with_embedding_denied() {
    let e = Env::new();
    e.write("a/emb.safetensors", &embedding());
    e.write("a/clean.txt", b"nothing here\n");
    let (d, reason) = e
        .run("Grep", json!({ "pattern": "x", "path": e.dir() }))
        .decision();
    assert_eq!(d, "deny");
    assert!(
        reason.contains("emb.safetensors scored biometric 85.0"),
        "{reason}"
    );
}

#[test]
fn grep_defaults_to_cwd() {
    let e = Env::new();
    e.write("emb.safetensors", &embedding());
    let (d, _) = e.run("Grep", json!({ "pattern": "x" })).decision();
    assert_eq!(d, "deny");
}

#[test]
fn grep_honours_gitignore_and_skips_hidden() {
    let e = Env::new();
    e.git_init();
    e.write(".gitignore", b"skipped/\n");
    e.write("skipped/emb.safetensors", &embedding());
    e.write(".hidden/emb.safetensors", &embedding());
    e.write("clean.txt", b"fine\n");
    e.run("Grep", json!({ "pattern": "x" })).silent();
}

#[test]
fn grep_glob_and_type_filter() {
    let e = Env::new();
    e.write("emb.safetensors", &embedding());
    e.write("notes.txt", b"plain\n");
    e.run("Grep", json!({ "pattern": "x", "glob": "*.txt" }))
        .silent();
    e.run("Grep", json!({ "pattern": "x", "type": "txt" }))
        .silent();
    let (d, _) = e
        .run("Grep", json!({ "pattern": "x", "glob": "*.safetensors" }))
        .decision();
    assert_eq!(d, "deny");
}

#[test]
fn grep_walk_limit_applies_on_error() {
    let e = Env::new();
    e.user_config("[limits]\nwalk_files = 2\n");
    for i in 0..5 {
        e.write(&format!("f{i}.txt"), b"plain\n");
    }
    let (d, reason) = e.run("Grep", json!({ "pattern": "x" })).decision();
    assert_eq!(d, "ask");
    assert!(reason.contains("walk limit"), "{reason}");
    assert!(reason.contains(&e.dir().display().to_string()), "{reason}");
}

#[test]
fn unreadable_file_asks() {
    if running_as_root() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let e = Env::new();
    let f = e.write("secret.txt", b"data\n");
    fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
    let out = e.run("Read", json!({ "file_path": f }));
    let (d, reason) = out.decision();
    assert_eq!(d, "ask");
    assert!(
        reason.starts_with(&format!("RiskGrep: could not scan {}", f.display())),
        "{reason}"
    );
}

#[test]
fn missing_file_prints_nothing() {
    let e = Env::new();
    let f: &Path = &e.dir().join("absent.txt");
    e.run("Read", json!({ "file_path": f })).silent();
}

#[test]
fn untrusted_repo_config_ignored() {
    let e = Env::new();
    e.git_init();
    e.write(
        ".riskgrep.toml",
        b"[claude_code.thresholds.biometric]\ndeny = 99\n",
    );
    let f = e.write("emb.safetensors", &embedding());
    let (d, _) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "deny");
}

#[test]
fn trusted_repo_config_is_read() {
    // Positive control for the test above: once the repository is trusted,
    // the same file changes the outcome (85 < 99 deny, but still >= 50 ask).
    let e = Env::new();
    e.git_init();
    e.user_config(&format!(
        "trusted_repos = [{:?}]\n",
        e.dir().display().to_string()
    ));
    e.write(
        ".riskgrep.toml",
        b"[claude_code.thresholds.biometric]\ndeny = 99\n",
    );
    let f = e.write("emb.safetensors", &embedding());
    let (d, _) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "ask");
}

#[test]
fn nested_directory_finds_repo_root_and_worktree_file() {
    // A subdirectory of a trusted repository, and a `.git` file as in
    // worktrees: both identify the repository root without spawning git.
    let e = Env::new();
    e.write("repo/.git", b"gitdir: /nonexistent\n");
    e.write(
        "repo/.riskgrep.toml",
        b"[claude_code.thresholds.biometric]\ndeny = 99\n",
    );
    e.user_config(&format!(
        "trusted_repos = [{:?}]\n",
        e.dir().join("repo").display().to_string()
    ));
    let f = e.write("repo/sub/emb.safetensors", &embedding());
    let input = json!({
        "hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": f}, "cwd": e.dir().join("repo/sub"),
    });
    let (d, _) = e.run_raw(input.to_string().as_bytes()).decision();
    assert_eq!(d, "ask");
}

#[test]
fn timeout_asks() {
    let e = Env::new();
    e.user_config("[claude_code]\ntime_budget_ms = 1\n");
    let f = e.write("big.txt", synth::source_text(5 << 20, 2).as_bytes());
    let (d, reason) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "ask");
    assert_eq!(reason, "RiskGrep: scan exceeded time budget");
}

#[test]
fn unknown_tool_silent() {
    let e = Env::new();
    e.run("WebFetch", json!({ "url": "https://example.com" }))
        .silent();
}

#[test]
fn malformed_input_asks_and_exits_zero() {
    let e = Env::new();
    for bad in [&b"not json"[..], b"[]", b"{}", b""] {
        let out = e.run_raw(bad);
        assert_eq!(out.code, Some(0));
        assert_eq!(out.stderr, "");
        let (d, reason) = out.decision();
        assert_eq!(d, "ask");
        assert_eq!(reason, "RiskGrep: unreadable hook input");
    }
}

#[test]
fn malformed_input_follows_on_error() {
    let e = Env::new();
    e.user_config("[claude_code]\non_error = \"allow\"\n");
    e.run_raw(b"not json").silent();
}

#[test]
fn never_allows() {
    let e = Env::new();
    let clean = e.write("main.rs", synth::source_text(500, 1).as_bytes());
    let secret = e.write("config.env", aws_file().as_bytes());
    let emb = e.write("emb.safetensors", &embedding());
    for f in [&clean, &secret, &emb] {
        let out = e.run("Read", json!({ "file_path": f }));
        assert!(!out.stdout.contains("allow"), "{}", out.stdout);
    }
    e.user_config("[claude_code]\non_error = \"allow\"\n");
    let out = e.run_raw(b"not json");
    assert!(!out.stdout.contains("allow"), "{}", out.stdout);
}

#[test]
fn print_config_outputs_settings_block() {
    let e = Env::new();
    let o = Command::new(env!("CARGO_BIN_EXE_riskgrep-claude"))
        .arg("print-config")
        .env("HOME", e.home.path())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let h = &v["hooks"]["PreToolUse"][0];
    assert_eq!(h["matcher"], "Read|NotebookRead|Grep|Bash");
    assert_eq!(h["hooks"][0]["command"], "riskgrep-claude");
    assert_eq!(h["hooks"][0]["timeout"], 5);
    assert_eq!(
        v["permissions"]["deny"],
        json!([
            "Edit(~/.config/riskgrep/**)",
            "Write(~/.config/riskgrep/**)"
        ])
    );
    assert!(String::from_utf8(o.stderr)
        .unwrap()
        .contains("settings.json"));
}
