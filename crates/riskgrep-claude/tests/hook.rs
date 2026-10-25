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
    assert!(reason.contains("Threshold: deny at 75. "), "{reason}");
    assert!(reason.ends_with(NO_PARTIAL), "{reason}");
    // Apart from the path, the only digits are the score and the threshold.
    let rest = reason.replace(&f.display().to_string(), "");
    assert_eq!(
        rest.chars().filter(char::is_ascii_digit).count(),
        5,
        "{rest}"
    );
}

#[test]
fn read_env_secret_denied() {
    let e = Env::new();
    let f = e.write("config.env", aws_file().as_bytes());
    let (d, reason) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "deny");
    assert!(reason.contains("scored secret 95.0"), "{reason}");
    assert!(reason.contains("Threshold: deny at 95."), "{reason}");
    assert!(!reason.contains("AKIA"), "{reason}");
}

#[test]
fn read_generic_secret_asks() {
    // The generic rule scores 80: the default secret `ask` threshold.
    let e = Env::new();
    let line = synth::fake_secret("generic_api_key_assignment", 1);
    let f = e.write("settings.env", format!("x = 1\n{line}\n").as_bytes());
    let (d, reason) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "ask");
    assert!(reason.contains("scored secret 80.0"), "{reason}");
    assert!(reason.contains("Threshold: ask at 80."), "{reason}");
}

const NO_PARTIAL: &str = "No partial read is available for this file; ask the user.";
const SAFE_PATHS: &str = "Do not read this file by other means (Bash, Grep, scripts). To use the rest of it, Read it with offset and limit ranges that exclude the lines above, or ask the user.";

/// `n` filler lines (`line N`), with `at` lines replaced: (line number, text).
fn numbered(n: usize, at: &[(usize, String)]) -> String {
    let mut out = String::new();
    for i in 1..=n {
        match at.iter().find(|(l, _)| *l == i) {
            Some((_, text)) => out.push_str(text),
            None => out.push_str(&format!("line {i}")),
        }
        out.push('\n');
    }
    out
}

fn aws_line(seed: u64) -> String {
    format!("id = \"{}\"", synth::fake_secret("aws_access_key", seed))
}

/// The decision for a `Read` of `f` with optional `offset` and `limit`:
/// `"none"` when the hook prints nothing.
fn read_decision(e: &Env, f: &Path, offset: Option<u64>, limit: Option<u64>) -> (String, String) {
    let mut input = json!({ "file_path": f });
    if let Some(o) = offset {
        input["offset"] = json!(o);
    }
    if let Some(l) = limit {
        input["limit"] = json!(l);
    }
    let out = e.run("Read", input);
    if out.stdout.is_empty() {
        out.silent();
        return ("none".into(), String::new());
    }
    out.decision()
}

#[test]
fn read_range_around_a_secret_line() {
    let e = Env::new();
    let f = e.write("app.env", numbered(30, &[(10, aws_line(5))]).as_bytes());
    let d = |o, l| read_decision(&e, &f, o, l).0;
    assert_eq!(d(Some(1), Some(8)), "none");
    // Widened by one line on each side, lines 1-9 touch line 10.
    assert_eq!(d(Some(1), Some(9)), "deny");
    assert_eq!(d(Some(12), Some(10)), "none");
    assert_eq!(d(Some(5), Some(10)), "deny");
    assert_eq!(d(None, Some(8)), "none");
    assert_eq!(d(Some(12), None), "none");
    assert_eq!(d(Some(11), None), "deny");
    let (d, reason) = read_decision(&e, &f, None, None);
    assert_eq!(d, "deny");
    assert_eq!(
        reason,
        format!(
            "RiskGrep: {} scored secret 95.0 (aws_access_token) on line 10. Threshold: deny at 95. {SAFE_PATHS}",
            f.display()
        )
    );
    // Values that are not positive integers judge the whole file.
    for bad in [
        json!({"offset": 0, "limit": 5}),
        json!({"offset": 12.0, "limit": 5}),
        json!({"offset": "12"}),
    ] {
        let mut input = bad.clone();
        input["file_path"] = json!(f);
        let (d, _) = e.run("Read", input).decision();
        assert_eq!(d, "deny", "{bad}");
    }
}

#[test]
fn read_range_counts_crlf_lines_as_claude_code_does() {
    // Claude Code 2.1.301 splits on LF and drops one CR before it; a lone
    // CR does not end a line. RiskGrep counts LF bytes the same way.
    let e = Env::new();
    let mut text = numbered(30, &[(10, aws_line(13))]).replace('\n', "\r\n");
    text = text.replacen("line 2\r\n", "line 2\rstill line 2\r\n", 1);
    let f = e.write("crlf.env", text.as_bytes());
    let (_, reason) = read_decision(&e, &f, None, None);
    assert!(reason.contains(") on line 10."), "{reason}");
    assert_eq!(read_decision(&e, &f, Some(1), Some(8)).0, "none");
    assert_eq!(read_decision(&e, &f, Some(1), Some(9)).0, "deny");
}

#[test]
fn no_partial_read_for_a_pem_block() {
    // `private_key` can match across lines, so its locations are not
    // complete and every read of the file is judged whole.
    let e = Env::new();
    let pem = synth::fake_pem("RSA PRIVATE KEY", 144, 6);
    let at: Vec<(usize, String)> = pem
        .lines()
        .enumerate()
        .map(|(i, l)| (3 + i, l.to_string()))
        .collect();
    let f = e.write("key.txt", numbered(12, &at).as_bytes());
    for (o, l) in [(1, 1), (2, 1), (9, 4), (5, 1)] {
        let (d, reason) = read_decision(&e, &f, Some(o), Some(l));
        assert_eq!(d, "deny", "offset {o} limit {l}");
        assert!(reason.ends_with(NO_PARTIAL), "{reason}");
    }
}

#[test]
fn no_partial_read_reaches_a_second_private_key() {
    let e = Env::new();
    for k in synth::two_key_files(61) {
        let f = e.write(k.name, k.whole().as_bytes());
        let (first, last) = k.keys[1];
        let (d, reason) =
            read_decision(&e, &f, Some(first.into()), Some((last - first + 1).into()));
        assert_eq!(d, "deny", "{}", k.name);
        assert!(reason.ends_with(NO_PARTIAL), "{}: {reason}", k.name);
        // A range that avoids both keys is judged whole too.
        let (d, _) = read_decision(&e, &f, Some(u64::from(k.keys[1].1) + 2), Some(1));
        assert_eq!(d, "deny", "{}", k.name);
    }
}

#[test]
fn no_partial_read_for_a_kubernetes_secret() {
    let e = Env::new();
    let mut lines = vec![
        "apiVersion: v1".to_string(),
        "kind: Secret".into(),
        "metadata:".into(),
        "  name: app".into(),
        "type: Opaque".into(),
        "data:".into(),
    ];
    let mut rng = synth::Rng::new(70);
    for i in 0..4 {
        let mut b = [0u8; 24];
        rng.fill(&mut b);
        let v: String = b.iter().map(|x| format!("{x:02x}")).collect();
        lines.push(format!("  key{i}: {v}"));
    }
    lines.push("---".into());
    let f = e.write("secret.yaml", format!("{}\n", lines.join("\n")).as_bytes());
    let (d, reason) = read_decision(&e, &f, None, None);
    assert_eq!(d, "ask", "{reason}");
    assert!(reason.contains("kubernetes_secret_yaml"), "{reason}");
    assert!(reason.ends_with(NO_PARTIAL), "{reason}");
    for line in 8..=10 {
        let (d, _) = read_decision(&e, &f, Some(line), Some(1));
        assert_eq!(d, "ask", "line {line}");
    }
}

#[test]
fn read_range_between_two_provider_tokens() {
    let e = Env::new();
    let gh = format!("x = \"{}\"", synth::fake_secret("github_pat", 14));
    let f = e.write(
        "tokens.env",
        numbered(30, &[(5, aws_line(15)), (20, gh)]).as_bytes(),
    );
    let (d, reason) = read_decision(&e, &f, None, None);
    assert_eq!(d, "deny");
    assert!(reason.contains(") on lines 5, 20. Threshold"), "{reason}");
    assert!(reason.ends_with(SAFE_PATHS), "{reason}");
    // Lines 7-18, widened to 6-19, avoid both tokens; 7-19 touches line 20.
    assert_eq!(read_decision(&e, &f, Some(7), Some(12)).0, "none");
    assert_eq!(read_decision(&e, &f, Some(7), Some(13)).0, "deny");
}

#[test]
fn read_range_around_tokens_that_end_their_lines() {
    // These rules' trailing delimiter can be the line feed that ends the
    // line; each token is still located on its own line.
    let e = Env::new();
    let openai = format!("id = {}", synth::fake_secret("openai_key", 3));
    let stripe = format!("other = {}", synth::fake_secret("stripe_key", 4));
    let f = e.write(
        "keys.env",
        numbered(30, &[(10, openai), (11, stripe)]).as_bytes(),
    );
    let (d, reason) = read_decision(&e, &f, None, None);
    assert_eq!(d, "deny");
    assert!(reason.contains("openai_api_key"), "{reason}");
    assert!(reason.contains("stripe_access_token"), "{reason}");
    assert!(reason.ends_with(SAFE_PATHS), "{reason}");
    assert_eq!(read_decision(&e, &f, Some(1), Some(8)).0, "none");
    assert_eq!(read_decision(&e, &f, Some(1), Some(9)).0, "deny");
    assert_eq!(read_decision(&e, &f, Some(13), None).0, "none");
    assert_eq!(read_decision(&e, &f, Some(12), None).0, "deny");
}

#[test]
fn read_range_between_two_secrets() {
    let e = Env::new();
    let f = e.write(
        "two.env",
        numbered(30, &[(5, aws_line(7)), (20, aws_line(8))]).as_bytes(),
    );
    let (_, reason) = read_decision(&e, &f, None, None);
    assert!(
        reason.contains("(aws_access_token) on lines 5, 20."),
        "{reason}"
    );
    assert_eq!(read_decision(&e, &f, Some(8), Some(9)).0, "none");
    assert_eq!(read_decision(&e, &f, Some(8), Some(14)).0, "deny");
}

#[test]
fn read_range_for_an_ask_level_secret() {
    let e = Env::new();
    e.user_config("[claude_code.thresholds.secret]\ndeny = 99\n");
    let f = e.write("app.env", numbered(30, &[(10, aws_line(16))]).as_bytes());
    let (d, reason) = read_decision(&e, &f, None, None);
    assert_eq!(d, "ask");
    assert!(
        reason.contains(") on line 10. Threshold: ask at 80."),
        "{reason}"
    );
    assert!(reason.ends_with(SAFE_PATHS), "{reason}");
    assert_eq!(read_decision(&e, &f, Some(1), Some(8)).0, "none");
    assert_eq!(read_decision(&e, &f, Some(1), Some(9)).0, "ask");
    assert_eq!(read_decision(&e, &f, Some(12), Some(5)).0, "none");
}

#[test]
fn no_partial_read_for_a_printed_embedding() {
    // The printed-float rules are not marked line-complete: a run broken
    // by a value they do not parse can leave floats outside every range.
    let e = Env::new();
    let floats = synth::printed_floats(192, synth::FloatStyle::PythonList);
    let f = e.write(
        "vec.txt",
        numbered(30, &[(10, format!("v = {floats}"))]).as_bytes(),
    );
    let (d, reason) = read_decision(&e, &f, None, None);
    assert_eq!(d, "ask");
    assert!(reason.contains("scored biometric 60.0 ("), "{reason}");
    assert!(reason.ends_with(NO_PARTIAL), "{reason}");
    assert_eq!(read_decision(&e, &f, Some(1), Some(8)).0, "ask");
}

#[test]
fn no_partial_read_for_a_sampled_file() {
    let e = Env::new();
    e.user_config("[claude_code]\ntime_budget_ms = 600000\n");
    let mut text = numbered(30, &[(10, aws_line(9))]);
    text.push_str(&synth::source_text(9 << 20, 3));
    let f = e.write("big.env", text.as_bytes());
    let (d, reason) = read_decision(&e, &f, Some(12), Some(5));
    assert_eq!(d, "deny");
    assert!(reason.ends_with(NO_PARTIAL), "{reason}");
    assert!(!reason.contains(" on line"), "{reason}");
}

/// A PKCS#1-shaped DER key header followed by random bytes.
fn der_key() -> Vec<u8> {
    let mut b = vec![0x30, 0x46, 0x02, 0x01, 0x00, 0x02];
    let mut body = vec![0u8; 0x40];
    synth::Rng::new(10).fill(&mut body);
    b.extend(body);
    b
}

#[test]
fn no_partial_read_for_structural_findings() {
    let e = Env::new();
    let cases = [
        ("DER key", e.write("id.der", &der_key()), "ask"),
        (
            "embedding",
            e.write("emb.safetensors", &embedding()),
            "deny",
        ),
        (
            "path rule",
            e.write("cert.p12", b"line 1\nline 2\nline 3\n"),
            "ask",
        ),
    ];
    for (what, f, want) in &cases {
        let (d, reason) = read_decision(&e, f, Some(2), Some(1));
        assert_eq!(&d, want, "{what}: {reason}");
        assert!(reason.ends_with(NO_PARTIAL), "{what}: {reason}");
        assert!(!reason.contains(" on line"), "{what}: {reason}");
    }
}

#[test]
fn grep_and_bash_ignore_read_ranges() {
    let e = Env::new();
    let f = e.write("app.env", numbered(30, &[(10, aws_line(11))]).as_bytes());
    let (d, _) = e
        .run(
            "Grep",
            json!({ "pattern": "x", "path": f, "offset": 1, "limit": 8 }),
        )
        .decision();
    assert_eq!(d, "deny");
    let (d, _) = e
        .run(
            "Bash",
            json!({ "command": "sed -n 1,8p app.env", "offset": 1, "limit": 8 }),
        )
        .decision();
    assert_eq!(d, "deny");
}

#[test]
fn cached_runs_decide_as_uncached_runs() {
    let e = Env::new();
    let text = e.write("app.env", numbered(30, &[(10, aws_line(12))]).as_bytes());
    let der = e.write("id.der", &der_key());
    let calls = [
        (&text, None, None),
        (&text, Some(1), Some(8)),
        (&text, Some(1), Some(9)),
        (&der, Some(5), Some(1)),
        (&der, None, None),
    ];
    let first: Vec<(String, String)> = calls
        .iter()
        .map(|(f, o, l)| read_decision(&e, f, *o, *l))
        .collect();
    let second: Vec<(String, String)> = calls
        .iter()
        .map(|(f, o, l)| read_decision(&e, f, *o, *l))
        .collect();
    assert_eq!(first, second);
    let kinds: Vec<&str> = first.iter().map(|d| d.0.as_str()).collect();
    assert_eq!(kinds, ["deny", "none", "deny", "ask", "ask"]);
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
    assert_eq!(d, "deny");
}

#[test]
fn bash_cat_secret_denied() {
    let e = Env::new();
    e.write("config.env", aws_file().as_bytes());
    let (d, reason) = e
        .run("Bash", json!({ "command": "cat config.env" }))
        .decision();
    assert_eq!(d, "deny");
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
fn grep_honours_gitignore_and_skips_vcs_directories() {
    // Claude Code 2.1.301 runs rg with `--hidden` and `--glob !NAME` for
    // each of these directories; `.gitignore` still applies.
    let e = Env::new();
    e.git_init();
    e.write(".gitignore", b"skipped/\n");
    e.write("skipped/emb.safetensors", &embedding());
    for vcs in [".git", ".svn", ".hg", ".bzr", ".jj", ".sl"] {
        e.write(&format!("{vcs}/emb.safetensors"), &embedding());
    }
    e.write("clean.txt", b"fine\n");
    e.run("Grep", json!({ "pattern": "x" })).silent();
}

#[test]
fn grep_searches_hidden_files() {
    let e = Env::new();
    e.write("h/.env", aws_file().as_bytes());
    e.write("h/readme.md", b"hello\n");
    let (d, reason) = e
        .run("Grep", json!({ "pattern": "x", "path": e.dir().join("h") }))
        .decision();
    assert_eq!(d, "deny");
    assert!(reason.contains("h/.env scored secret 95.0"), "{reason}");

    e.write("k/.aws/credentials", aws_file().as_bytes());
    let (d, reason) = e
        .run("Grep", json!({ "pattern": "x", "path": e.dir().join("k") }))
        .decision();
    assert_eq!(d, "deny");
    assert!(
        reason.contains("k/.aws/credentials scored secret 95.0"),
        "{reason}"
    );
}

#[test]
fn grep_glob_splits_like_claude_code() {
    let e = Env::new();
    e.write("g/x.env", aws_file().as_bytes());
    e.write("g/y.md", b"hello\n");
    let dir = e.dir().join("g");
    e.run(
        "Grep",
        json!({ "pattern": "x", "path": dir, "glob": "*.md" }),
    )
    .silent();
    for glob in ["*.md,*.env", "*.md *.env", "*.{md,env}", " *.md,, *.env "] {
        let (d, reason) = e
            .run("Grep", json!({ "pattern": "x", "path": dir, "glob": glob }))
            .decision();
        assert_eq!(d, "deny", "glob {glob:?}");
        assert!(reason.contains("x.env scored secret 95.0"), "{reason}");
    }
}

#[test]
fn grep_path_is_trimmed_and_tilde_expanded() {
    let e = Env::new();
    let home = e.home.path();
    fs::create_dir_all(home.join("proj")).unwrap();
    fs::write(home.join("proj/a.txt"), aws_file()).unwrap();
    for path in ["~/proj", " ~/proj ", "~/proj/a.txt", "~"] {
        let (d, reason) = e
            .run("Grep", json!({ "pattern": "x", "path": path }))
            .decision();
        assert_eq!(d, "deny", "path {path:?}");
        assert!(reason.contains("proj/a.txt scored secret 95.0"), "{reason}");
    }
}

#[test]
fn read_on_a_directory_is_ignored() {
    let e = Env::new();
    e.write("d/config.env", aws_file().as_bytes());
    e.run("Read", json!({ "file_path": e.dir().join("d") }))
        .silent();
}

#[test]
fn config_error_reason_names_position_not_content() {
    let e = Env::new();
    e.user_config("[claude_code]\nbogus_key = 1\n");
    let f = e.write("a.txt", b"hello\n");
    let (d, reason) = e.run("Read", json!({ "file_path": f })).decision();
    assert_eq!(d, "ask");
    let cfg = e.home.path().join(".config/riskgrep/config.toml");
    assert_eq!(
        reason,
        format!(
            "RiskGrep: configuration error (invalid config {} at line 2, column 1)",
            cfg.display()
        )
    );
}

#[test]
fn bash_home_pwd_and_tilde_are_expanded() {
    let e = Env::new();
    let home = e.home.path();
    fs::create_dir_all(home.join("proj")).unwrap();
    fs::write(home.join("proj/a.txt"), aws_file()).unwrap();
    e.write("a.txt", aws_file().as_bytes());
    for command in [
        "cat \"$PWD/a.txt\"",
        "cat ${PWD}/a.txt",
        "cat $HOME/proj/a.txt",
        "cat \"${HOME}\"/proj/a.txt",
        "cat ~/proj/a.txt",
    ] {
        let (d, reason) = e.run("Bash", json!({ "command": command })).decision();
        assert_eq!(d, "deny", "{command}");
        assert!(reason.contains("a.txt scored secret 95.0"), "{reason}");
    }
}

#[test]
fn bash_home_pwd_stay_unresolved_after_a_change() {
    let e = Env::new();
    let home = e.home.path();
    fs::create_dir_all(home.join("proj")).unwrap();
    fs::write(home.join("proj/a.txt"), aws_file()).unwrap();
    e.write("a.txt", aws_file().as_bytes());
    e.write("d/a.txt", b"hello\n");
    let commands = [
        "HOME=/x cat $HOME/proj/a.txt",
        "export HOME=/x; cat ~/proj/a.txt",
        "cd d && cat $PWD/a.txt",
        "pushd d; cat \"$PWD/a.txt\"",
    ];
    // Under the default `on_unresolved = "allow"` nothing is scanned.
    for command in commands {
        e.run("Bash", json!({ "command": command })).silent();
    }
    e.user_config("[claude_code]\non_unresolved = \"deny\"\n");
    for command in commands {
        let (d, reason) = e.run("Bash", json!({ "command": command })).decision();
        assert_eq!(d, "deny", "{command}");
        assert_eq!(
            reason, "RiskGrep: command reads files that could not be determined",
            "{command}"
        );
    }
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
fn unknown_non_mcp_tool_silent_even_when_unresolved_asks() {
    let e = Env::new();
    e.user_config("[claude_code]\non_unresolved = \"ask\"\n");
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
    assert_eq!(h["matcher"], "^(Read|NotebookRead|Grep|Glob|Bash|mcp__.*)$");
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

// ---- MCP tools and Glob ----

const FS_READ: &str = "mcp__filesystem__read_text_file";
const FS_MANY: &str = "mcp__filesystem__read_multiple_files";
const DC_READ: &str = "mcp__plugin_desktop-commander_desktop-commander__read_file";

#[test]
fn mcp_read_of_flagged_file_denies() {
    let e = Env::new();
    let f = e.write("config.env", aws_file().as_bytes());
    for tool in [FS_READ, DC_READ] {
        let (d, reason) = e.run(tool, json!({ "path": f })).decision();
        assert_eq!(d, "deny", "{tool}");
        assert!(reason.contains("config.env scored secret 95.0"), "{reason}");
    }
    // A relative path resolves against the hook's cwd, as for Read.
    let (d, _) = e.run(FS_READ, json!({ "path": "config.env" })).decision();
    assert_eq!(d, "deny");
}

#[test]
fn mcp_read_of_clean_or_missing_file_prints_nothing() {
    let e = Env::new();
    let f = e.write("clean.txt", b"nothing here\n");
    e.run(FS_READ, json!({ "path": f })).silent();
    e.run(FS_READ, json!({ "path": "missing.txt" })).silent();
    e.run(FS_READ, json!({ "path": e.dir() })).silent();
}

#[test]
fn mcp_list_of_paths_scans_each() {
    let e = Env::new();
    let clean = e.write("clean.txt", b"nothing here\n");
    let emb = e.write("emb.safetensors", &embedding());
    let (d, reason) = e.run(FS_MANY, json!({ "paths": [clean, emb] })).decision();
    assert_eq!(d, "deny");
    assert!(
        reason.contains("emb.safetensors scored biometric"),
        "{reason}"
    );
    e.run(FS_MANY, json!({ "paths": [clean] })).silent();
}

#[test]
fn mcp_malformed_path_field_is_unresolved() {
    let e = Env::new();
    let clean = e.write("clean.txt", b"nothing here\n");
    let bad = [
        json!({}),
        json!({ "path": 7 }),
        json!({ "path": { "p": "clean.txt" } }),
    ];
    for input in &bad {
        e.run(FS_READ, input.clone()).silent();
    }
    e.run(FS_MANY, json!({ "paths": [clean, 3] })).silent();
    e.user_config("[claude_code]\non_unresolved = \"ask\"\n");
    for input in &bad {
        let (d, reason) = e.run(FS_READ, input.clone()).decision();
        assert_eq!(d, "ask", "{input}");
        assert_eq!(
            reason,
            format!("RiskGrep: could not determine the files {FS_READ} reads")
        );
    }
    let (d, _) = e.run(FS_MANY, json!({ "paths": [clean, 3] })).decision();
    assert_eq!(d, "ask");
}

#[test]
fn unmapped_mcp_tool_follows_on_unresolved() {
    let e = Env::new();
    let f = e.write("config.env", aws_file().as_bytes());
    let tool = "mcp__other__open_file";
    // The default, `allow`: no decision.
    e.run(tool, json!({ "path": f })).silent();
    e.user_config("[claude_code]\non_unresolved = \"ask\"\n");
    let (d, reason) = e.run(tool, json!({ "path": f })).decision();
    assert_eq!(d, "ask");
    assert_eq!(
        reason,
        format!("RiskGrep: could not determine the files {tool} reads")
    );
    // A tool mapped as reading nothing gets no decision.
    e.run("mcp__filesystem__write_file", json!({ "path": f }))
        .silent();
}

#[test]
fn user_added_mcp_entry_is_used() {
    let e = Env::new();
    let f = e.write("config.env", aws_file().as_bytes());
    e.user_config(
        "[claude_code.mcp_tools.\"mcp__notes__open\"]\npaths = [\"file\"]\n\n\
         [claude_code.mcp_tools.\"mcp__notes__*\"]\nkind = \"none\"\n",
    );
    let (d, _) = e.run("mcp__notes__open", json!({ "file": f })).decision();
    assert_eq!(d, "deny");
    e.run("mcp__notes__list", json!({ "file": f })).silent();
}

#[test]
fn malformed_mcp_entry_is_a_configuration_error() {
    let e = Env::new();
    e.user_config("[claude_code.mcp_tools.\"mcp__notes__open\"]\nkind = \"read\"\n");
    let (d, reason) = e.run("mcp__notes__open", json!({ "file": "x" })).decision();
    assert_eq!(d, "ask");
    assert!(
        reason.starts_with("RiskGrep: configuration error ("),
        "{reason}"
    );
}

#[test]
fn mcp_walk_scans_files_under_the_directory() {
    let e = Env::new();
    e.write("a/emb.safetensors", &embedding());
    e.write("a/clean.txt", b"nothing here\n");
    e.write("b/clean.txt", b"nothing here\n");
    let tool = "mcp__desktop-commander__start_search";
    let (d, reason) = e
        .run(tool, json!({ "path": e.dir().join("a"), "pattern": "x" }))
        .decision();
    assert_eq!(d, "deny");
    assert!(
        reason.contains("emb.safetensors scored biometric"),
        "{reason}"
    );
    e.run(tool, json!({ "path": "b", "pattern": "x" })).silent();
}

/// A name the path rules flag at secret 90 (`pkcs12_file`): `ask` by
/// default. The content is not read, so it is irrelevant.
const KEY_NAME: &str = "cert.p12";

#[test]
fn glob_revealing_a_flagged_name_asks() {
    let e = Env::new();
    e.write(&format!("keys/{KEY_NAME}"), b"x");
    e.write("src/main.rs", b"fn main() {}\n");
    let (d, reason) = e.run("Glob", json!({ "pattern": "**/*.p12" })).decision();
    assert_eq!(d, "ask");
    assert!(
        reason.starts_with(&format!(
            "RiskGrep: file name keys/{KEY_NAME} scored secret 90.0 (pkcs12_file)"
        )),
        "{reason}"
    );
    assert!(!reason.contains("Do not read"), "{reason}");
    // `path` narrows the search.
    let (d, _) = e
        .run(
            "Glob",
            json!({ "pattern": "*", "path": e.dir().join("keys") }),
        )
        .decision();
    assert_eq!(d, "ask");
    e.run("Glob", json!({ "pattern": "*", "path": "src" }))
        .silent();
}

#[test]
fn glob_judges_names_not_content() {
    let e = Env::new();
    e.write("config.env", aws_file().as_bytes());
    e.write("emb.safetensors", &embedding());
    e.run("Glob", json!({ "pattern": "**/*" })).silent();
    e.run("Glob", json!({ "pattern": "*.txt" })).silent();
}

#[test]
fn glob_name_rule_weight_meets_configured_threshold() {
    let e = Env::new();
    e.write("voices/voiceprint_a.bin", b"x");
    // `path_biometric_name` weighs 30, below the default ask threshold.
    e.run("Glob", json!({ "pattern": "voices/*" })).silent();
    e.user_config("[claude_code.thresholds.biometric]\nask = 30\n");
    let (d, reason) = e.run("Glob", json!({ "pattern": "voices/*" })).decision();
    assert_eq!(d, "ask");
    assert!(reason.contains("path_biometric_name"), "{reason}");
}

#[test]
fn mcp_names_tool_respects_depth() {
    let e = Env::new();
    e.write(&format!("top/{KEY_NAME}"), b"x");
    e.write(&format!("deep/sub/{KEY_NAME}"), b"x");
    let list = "mcp__filesystem__list_directory";
    let (d, _) = e.run(list, json!({ "path": "top" })).decision();
    assert_eq!(d, "ask");
    e.run(list, json!({ "path": "deep" })).silent();
    let (d, _) = e
        .run("mcp__filesystem__directory_tree", json!({ "path": "deep" }))
        .decision();
    assert_eq!(d, "ask");
}

#[test]
fn names_follow_a_symlinked_root() {
    let e = Env::new();
    e.write(&format!("real/keys/{KEY_NAME}"), b"x");
    std::os::unix::fs::symlink(e.dir().join("real"), e.dir().join("link")).unwrap();
    let (d, _) = e
        .run("mcp__filesystem__directory_tree", json!({ "path": "link" }))
        .decision();
    assert_eq!(d, "ask");
    let (d, _) = e
        .run("Glob", json!({ "pattern": "**/*.p12", "path": "link" }))
        .decision();
    assert_eq!(d, "ask");
}

#[test]
fn glob_pattern_may_climb_out_of_path() {
    let e = Env::new();
    e.write(&format!("keys/{KEY_NAME}"), b"x");
    e.write("sub/clean.txt", b"x");
    for pattern in ["../keys/*.p12", "./../keys/*"] {
        let (d, _) = e
            .run("Glob", json!({ "pattern": pattern, "path": "sub" }))
            .decision();
        assert_eq!(d, "ask", "{pattern}");
    }
    let (d, _) = e.run("Glob", json!({ "pattern": "./keys/*" })).decision();
    assert_eq!(d, "ask");
}

#[test]
fn mcp_walk_limit_names_the_root_that_reached_it() {
    let e = Env::new();
    e.write("small/a.txt", b"x\n");
    for i in 0..3 {
        e.write(&format!("big/f{i}.txt"), b"x\n");
    }
    e.user_config(
        "[limits]\nwalk_files = 2\n\n\
         [claude_code.mcp_tools.\"mcp__t__search\"]\npaths = [\"paths\"]\nkind = \"walk\"\n",
    );
    let (d, reason) = e
        .run("mcp__t__search", json!({ "paths": ["small", "big"] }))
        .decision();
    assert_eq!(d, "ask");
    assert!(reason.contains("big (walk limit)"), "{reason}");
    assert!(!reason.contains("small"), "{reason}");
}

#[test]
fn mcp_walk_does_not_follow_links_below_the_root() {
    let e = Env::new();
    e.write("elsewhere/emb.safetensors", &embedding());
    e.write("proj/clean.txt", b"nothing here\n");
    std::os::unix::fs::symlink(e.dir().join("elsewhere"), e.dir().join("proj/link")).unwrap();
    std::os::unix::fs::symlink(
        e.dir().join("elsewhere/emb.safetensors"),
        e.dir().join("proj/emb-link"),
    )
    .unwrap();
    let tool = "mcp__desktop-commander__start_search";
    e.run(tool, json!({ "path": "proj", "pattern": "x" }))
        .silent();
}
