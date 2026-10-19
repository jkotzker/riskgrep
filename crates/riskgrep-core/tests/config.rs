use riskgrep_core::config::{baseline_path, load, Action, Mode, Overrides, Threshold};
use riskgrep_core::model::Category;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

static ENV: Mutex<()> = Mutex::new(());

fn cat(s: &str) -> Category {
    Category(s.into())
}

struct Env {
    _guard: std::sync::MutexGuard<'static, ()>,
    home: tempfile::TempDir,
    repo: tempfile::TempDir,
}

fn env(user: Option<&str>, repo: Option<&str>) -> Env {
    let guard = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let repo_dir = tempfile::tempdir().unwrap();
    if let Some(u) = user {
        let dir = home.path().join(".config/riskgrep");
        std::fs::create_dir_all(&dir).unwrap();
        // `{repo}` stands for the repository directory.
        let text = u.replace("{repo}", repo_dir.path().to_str().unwrap());
        std::fs::write(dir.join("config.toml"), text).unwrap();
    }
    if let Some(r) = repo {
        std::fs::write(repo_dir.path().join(".riskgrep.toml"), r).unwrap();
    }
    std::env::set_var("HOME", home.path());
    Env {
        _guard: guard,
        home,
        repo: repo_dir,
    }
}

impl Env {
    fn root(&self) -> &Path {
        self.repo.path()
    }
}

#[test]
fn defaults_match_design() {
    let e = env(None, None);
    let _ = &e.home;
    let c = load(Mode::Cli, None, Overrides::default()).unwrap();
    assert_eq!(c.categories, None);
    assert!(c.rulesets.is_empty());
    let t = &c.claude_code.thresholds;
    assert_eq!(
        t[&cat("biometric")],
        Threshold {
            ask: Some(50.0),
            deny: Some(75.0)
        }
    );
    assert_eq!(
        t[&cat("secret")],
        Threshold {
            ask: Some(90.0),
            deny: None
        }
    );
    assert_eq!(c.claude_code.on_error, Action::Ask);
    assert_eq!(c.claude_code.on_skipped, Action::Allow);
    assert_eq!(c.claude_code.on_unresolved, Action::Allow);
    assert_eq!(c.claude_code.time_budget_ms, 2000);
    assert_eq!(c.git.block_at[&cat("secret")], 80.0);
    assert_eq!(c.git.block_at[&cat("biometric")], 75.0);
    assert_eq!(c.git.on_error, Action::Block);
    assert_eq!(c.git.on_skipped, Action::Allow);
    assert!(!c.git.full_files);
    assert_eq!(c.limits.text_max, 8_388_608);
    assert_eq!(c.limits.walk_files, 10_000);
    assert!(!c.no_cache);
}

#[test]
fn layering_order() {
    let e = env(
        Some(
            r#"
categories = ["secret"]
rulesets = ["user-set"]
weight_overrides = { "a:one" = 1.0, "a:two" = 2.0 }
[limits]
text_max = 100
time_budget_ms = 500
[git]
block_at = { secret = 60 }
on_skipped = "ask"
"#,
        ),
        Some(
            r#"
rulesets = ["repo-set"]
weight_overrides = { "a:two" = 9.0 }
[limits]
text_max = 200
[git]
block_at = { biometric = 10 }
"#,
        ),
    );
    let c = load(
        Mode::Git,
        Some(e.root()),
        Overrides {
            categories: Some(vec![cat("biometric")]),
            rulesets: None,
            no_cache: true,
        },
    )
    .unwrap();
    // CLI replaces the user's categories; rulesets list: repo replaces user.
    assert_eq!(c.categories, Some(vec![cat("biometric")]));
    assert_eq!(c.rulesets, vec!["repo-set".to_string()]);
    // Scalars: repo over user; untouched user scalar survives.
    assert_eq!(c.limits.text_max, 200);
    assert_eq!(c.limits.time_budget, Duration::from_millis(500));
    // Maps merge key by key, later wins per key.
    assert_eq!(c.weight_overrides["a:one"], 1.0);
    assert_eq!(c.weight_overrides["a:two"], 9.0);
    assert_eq!(c.git.block_at[&cat("secret")], 60.0);
    assert_eq!(c.git.block_at[&cat("biometric")], 10.0);
    assert_eq!(c.git.on_skipped, Action::Ask);
    assert!(c.no_cache);

    let c = load(
        Mode::Git,
        Some(e.root()),
        Overrides {
            rulesets: Some(vec!["cli-set".into()]),
            ..Overrides::default()
        },
    )
    .unwrap();
    assert_eq!(c.rulesets, vec!["cli-set".to_string()]);
}

const WEAKEN: &str = r#"
[claude_code]
thresholds = { biometric = { deny = 99 } }
on_error = "allow"
[ignore]
paths = ["**"]
"#;

#[test]
fn claude_mode_ignores_untrusted_repo_config() {
    let e = env(None, Some(WEAKEN));
    let c = load(Mode::ClaudeCode, Some(e.root()), Overrides::default()).unwrap();
    assert_eq!(c.claude_code.thresholds[&cat("biometric")].deny, Some(75.0));
    assert_eq!(c.claude_code.on_error, Action::Ask);
    assert!(!c.ignore.ignores("any/file", "any_rule"));
    assert_eq!(baseline_path(Mode::ClaudeCode, Some(e.root()), &c), None);
}

#[test]
fn repo_config_cannot_trust_itself() {
    let repo = r#"trusted_repos = ["/"]"#;
    let e = env(None, Some(repo));
    let c = load(Mode::Git, Some(e.root()), Overrides::default()).unwrap();
    assert!(c.trusted_repos.is_empty());
}

#[test]
fn claude_mode_honours_trusted_repo() {
    let e = env(Some(r#"trusted_repos = ["{repo}"]"#), Some(WEAKEN));
    let c = load(Mode::ClaudeCode, Some(e.root()), Overrides::default()).unwrap();
    assert_eq!(c.claude_code.thresholds[&cat("biometric")].deny, Some(99.0));
    // Field-wise merge: the repo set only `deny`, so `ask` stays.
    assert_eq!(c.claude_code.thresholds[&cat("biometric")].ask, Some(50.0));
    assert_eq!(c.claude_code.on_error, Action::Allow);
    assert!(c.ignore.ignores("any/file", "any_rule"));
    assert_eq!(
        baseline_path(Mode::ClaudeCode, Some(e.root()), &c),
        Some(e.root().join(".riskgrep-baseline.json"))
    );
}

#[test]
fn git_mode_reads_repo_config() {
    let e = env(None, Some(WEAKEN));
    let c = load(Mode::Git, Some(e.root()), Overrides::default()).unwrap();
    assert_eq!(c.claude_code.thresholds[&cat("biometric")].deny, Some(99.0));
    assert_eq!(
        baseline_path(Mode::Git, Some(e.root()), &c),
        Some(e.root().join(".riskgrep-baseline.json"))
    );
    assert_eq!(baseline_path(Mode::Git, None, &c), None);
}

#[test]
fn unknown_key_is_error() {
    let e = env(None, Some("[claude_code]\non_eror = \"allow\"\n"));
    let err = load(Mode::Git, Some(e.root()), Overrides::default()).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("on_eror"), "{msg}");
    assert!(msg.contains(".riskgrep.toml"), "{msg}");
    drop(e);

    let e = env(Some("bogus_top = 1\n"), None);
    let err = load(Mode::Cli, None, Overrides::default()).unwrap_err();
    assert!(err.to_string().contains("bogus_top"));
    assert!(err.to_string().contains("config.toml"));
    let _ = e.root();
}

#[test]
fn malformed_toml_is_error_naming_file() {
    let e = env(Some("categories = [\n"), None);
    let err = load(Mode::Cli, None, Overrides::default()).unwrap_err();
    assert!(err.to_string().contains("config.toml"));
    let _ = e.root();
}

#[test]
fn action_serializes_lowercase_and_rejects_others() {
    let e = env(Some("[git]\non_error = \"Block\"\n"), None);
    assert!(load(Mode::Cli, None, Overrides::default()).is_err());
    let _ = e.root();
}
