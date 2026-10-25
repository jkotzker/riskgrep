use riskgrep_core::config::{baseline_path, load, Action, Mode, Overrides, Threshold};
use riskgrep_core::meta::RuleMeta;
use riskgrep_core::model::Category;
use std::collections::HashMap;
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
            ask: Some(80.0),
            deny: Some(95.0)
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

#[test]
fn ignore_lists_layer_independently() {
    let e = env(
        Some("[ignore]\nrules = [{ path = \"docs/**\", rules = [\"generic_api_key\"] }]\n"),
        Some("[ignore]\npaths = [\"vendor/**\"]\n"),
    );
    let c = load(Mode::Git, Some(e.root()), Overrides::default()).unwrap();
    assert!(c.ignore.ignores("vendor/x.rs", "any"));
    assert!(c.ignore.ignores("docs/a.md", "generic_api_key"));
    assert!(!c.ignore.ignores("docs/a.md", "other"));
}

fn meta(weight: f64) -> RuleMeta {
    RuleMeta {
        category: cat("secret"),
        weight,
        tiers: None,
        family: None,
        family_cap: None,
        post: vec![],
        line_complete: false,
    }
}

fn with_weights(w: &str) -> riskgrep_core::config::Config {
    let e = env(Some(&format!("weight_overrides = {w}\n")), None);
    let c = load(Mode::Cli, None, Overrides::default()).unwrap();
    drop(e);
    c
}

fn bundle_meta() -> HashMap<String, RuleMeta> {
    HashMap::from([("secrets-core:aws".to_string(), meta(5.0))])
}

#[test]
fn weight_override_applies_and_skips_unloaded_namespace() {
    let c = with_weights(r#"{ "secrets-core:aws" = 7.5, "other-set:x" = 1.0 }"#);
    let mut m = bundle_meta();
    c.apply_weight_overrides(&mut m).unwrap();
    assert_eq!(m["secrets-core:aws"].weight, 7.5);
    assert_eq!(m.len(), 1);
}

#[test]
fn weight_override_errors() {
    let mut m = bundle_meta();
    let c = with_weights(r#"{ "secrets-core:nope" = 1.0 }"#);
    let err = c.apply_weight_overrides(&mut m).unwrap_err();
    assert!(err.to_string().contains("secrets-core:nope"));
    let c = with_weights(r#"{ "secrets-core:aws" = 100.5 }"#);
    assert!(c.apply_weight_overrides(&mut m).is_err());
    let c = with_weights(r#"{ "secrets-core:aws" = nan }"#);
    assert!(c.apply_weight_overrides(&mut m).is_err());
    let c = with_weights(r#"{ "noprefix" = 1.0 }"#);
    assert!(c.apply_weight_overrides(&mut m).is_err());
    assert_eq!(m["secrets-core:aws"].weight, 5.0);
}

#[test]
fn relative_paths_resolve_against_the_declaring_config() {
    let user = "extra_ruleset_dirs = [\"r\", \"/abs/rules\"]\ntrusted_repos = [\"proj\"]\n";
    let e = env(Some(user), None);
    let user_dir = e.home.path().join(".config/riskgrep");
    let c = load(Mode::Cli, None, Overrides::default()).unwrap();
    assert_eq!(
        c.extra_ruleset_dirs,
        vec![user_dir.join("r"), Path::new("/abs/rules").to_path_buf()]
    );
    assert_eq!(c.trusted_repos, vec![user_dir.join("proj")]);
    drop(e);

    let e = env(None, Some("extra_ruleset_dirs = [\"rules\"]\n"));
    let c = load(Mode::Git, Some(e.root()), Overrides::default()).unwrap();
    assert_eq!(c.extra_ruleset_dirs, vec![e.root().join("rules")]);
}

/// A ruleset directory with one `secret` rule of `weight` matching `text`.
fn rule_dir(dir: &Path, id: &str, weight: i32, text: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("ruleset.toml"),
        format!(
            "id = \"{id}\"\nversion = \"1\"\nlicence = \"MIT\"\ndescription = \"t\"\n\
             categories = [\"secret\"]\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("a.yar"),
        format!(
            "rule {id}_rule {{ meta:\n category = \"secret\"\n weight = {weight}\n \
             strings: $hit = \"{text}\"\n condition: $hit }}\n"
        ),
    )
    .unwrap();
}

#[test]
fn claude_mode_never_resolves_user_paths_in_an_untrusted_repo() {
    let e = env(Some("extra_ruleset_dirs = [\"r\"]\n"), None);
    // The untrusted repository supplies `r/` with a rule that would cancel
    // every secret finding.
    rule_dir(&e.root().join("r"), "planted", -100, "AKIA");
    std::fs::create_dir(e.root().join(".git")).unwrap();
    rule_dir(
        &e.home.path().join(".config/riskgrep/r"),
        "user_extra",
        10,
        "riskgrep-user-extra-probe",
    );
    let cfg = load(Mode::ClaudeCode, Some(e.root()), Overrides::default()).unwrap();
    let ids: Vec<String> = riskgrep_core::scanner::resolve_rulesets(&cfg, Some(e.root()))
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(ids.contains(&"user_extra".to_string()), "{ids:?}");
    assert!(!ids.contains(&"planted".to_string()), "{ids:?}");
    let cache = tempfile::tempdir().unwrap();
    let mut g =
        riskgrep_core::RiskGrep::with_cache_dir(cfg, Some(e.root()), Some(cache.path().into()))
            .unwrap();
    let key = riskgrep_core::synth::fake_secret("aws_access_key", 5);
    let r = g.scan_bytes("k.txt", format!("id = \"{key}\"\n").as_bytes());
    assert_eq!(r.targets[0].scores[&cat("secret")], 95.0);
}

#[test]
fn load_records_mode() {
    let _e = env(None, None);
    for mode in [Mode::Cli, Mode::Git, Mode::ClaudeCode] {
        assert_eq!(load(mode, None, Overrides::default()).unwrap().mode, mode);
    }
}

#[test]
fn mcp_tool_defaults_cover_common_servers() {
    use riskgrep_core::config::McpKind;
    let _e = env(None, None);
    let c = load(Mode::ClaudeCode, None, Overrides::default()).unwrap();
    let cc = &c.claude_code;
    let read = cc.mcp_tool("mcp__filesystem__read_text_file").unwrap();
    assert_eq!(read.kind, McpKind::Read);
    assert_eq!(read.paths, ["path"]);
    let many = cc
        .mcp_tool("mcp__plugin_desktop-commander_desktop-commander__read_multiple_files")
        .unwrap();
    assert_eq!(many.paths, ["paths"]);
    assert_eq!(
        cc.mcp_tool("mcp__desktop-commander__start_search")
            .unwrap()
            .kind,
        McpKind::Walk
    );
    let list = cc.mcp_tool("mcp__filesystem__list_directory").unwrap();
    assert_eq!((list.kind, list.max_depth), (McpKind::Names, Some(1)));
    assert_eq!(
        cc.mcp_tool("mcp__filesystem__write_file").unwrap().kind,
        McpKind::None
    );
    assert!(cc.mcp_tool("mcp__other__read_file").is_none());
    assert!(cc.mcp_tool("Read").is_none());
}

#[test]
fn mcp_tool_user_entry_adds_and_replaces() {
    use riskgrep_core::config::McpKind;
    let _e = env(
        Some(
            "[claude_code.mcp_tools.\"mcp__notes__open\"]\npaths = [\"file\", \"files\"]\n\n\
             [claude_code.mcp_tools.\"mcp__db_*__query\"]\nkind = \"none\"\n\n\
             [claude_code.mcp_tools.\"mcp__filesystem__read_file\"]\npaths = [\"other\"]\n",
        ),
        None,
    );
    let c = load(Mode::ClaudeCode, None, Overrides::default()).unwrap();
    let cc = &c.claude_code;
    let open = cc.mcp_tool("mcp__notes__open").unwrap();
    assert_eq!(
        (open.kind, open.paths.as_slice()),
        (
            McpKind::Read,
            &["file".to_string(), "files".to_string()][..]
        )
    );
    assert_eq!(
        cc.mcp_tool("mcp__db_main__query").unwrap().kind,
        McpKind::None
    );
    assert!(cc.mcp_tool("mcp__db_main__drop").is_none());
    assert_eq!(
        cc.mcp_tool("mcp__filesystem__read_file").unwrap().paths,
        ["other"]
    );
    // Built-in entries the user did not name stay.
    assert!(cc.mcp_tool("mcp__filesystem__read_text_file").is_some());
}

#[test]
fn mcp_tool_malformed_entries_rejected() {
    for bad in [
        // Not an MCP tool name.
        "[claude_code.mcp_tools.Read]\npaths = [\"file_path\"]\n",
        // A reading kind without fields.
        "[claude_code.mcp_tools.\"mcp__x__y\"]\nkind = \"read\"\n",
        "[claude_code.mcp_tools.\"mcp__x__y\"]\npaths = []\n",
        // Unknown kind, unknown key, wrong type.
        "[claude_code.mcp_tools.\"mcp__x__y\"]\npaths = [\"p\"]\nkind = \"write\"\n",
        "[claude_code.mcp_tools.\"mcp__x__y\"]\npaths = [\"p\"]\nfield = \"p\"\n",
        "[claude_code.mcp_tools.\"mcp__x__y\"]\npaths = \"p\"\n",
    ] {
        let _e = env(Some(bad), None);
        let err = load(Mode::ClaudeCode, None, Overrides::default()).unwrap_err();
        assert!(
            err.0.contains("config") || err.0.contains("mcp_tools"),
            "{bad}: {err}"
        );
    }
}
