//! Layered configuration: defaults, user file, repository file, CLI
//! overrides. A repository file is untrusted input for the Claude Code hook
//! (the gated agent can write it), so that mode reads it only for
//! repositories the user config lists in `trusted_repos`.

use crate::classify::Limits;
use crate::meta::RuleMeta;
use crate::model::Category;
use crate::suppress::{IgnoreRules, IgnoreSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

pub const REPO_CONFIG: &str = ".riskgrep.toml";
pub const BASELINE_FILE: &str = ".riskgrep-baseline.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Ask,
    Deny,
    Block,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    pub ask: Option<f64>,
    pub deny: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClaudeCodeConfig {
    pub thresholds: BTreeMap<Category, Threshold>,
    pub on_error: Action,
    pub on_skipped: Action,
    pub on_unresolved: Action,
    pub time_budget_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GitConfig {
    pub block_at: BTreeMap<Category, f64>,
    pub on_error: Action,
    pub on_skipped: Action,
    pub full_files: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub categories: Option<Vec<Category>>,
    pub rulesets: Vec<String>,
    pub extra_ruleset_dirs: Vec<PathBuf>,
    pub weight_overrides: BTreeMap<String, f64>,
    pub limits: Limits,
    pub ignore: IgnoreRules,
    pub claude_code: ClaudeCodeConfig,
    pub git: GitConfig,
    pub trusted_repos: Vec<PathBuf>,
    /// Set by the `--no-cache` override; the cache is on otherwise.
    pub no_cache: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub categories: Option<Vec<Category>>,
    pub rulesets: Option<Vec<String>>,
    pub no_cache: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Cli,
    Git,
    ClaudeCode,
}

fn cat(s: &str) -> Category {
    Category(s.to_string())
}

impl Default for Config {
    fn default() -> Self {
        Config {
            categories: None,
            rulesets: Vec::new(),
            extra_ruleset_dirs: Vec::new(),
            weight_overrides: BTreeMap::new(),
            limits: Limits::default(),
            ignore: IgnoreRules::default(),
            claude_code: ClaudeCodeConfig {
                thresholds: BTreeMap::from([
                    (
                        cat("biometric"),
                        Threshold {
                            ask: Some(50.0),
                            deny: Some(75.0),
                        },
                    ),
                    (
                        cat("secret"),
                        Threshold {
                            ask: Some(90.0),
                            deny: None,
                        },
                    ),
                ]),
                on_error: Action::Ask,
                on_skipped: Action::Allow,
                on_unresolved: Action::Allow,
                time_budget_ms: 2000,
            },
            git: GitConfig {
                block_at: BTreeMap::from([(cat("secret"), 80.0), (cat("biometric"), 75.0)]),
                on_error: Action::Block,
                on_skipped: Action::Allow,
                full_files: false,
            },
            trusted_repos: Vec::new(),
            no_cache: false,
        }
    }
}

// ---- file layers: every field optional ----

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsLayer {
    text_max: Option<u64>,
    sample: Option<u64>,
    sniff: Option<usize>,
    walk_files: Option<usize>,
    time_budget_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeLayer {
    thresholds: Option<BTreeMap<Category, Threshold>>,
    on_error: Option<Action>,
    on_skipped: Option<Action>,
    on_unresolved: Option<Action>,
    time_budget_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitLayer {
    block_at: Option<BTreeMap<Category, f64>>,
    on_error: Option<Action>,
    on_skipped: Option<Action>,
    full_files: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Layer {
    categories: Option<Vec<Category>>,
    rulesets: Option<Vec<String>>,
    extra_ruleset_dirs: Option<Vec<PathBuf>>,
    weight_overrides: Option<BTreeMap<String, f64>>,
    trusted_repos: Option<Vec<PathBuf>>,
    limits: Option<LimitsLayer>,
    ignore: Option<IgnoreSpec>,
    claude_code: Option<ClaudeLayer>,
    git: Option<GitLayer>,
}

fn read_layer(path: &Path) -> Result<Option<Layer>, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ConfigError(format!(
                "cannot read config {}: {e}",
                path.display()
            )))
        }
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| ConfigError(format!("invalid config {}: {e}", path.display())))
}

fn merge_map<K: Ord, V>(into: &mut BTreeMap<K, V>, from: BTreeMap<K, V>) {
    into.extend(from);
}

impl Config {
    fn merge(&mut self, l: Layer, trust: bool) -> Result<(), ConfigError> {
        if let Some(v) = l.categories {
            self.categories = Some(v);
        }
        if let Some(v) = l.rulesets {
            self.rulesets = v;
        }
        if let Some(v) = l.extra_ruleset_dirs {
            self.extra_ruleset_dirs = v;
        }
        if let Some(v) = l.weight_overrides {
            merge_map(&mut self.weight_overrides, v);
        }
        if trust {
            if let Some(v) = l.trusted_repos {
                self.trusted_repos = v;
            }
        }
        if let Some(x) = l.limits {
            if let Some(v) = x.text_max {
                self.limits.text_max = v;
            }
            if let Some(v) = x.sample {
                self.limits.sample = v;
            }
            if let Some(v) = x.sniff {
                self.limits.sniff = v;
            }
            if let Some(v) = x.walk_files {
                self.limits.walk_files = v;
            }
            if let Some(v) = x.time_budget_ms {
                self.limits.time_budget = Duration::from_millis(v);
            }
        }
        if let Some(spec) = l.ignore {
            self.ignore = IgnoreRules::new(spec).map_err(|e| ConfigError(e.0))?;
        }
        if let Some(x) = l.claude_code {
            if let Some(map) = x.thresholds {
                for (k, t) in map {
                    let e = self.claude_code.thresholds.entry(k).or_default();
                    if t.ask.is_some() {
                        e.ask = t.ask;
                    }
                    if t.deny.is_some() {
                        e.deny = t.deny;
                    }
                }
            }
            if let Some(v) = x.on_error {
                self.claude_code.on_error = v;
            }
            if let Some(v) = x.on_skipped {
                self.claude_code.on_skipped = v;
            }
            if let Some(v) = x.on_unresolved {
                self.claude_code.on_unresolved = v;
            }
            if let Some(v) = x.time_budget_ms {
                self.claude_code.time_budget_ms = v;
            }
        }
        if let Some(x) = l.git {
            if let Some(v) = x.block_at {
                merge_map(&mut self.git.block_at, v);
            }
            if let Some(v) = x.on_error {
                self.git.on_error = v;
            }
            if let Some(v) = x.on_skipped {
                self.git.on_skipped = v;
            }
            if let Some(v) = x.full_files {
                self.git.full_files = v;
            }
        }
        Ok(())
    }

    /// Set `weight` on each bundle rule named in `weight_overrides`
    /// (`namespace:rule` keys). A key naming no loaded rule is an error.
    pub fn apply_weight_overrides(
        &self,
        meta: &mut HashMap<String, RuleMeta>,
    ) -> Result<(), ConfigError> {
        for (key, w) in &self.weight_overrides {
            match meta.get_mut(key) {
                Some(m) => m.weight = *w,
                None => {
                    return Err(ConfigError(format!(
                        "weight_overrides: no loaded rule `{key}`"
                    )))
                }
            }
        }
        Ok(())
    }
}

fn user_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".config/riskgrep/config.toml"))
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn is_trusted(repo_root: &Path, trusted: &[PathBuf]) -> bool {
    let root = canonical(repo_root);
    trusted.iter().any(|t| canonical(t) == root)
}

/// Defaults, then the user file, then the repository file, then `cli`.
/// `Mode::ClaudeCode` reads the repository file only when `repo_root` is in
/// the user file's `trusted_repos`; `trusted_repos` in a repository file is
/// ignored in every mode.
pub fn load(
    mode: Mode,
    repo_root: Option<&Path>,
    cli_overrides: Overrides,
) -> Result<Config, ConfigError> {
    let mut cfg = Config::default();
    if let Some(layer) = user_config_path()
        .map(|p| read_layer(&p))
        .transpose()?
        .flatten()
    {
        cfg.merge(layer, true)?;
    }
    if let Some(root) = repo_root {
        let allowed = mode != Mode::ClaudeCode || is_trusted(root, &cfg.trusted_repos);
        if allowed {
            if let Some(layer) = read_layer(&root.join(REPO_CONFIG))? {
                cfg.merge(layer, false)?;
            }
        }
    }
    if let Some(c) = cli_overrides.categories {
        cfg.categories = Some(c);
    }
    if let Some(r) = cli_overrides.rulesets {
        cfg.rulesets = r;
    }
    if cli_overrides.no_cache {
        cfg.no_cache = true;
    }
    Ok(cfg)
}

/// Baseline file location, or `None` when there is no repository or, for
/// the Claude Code hook, the repository is not trusted.
pub fn baseline_path(mode: Mode, repo_root: Option<&Path>, cfg: &Config) -> Option<PathBuf> {
    let root = repo_root?;
    if mode == Mode::ClaudeCode && !is_trusted(root, &cfg.trusted_repos) {
        return None;
    }
    Some(root.join(BASELINE_FILE))
}
