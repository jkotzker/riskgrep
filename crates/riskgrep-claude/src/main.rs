//! `riskgrep-claude`: a Claude Code `PreToolUse` hook.
//!
//! Reads the hook input on stdin, finds the files the tool call would read,
//! scans them, and prints an `ask` or `deny` decision when a category crosses
//! its threshold. Prints nothing otherwise and never emits `allow`. The exit
//! status is always 0: Claude Code documents an exit other than 0 or 2
//! without a JSON decision as a non-blocking error that lets the call
//! proceed (fail-open), though the handling depends on its version. Failures
//! here must ask, which only a JSON decision does reliably.

use riskgrep_claude::bash::bash_targets_within;
use riskgrep_claude::decide::{decide, decide_names, error_decision, Decision};
use riskgrep_claude::input::{self, HookInput};
use riskgrep_claude::resolve;
use riskgrep_core::config::{self, Action, Config, McpKind, Mode, Overrides};
use riskgrep_core::{Report, RiskGrep};
use serde_json::json;
use std::io::{Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

/// Standard input beyond this many bytes is not read.
const STDIN_MAX: u64 = 16 << 20;
/// Longest total time budget honoured; keeps deadline arithmetic far from
/// overflow.
const MAX_BUDGET: Duration = Duration::from_secs(3600);
/// Bash analysis gets this share of the budget, but never less than
/// [`MIN_BASH_BUDGET`].
const BASH_SHARE: u32 = 4;
const MIN_BASH_BUDGET: Duration = Duration::from_millis(50);
const WORKER_STACK: usize = 16 << 20;
/// The `print-config` matcher. A matcher with characters other than
/// letters, digits, `_`, `-`, spaces, `,`, and `|` is an unanchored
/// regular expression in Claude Code, so it is anchored here.
const MATCHER: &str = "^(Read|NotebookRead|Grep|Glob|Bash|mcp__.*)$";

fn main() {
    let start = Instant::now();
    if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "print-config")
    {
        print_config();
        return;
    }
    // A panic must not print the default message or end in a non-zero exit,
    // which Claude Code treats as a non-blocking error (fail-open).
    panic::set_hook(Box::new(|_| {}));
    let decision = panic::catch_unwind(|| run(start)).unwrap_or_else(|_| {
        error_decision(
            Config::default().claude_code.on_error,
            "RiskGrep: internal error",
        )
    });
    emit(&decision);
}

fn emit(d: &Decision) {
    let (word, reason) = match d {
        Decision::NoOpinion => return,
        Decision::Ask(r) => ("ask", r),
        Decision::Deny(r) => ("deny", r),
    };
    let out = json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": word,
        "permissionDecisionReason": reason,
    }});
    let mut so = std::io::stdout().lock();
    let _ = writeln!(so, "{out}");
    let _ = so.flush();
}

fn print_config() {
    eprintln!(
        "# Merge this into ~/.claude/settings.json by hand: add the hook entry to \
         hooks.PreToolUse and the deny rules to permissions.deny."
    );
    let cfg = json!({
        "hooks": {"PreToolUse": [{
            "matcher": MATCHER,
            "hooks": [{"type": "command", "command": "riskgrep-claude", "timeout": 5}],
        }]},
        "permissions": {"deny": [
            "Edit(~/.config/riskgrep/**)",
            "Write(~/.config/riskgrep/**)",
        ]},
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&cfg).expect("static json")
    );
}

fn run(start: Instant) -> Decision {
    let mut buf = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(STDIN_MAX)
        .read_to_end(&mut buf);
    let parsed = read
        .map_err(|_| ())
        .and_then(|_| input::parse(&buf).map_err(|_| ()));
    let Ok(hook) = parsed else {
        let on_error = config::load(Mode::ClaudeCode, None, Overrides::default())
            .map_or(Action::Ask, |c| c.claude_code.on_error);
        return error_decision(on_error, "RiskGrep: unreadable hook input");
    };
    let gated = matches!(
        hook.tool_name.as_str(),
        "Read" | "NotebookRead" | "Grep" | "Glob" | "Bash"
    ) || hook.tool_name.starts_with("mcp__");
    if !gated || hook.event.as_deref().is_some_and(|e| e != "PreToolUse") {
        return Decision::NoOpinion;
    }
    let cwd = hook
        .cwd
        .clone()
        .filter(|c| c.is_dir())
        .or_else(|| std::env::current_dir().ok());
    let Some(cwd) = cwd else {
        return error_decision(
            Config::default().claude_code.on_error,
            "RiskGrep: no working directory",
        );
    };
    // The scanner resolves relative paths against the process directory.
    let _ = std::env::set_current_dir(&cwd);
    let root = riskgrep_core::repo::repo_root_from_env(&cwd);
    let cfg = match config::load(Mode::ClaudeCode, root.as_deref(), Overrides::default()) {
        Ok(c) => c,
        Err(e) => {
            return Decision::Ask(format!(
                "RiskGrep: configuration error ({})",
                config_error_summary(&e.0)
            ));
        }
    };
    let cc = cfg.claude_code.clone();
    let total = Duration::from_millis(cc.time_budget_ms).min(MAX_BUDGET);
    let deadline = start + total;
    match panic::catch_unwind(AssertUnwindSafe(|| {
        work(&hook, cfg, root, &cwd, deadline, total)
    })) {
        Ok(d) => d,
        Err(_) => error_decision(cc.on_error, "RiskGrep: internal error"),
    }
}

/// A configuration error without configuration text: a TOML error becomes
/// `<what> <path> at line L, column C` (its snippet and message, which
/// quote the file, are dropped); any other error keeps its first line.
fn config_error_summary(msg: &str) -> String {
    let first = msg.lines().next().unwrap_or_default();
    match first.split_once(": TOML parse error at ") {
        Some((head, position)) => format!("{head} at {position}"),
        None => first.to_string(),
    }
}

/// What the worker thread scans.
enum Job {
    Files(Vec<PathBuf>),
    Grep {
        glob: Option<String>,
        kind: Option<String>,
    },
    /// The files under these paths (an MCP content search).
    Walk(Vec<PathBuf>),
    /// The names under these paths, judged without their content.
    Names {
        roots: Vec<PathBuf>,
        glob: Option<String>,
        max_depth: Option<usize>,
    },
}

fn work(
    hook: &HookInput,
    cfg: Config,
    root: Option<PathBuf>,
    cwd: &Path,
    deadline: Instant,
    total: Duration,
) -> Decision {
    let cc = cfg.claude_code.clone();
    let mut unresolved = false;
    let job = match hook.tool_name.as_str() {
        "Bash" => {
            let Some(cmd) = hook.str_field("command") else {
                return Decision::NoOpinion;
            };
            let budget = (total / BASH_SHARE).max(MIN_BASH_BUDGET);
            let t = bash_targets_within(cmd, cwd, budget);
            unresolved = t.unresolved;
            if t.files.is_empty() {
                return decide(
                    &Report::from_targets("", "", Vec::new()),
                    unresolved,
                    &cc,
                    None,
                );
            }
            Job::Files(t.files)
        }
        "Grep" => Job::Grep {
            glob: hook.str_field("glob").map(str::to_string),
            kind: hook.str_field("type").map(str::to_string),
        },
        "Glob" => {
            let home = std::env::var("HOME").ok();
            let Some((root, pattern)) = resolve::glob_root(hook, cwd, home.as_deref()) else {
                return Decision::NoOpinion;
            };
            Job::Names {
                roots: vec![root],
                glob: Some(pattern),
                max_depth: None,
            }
        }
        name if name.starts_with("mcp__") => match mcp_job(hook, &cc, cwd) {
            Ok(Some(job)) => job,
            Ok(None) => return Decision::NoOpinion,
            Err(()) => {
                return error_decision(
                    cc.on_unresolved,
                    &format!("RiskGrep: could not determine the files {name} reads"),
                )
            }
        },
        _ => match resolve::read_target(hook, cwd) {
            Some(p) => Job::Files(vec![p]),
            None => return Decision::NoOpinion,
        },
    };
    let names = matches!(job, Job::Names { .. });
    let (tx, rx) = mpsc::channel();
    let spawned = {
        let hook = hook.clone();
        let cwd = cwd.to_path_buf();
        std::thread::Builder::new()
            .name("riskgrep-scan".into())
            .stack_size(WORKER_STACK)
            .spawn(move || {
                let _ = tx.send(scan(&hook, cfg, root.as_deref(), &cwd, job));
            })
    };
    if spawned.is_err() {
        return error_decision(cc.on_error, "RiskGrep: could not start scan");
    }
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(report)) if names => decide_names(&report, &cc),
        Ok(Ok(report)) => decide(&report, unresolved, &cc, input::requested_lines(hook)),
        Ok(Err(reason)) => error_decision(cc.on_error, &format!("RiskGrep: {reason}")),
        Err(RecvTimeoutError::Timeout) => {
            error_decision(cc.on_error, "RiskGrep: scan exceeded time budget")
        }
        Err(RecvTimeoutError::Disconnected) => {
            error_decision(cc.on_error, "RiskGrep: scan failed unexpectedly")
        }
    }
}

/// The job for an MCP call: `Ok(None)` when it reads nothing, `Err` when
/// the tool has no `claude_code.mcp_tools` entry or its path fields cannot
/// be read.
fn mcp_job(hook: &HookInput, cc: &config::ClaudeCodeConfig, cwd: &Path) -> Result<Option<Job>, ()> {
    let tool = cc.mcp_tool(&hook.tool_name).ok_or(())?;
    if tool.kind == McpKind::None {
        return Ok(None);
    }
    let home = std::env::var("HOME").ok();
    let paths = resolve::mcp_paths(hook, &tool.paths, cwd, home.as_deref()).ok_or(())?;
    if paths.is_empty() {
        return Ok(None);
    }
    Ok(Some(match tool.kind {
        McpKind::Read => {
            let files = resolve::existing_files(paths);
            if files.is_empty() {
                return Ok(None);
            }
            Job::Files(files)
        }
        McpKind::Walk => Job::Walk(paths),
        McpKind::Names | McpKind::None => Job::Names {
            roots: paths,
            glob: None,
            max_depth: tool.max_depth,
        },
    }))
}

/// Scores each name with the path rules alone (`RiskGrep::scan_names`). Names are
/// relative to `cwd`, as the scanner names files it reads.
fn scan_names(
    cfg: Config,
    root: Option<&Path>,
    cwd: &Path,
    names: &[PathBuf],
) -> Result<Report, String> {
    if names.is_empty() {
        return Ok(Report::from_targets("", "", Vec::new()));
    }
    let cfg = Config {
        no_cache: true,
        ..cfg
    };
    let mut rg =
        RiskGrep::new(cfg, root).map_err(|e| format!("could not start scanner ({})", e.0))?;
    let names: Vec<String> = names
        .iter()
        .map(|p| {
            p.strip_prefix(cwd)
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let report = rg.scan_names(&names);
    std::mem::forget(rg);
    Ok(report)
}

fn scan(
    hook: &HookInput,
    cfg: Config,
    root: Option<&Path>,
    cwd: &Path,
    job: Job,
) -> Result<Report, String> {
    let limit = cfg.limits.walk_files;
    let mut limit_hit = None;
    let files = match job {
        Job::Files(f) => f,
        Job::Grep { glob, kind } => {
            let g = resolve::grep_files(hook, cwd, glob.as_deref(), kind.as_deref(), limit);
            if g.limit_hit {
                limit_hit = Some(
                    hook.str_field("path")
                        .map_or_else(|| cwd.display().to_string(), |p| p.to_string()),
                );
            }
            g.files
        }
        Job::Walk(roots) => {
            let w = resolve::walk_entries(&roots, None, None, true, limit);
            if w.limit_hit {
                limit_hit = Some(roots[0].display().to_string());
            }
            w.entries
        }
        Job::Names {
            roots,
            glob,
            max_depth,
        } => {
            let w = resolve::walk_entries(&roots, glob.as_deref(), max_depth, false, limit);
            return scan_names(cfg, root, cwd, &w.entries);
        }
    };
    let mut report = if files.is_empty() {
        Report::from_targets("", "", Vec::new())
    } else {
        let mut rg =
            RiskGrep::new(cfg, root).map_err(|e| format!("could not start scanner ({})", e.0))?;
        let report = rg.scan_paths(&files);
        // Close the evidence cache normally (the SQLite close checkpoints
        // the WAL), then skip the rules and scanner destructors: the process
        // exits right after the decision and the OS reclaims their memory.
        rg.close_cache();
        std::mem::forget(rg);
        report
    };
    if let Some(dir) = limit_hit {
        use riskgrep_core::{TargetReport, TargetStatus};
        let mut targets = report.targets;
        targets.push(TargetReport {
            target: dir,
            status: TargetStatus::Unscanned {
                reason: "walk limit".to_string(),
            },
            scores: Default::default(),
            evidence: Vec::new(),
            suppressed: 0,
            text: false,
        });
        report = Report::from_targets(&report.riskgrep_version, &report.rules_bundle, targets);
    }
    Ok(report)
}
