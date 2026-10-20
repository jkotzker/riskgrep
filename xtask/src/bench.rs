//! `cargo xtask bench`: latency benchmarks of the release binaries.
//!
//! Each case runs under `hyperfine --warmup 5 --runs 60` in an isolated HOME
//! whose rules bundle is already compiled. The p95 of the 60 runs is compared
//! with `bench/targets.toml` and, when present, with
//! `bench/baseline-<os>.json`. The one-time bundle compile is timed and
//! reported separately. Inputs are generated text without secret-like or
//! embedding-like content, and no output ever contains file content.

use crate::eval::workspace_root;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const USAGE: &str = "usage: cargo xtask bench [--write-baseline] [--runs N]";
const WARMUP: u32 = 5;
const DEFAULT_RUNS: u32 = 60;
/// A p95 more than this fraction above the baseline is a regression.
const REGRESSION: f64 = 0.25;
/// Pause between writing fixtures and measuring: the evidence cache ignores
/// entries written within 2 s of a file's mtime.
const SETTLE: Duration = Duration::from_secs(3);

#[derive(Deserialize)]
struct Targets {
    case: BTreeMap<String, Case>,
}

#[derive(Deserialize)]
struct Case {
    description: String,
    p95_ms: f64,
}

/// Nearest-rank 95th percentile of `times` (seconds), in milliseconds.
pub fn p95_ms(times: &[f64]) -> f64 {
    assert!(!times.is_empty(), "no timings");
    let mut v = times.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite timings"));
    let rank = (0.95 * v.len() as f64).ceil() as usize;
    v[rank.clamp(1, v.len()) - 1] * 1000.0
}

/// The verdict for one case: `Err` carries the reasons it failed.
pub fn judge(p95: f64, target: f64, baseline: Option<f64>) -> Result<(), Vec<String>> {
    let mut why = Vec::new();
    if p95 > target {
        why.push(format!("p95 {p95:.2} ms is over the {target:.1} ms target"));
    }
    if let Some(b) = baseline {
        let limit = b * (1.0 + REGRESSION);
        if p95 > limit {
            why.push(format!(
                "p95 {p95:.2} ms is more than 25% over the baseline {b:.2} ms (limit {limit:.2} ms)"
            ));
        }
    }
    if why.is_empty() {
        Ok(())
    } else {
        Err(why)
    }
}

/// Deterministic source-like text of about `bytes` bytes. It contains no
/// long random strings, so it triggers no rule.
fn filler(bytes: usize, seed: usize) -> String {
    const WORDS: [&str; 12] = [
        "handler", "context", "buffer", "result", "request", "index", "record", "stream", "cursor",
        "window", "offset", "length",
    ];
    let mut out = String::with_capacity(bytes + 128);
    let mut i = seed;
    while out.len() < bytes {
        let (a, b) = (WORDS[i % 12], WORDS[(i / 12 + 5) % 12]);
        out.push_str(&format!(
            "fn {a}_{b}_{i}(ctx: &Context, items: &[Item]) -> usize {{ items.len() + {a}_count(ctx) }}\n"
        ));
        i += 7;
    }
    out
}

fn os_name() -> &'static str {
    std::env::consts::OS
}

fn run_checked(cmd: &mut Command, what: &str) -> Result<(), String> {
    let status = cmd
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("{what}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what}: {status}"))
    }
}

fn build_release(root: &Path) -> Result<(), String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    run_checked(
        Command::new(cargo)
            .args([
                "build",
                "--release",
                "-p",
                "riskgrep",
                "-p",
                "riskgrep-claude",
            ])
            .current_dir(root),
        "cargo build --release",
    )
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"))
}

struct Bench {
    riskgrep: PathBuf,
    claude: PathBuf,
    home: PathBuf,
    cache: PathBuf,
    work: PathBuf,
    repo: PathBuf,
    out: PathBuf,
    runs: u32,
}

impl Bench {
    fn env(&self, c: &mut Command) {
        c.env("HOME", &self.home)
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env(
                "GIT_CEILING_DIRECTORIES",
                self.work.parent().unwrap_or(&self.work),
            )
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("CLAUDE_CODE");
    }

    /// Shell command that wipes the evidence cache but keeps the bundles.
    fn wipe_command(&self) -> String {
        let db = self.cache.join("evidence.sqlite");
        let db = db.display();
        format!("rm -f {db} {db}-wal {db}-shm")
    }

    /// Runs one case and returns the p95 in milliseconds.
    fn measure(
        &self,
        name: &str,
        cwd: &Path,
        command: &str,
        input: Option<&Path>,
        prepare: Option<&str>,
    ) -> Result<f64, String> {
        let json = self.out.join(format!("{name}.json"));
        let mut c = Command::new("hyperfine");
        c.args([
            "-N",
            "--warmup",
            &WARMUP.to_string(),
            "--runs",
            &self.runs.to_string(),
        ])
        .arg("--export-json")
        .arg(&json);
        if let Some(i) = input {
            c.arg("--input").arg(i);
        }
        if let Some(p) = prepare {
            c.arg("--prepare").arg(p);
        }
        c.arg(command)
            .current_dir(cwd)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .stdin(Stdio::null());
        self.env(&mut c);
        let status = c.status().map_err(|e| {
            format!("hyperfine: {e} (install it: `brew install hyperfine` or `cargo install hyperfine`)")
        })?;
        if !status.success() {
            return Err(format!("hyperfine failed for {name}: {status}"));
        }
        let v: serde_json::Value = serde_json::from_slice(
            &fs::read(&json).map_err(|e| format!("{}: {e}", json.display()))?,
        )
        .map_err(|e| format!("{}: {e}", json.display()))?;
        let r = &v["results"][0];
        // hyperfine 1.x lists `times` (seconds); 2.x lists `measurements`.
        let times: Vec<f64> = if let Some(t) = r["times"].as_array() {
            t.iter().filter_map(|t| t.as_f64()).collect()
        } else {
            r["measurements"]
                .as_array()
                .ok_or("hyperfine output has neither times nor measurements")?
                .iter()
                .filter_map(|m| m["time_wall_clock"]["value"].as_f64())
                .collect()
        };
        if times.len() != self.runs as usize {
            return Err(format!(
                "{name}: expected {} timings, got {}",
                self.runs,
                times.len()
            ));
        }
        Ok(p95_ms(&times))
    }
}

fn hook_input(tool_cwd: &Path, file: &Path) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": file },
        "cwd": tool_cwd,
    })
    .to_string()
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut write_baseline = false;
    let mut runs = DEFAULT_RUNS;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--write-baseline" => write_baseline = true,
            "--runs" => {
                runs = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|n| *n >= 20)
                    .ok_or_else(|| format!("--runs needs a number of at least 20\n{USAGE}"))?
            }
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    let root = workspace_root();
    let targets: Targets = toml::from_str(
        &fs::read_to_string(root.join("bench/targets.toml"))
            .map_err(|e| format!("bench/targets.toml: {e}"))?,
    )
    .map_err(|e| format!("bench/targets.toml: {e}"))?;

    build_release(&root)?;
    let tdir = target_dir(&root);
    let base = tdir.join("bench");
    if base.exists() {
        fs::remove_dir_all(&base).map_err(|e| format!("{}: {e}", base.display()))?;
    }
    let home = base.join("home");
    let work = base.join("work");
    let repo = base.join("repo");
    let out = base.join("out");
    for d in [&home, &work, &repo, &out] {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let cache = riskgrep_core::paths::cache_dir_for(
        Some(home.clone().into()),
        Some(home.join(".cache").into()),
        cfg!(target_os = "macos"),
    )
    .ok_or("no cache directory")?;
    let b = Bench {
        riskgrep: tdir.join("release/riskgrep"),
        claude: tdir.join("release/riskgrep-claude"),
        home,
        cache,
        work,
        repo,
        out,
        runs,
    };

    // One-time bundle compile, timed apart from the cases.
    let mut compile = Command::new(&b.riskgrep);
    compile.args(["rules", "compile"]).current_dir(&b.work);
    b.env(&mut compile);
    let started = Instant::now();
    run_checked(compile.stdout(Stdio::null()), "riskgrep rules compile")?;
    let compile_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!("bundle compile (once, cold cache): {compile_ms:.0} ms (not part of any case)");

    // Fixtures.
    let read_cached = b.work.join("cached.rs");
    let read_uncached = b.work.join("uncached.rs");
    let stdin_4k = b.work.join("stdin-4kb.txt");
    let stdin_1m = b.work.join("stdin-1mb.txt");
    fs::write(&read_cached, filler(8 * 1024, 2)).map_err(|e| e.to_string())?;
    fs::write(&read_uncached, filler(64 * 1024, 3)).map_err(|e| e.to_string())?;
    fs::write(&stdin_4k, filler(4 * 1024, 4)).map_err(|e| e.to_string())?;
    fs::write(&stdin_1m, filler(1024 * 1024, 5)).map_err(|e| e.to_string())?;
    let hook_cached = b.out.join("hook-cached.json");
    let hook_uncached = b.out.join("hook-uncached.json");
    fs::write(&hook_cached, hook_input(&b.work, &read_cached)).map_err(|e| e.to_string())?;
    fs::write(&hook_uncached, hook_input(&b.work, &read_uncached)).map_err(|e| e.to_string())?;

    let git = |args: &[&str]| -> Result<(), String> {
        let mut c = Command::new("git");
        c.args(args).current_dir(&b.repo);
        b.env(&mut c);
        run_checked(c.stdout(Stdio::null()), &format!("git {}", args.join(" ")))
    };
    git(&["init", "-q"])?;
    for i in 0..20 {
        fs::write(
            b.repo.join(format!("file{i:02}.rs")),
            filler(3 * 1024, 10 + i),
        )
        .map_err(|e| e.to_string())?;
    }
    git(&["add", "."])?;

    println!("settling fixtures for {} s", SETTLE.as_secs());
    std::thread::sleep(SETTLE);

    let rg = b.riskgrep.display().to_string();
    let cl = b.claude.display().to_string();
    let wipe = b.wipe_command();
    let mut measured: BTreeMap<&str, f64> = BTreeMap::new();
    measured.insert(
        "claude_read_cached",
        b.measure("claude_read_cached", &b.work, &cl, Some(&hook_cached), None)?,
    );
    measured.insert(
        "claude_read_uncached",
        b.measure(
            "claude_read_uncached",
            &b.work,
            &cl,
            Some(&hook_uncached),
            Some(&wipe),
        )?,
    );
    measured.insert(
        "scan_stdin_4kb",
        b.measure(
            "scan_stdin_4kb",
            &b.work,
            &format!("{rg} scan -"),
            Some(&stdin_4k),
            None,
        )?,
    );
    measured.insert(
        "scan_stdin_1mb",
        b.measure(
            "scan_stdin_1mb",
            &b.work,
            &format!("{rg} scan -"),
            Some(&stdin_1m),
            None,
        )?,
    );
    measured.insert(
        "git_pre_commit_20_files",
        b.measure(
            "git_pre_commit_20_files",
            &b.repo,
            &format!("{rg} git pre-commit"),
            None,
            Some(&wipe),
        )?,
    );

    let baseline_path = root.join(format!("bench/baseline-{}.json", os_name()));
    if write_baseline {
        let rounded: BTreeMap<&str, f64> = measured
            .iter()
            .map(|(k, v)| (*k, (v * 100.0).round() / 100.0))
            .collect();
        let json = serde_json::to_string_pretty(&rounded).map_err(|e| e.to_string())?;
        fs::write(&baseline_path, format!("{json}\n"))
            .map_err(|e| format!("{}: {e}", baseline_path.display()))?;
        println!("wrote {}", baseline_path.display());
    }
    let baseline: Option<BTreeMap<String, f64>> = match fs::read_to_string(&baseline_path) {
        Ok(s) => Some(
            serde_json::from_str(&s).map_err(|e| format!("{}: {e}", baseline_path.display()))?,
        ),
        Err(_) => {
            println!(
                "no baseline at bench/baseline-{}.json: regression check skipped (targets still enforced)",
                os_name()
            );
            None
        }
    };

    println!(
        "\n{:<26} {:>9} {:>9} {:>10}  result",
        "case", "p95 ms", "target", "baseline"
    );
    let mut failures = Vec::new();
    for (name, case) in &targets.case {
        let p95 = *measured
            .get(name.as_str())
            .ok_or_else(|| format!("targets.toml case `{name}` has no benchmark"))?;
        let base = baseline.as_ref().and_then(|m| m.get(name)).copied();
        let verdict = judge(p95, case.p95_ms, base);
        println!(
            "{:<26} {:>9.2} {:>9.1} {:>10}  {}  ({})",
            name,
            p95,
            case.p95_ms,
            base.map_or("-".into(), |b| format!("{b:.2}")),
            if verdict.is_ok() { "pass" } else { "FAIL" },
            case.description
        );
        if let Err(why) = verdict {
            failures.extend(why.into_iter().map(|w| format!("{name}: {w}")));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("benchmark failed:\n  {}", failures.join("\n  ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p95_is_nearest_rank() {
        let t: Vec<f64> = (1..=60).map(|i| i as f64 / 1000.0).collect();
        // ceil(0.95 * 60) = 57th value.
        assert!((p95_ms(&t) - 57.0).abs() < 1e-9);
        assert!((p95_ms(&[0.002]) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn target_miss_fails() {
        assert!(judge(5.1, 5.0, None).is_err());
        assert!(judge(5.0, 5.0, None).is_ok());
    }

    #[test]
    fn regression_over_25_percent_fails() {
        assert!(judge(3.8, 5.0, Some(3.0)).is_err());
        assert!(judge(3.75, 5.0, Some(3.0)).is_ok());
        let both = judge(7.0, 5.0, Some(3.0)).unwrap_err();
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn filler_has_the_requested_size() {
        let s = filler(4096, 1);
        assert!(s.len() >= 4096 && s.len() < 4096 + 256);
        assert_eq!(s, filler(4096, 1));
    }
}
