//! `cargo xtask instructions`: instruction counts of the benchmark cases.
//!
//! Runs every case of `cargo xtask bench` (the same fixtures, isolated HOME,
//! and warm rules bundle) under an instruction counter, and compares the
//! smallest count of each case with `bench/instructions-<os>-<counter>.json`.
//! Instruction counts depend far less on what else the machine is doing than
//! wall-clock time does, so this answers "did this change make it slower?" on
//! any machine, hosted CI runners included. Whether it is fast enough in
//! absolute terms is still `cargo xtask bench` on fixed hardware.
//!
//! Counters: `perf` (Linux, `perf stat -e instructions:u`, user space of the
//! benchmarked process only), `callgrind` (Linux, Valgrind's instruction
//! count `Ir`, the benchmarked process only), and `time` (macOS,
//! `/usr/bin/time -l` "instructions retired"). Counts from different counters
//! or operating systems are not comparable, so each pair has its own baseline.

use crate::bench::{self, CaseSpec, Prepared};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const USAGE: &str = "usage: cargo xtask instructions [--counter auto|perf|callgrind|time] [--runs N] [--no-build] [--json FILE] [--write-baseline] [--check]";
const DEFAULT_RUNS: u32 = 5;
/// A case whose smallest count is more than this fraction above its baseline
/// is a regression.
pub const THRESHOLD: f64 = 0.02;

/// User configuration for the counted runs: time budgets no case reaches.
const GENEROUS_BUDGETS: &str =
    "[limits]\ntime_budget_ms = 600000\n\n[claude_code]\ntime_budget_ms = 600000\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    Perf,
    Callgrind,
    Time,
}

impl Counter {
    pub fn name(self) -> &'static str {
        match self {
            Counter::Perf => "perf",
            Counter::Callgrind => "callgrind",
            Counter::Time => "time",
        }
    }

    pub fn from_name(s: &str) -> Option<Counter> {
        [Counter::Perf, Counter::Callgrind, Counter::Time]
            .into_iter()
            .find(|c| c.name() == s)
    }

    /// `program args` wrapped in this counter, which writes its result to
    /// `report` (`perf`, `callgrind`) or to standard error (`time`).
    fn command(self, program: &Path, args: &[&str], report: &Path) -> Command {
        let mut c = match self {
            Counter::Perf => {
                let mut c = Command::new("perf");
                c.args([
                    "stat",
                    "-x",
                    ",",
                    "--no-inherit",
                    "-e",
                    "instructions:u",
                    "-o",
                ])
                .arg(report)
                .arg("--");
                c
            }
            Counter::Callgrind => {
                let mut c = Command::new("valgrind");
                c.args(["--tool=callgrind", "--quiet"])
                    .arg(format!("--callgrind-out-file={}", report.display()));
                c
            }
            Counter::Time => {
                let mut c = Command::new("/usr/bin/time");
                c.arg("-l");
                c
            }
        };
        c.arg(program).args(args);
        c
    }

    /// The count from a finished run.
    fn read(self, stderr: &str, report: &Path) -> Result<u64, String> {
        let file = || fs::read_to_string(report).map_err(|e| format!("{}: {e}", report.display()));
        match self {
            Counter::Perf => parse_perf(&file()?),
            Counter::Callgrind => parse_callgrind(&file()?)
                .ok_or_else(|| "no totals line in the callgrind output".into()),
            Counter::Time => parse_time(stderr)
                .filter(|n| *n > 0)
                .ok_or_else(|| "/usr/bin/time -l reported no instructions retired".into()),
        }
    }
}

/// "instructions retired" from `/usr/bin/time -l` on macOS.
pub fn parse_time(stderr: &str) -> Option<u64> {
    stderr.lines().rev().find_map(|l| {
        let l = l.trim();
        l.strip_suffix("instructions retired")?.trim().parse().ok()
    })
}

/// The `instructions:u` count from `perf stat -x ,` output.
pub fn parse_perf(out: &str) -> Result<u64, String> {
    let line = out
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && l.contains("instructions"))
        .ok_or("no instructions line in the perf output")?;
    let value = line.split(',').next().unwrap_or("");
    value
        .parse()
        .map_err(|_| format!("perf could not count instructions: `{value}`"))
}

/// The instruction count (`Ir`) from a callgrind output file.
pub fn parse_callgrind(out: &str) -> Option<u64> {
    let total = |prefix: &str| {
        out.lines().find_map(|l| {
            l.strip_prefix(prefix)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    };
    total("totals:").or_else(|| total("summary:"))
}

/// Smallest, median, and largest of `counts`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Summary {
    pub min: u64,
    pub median: u64,
    pub max: u64,
}

impl Summary {
    pub fn of(counts: &[u64]) -> Summary {
        assert!(!counts.is_empty(), "no counts");
        let mut v = counts.to_vec();
        v.sort_unstable();
        Summary {
            min: v[0],
            median: v[v.len() / 2],
            max: v[v.len() - 1],
        }
    }

    /// (max - min) / min, in percent.
    pub fn spread_pct(&self) -> f64 {
        (self.max - self.min) as f64 / self.min as f64 * 100.0
    }
}

/// The verdict for one case against its baseline.
pub fn judge(count: u64, baseline: u64, threshold: f64) -> Result<(), String> {
    let limit = baseline as f64 * (1.0 + threshold);
    if count as f64 > limit {
        Err(format!(
            "{count} instructions is {:+.2}% against the baseline {baseline} (limit {:+.2}%)",
            (count as f64 / baseline as f64 - 1.0) * 100.0,
            threshold * 100.0
        ))
    } else {
        Ok(())
    }
}

/// Every failure of `measured` (smallest count per case) against `baseline`:
/// regressions, cases without a baseline, and baseline entries for cases
/// that no longer exist.
pub fn check(
    measured: &BTreeMap<String, u64>,
    baseline: &BTreeMap<String, u64>,
    threshold: f64,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, count) in measured {
        match baseline.get(name) {
            Some(b) => {
                if let Err(why) = judge(*count, *b, threshold) {
                    failures.push(format!("{name}: {why}"));
                }
            }
            None => failures.push(format!("{name}: no baseline")),
        }
    }
    for name in baseline.keys().filter(|n| !measured.contains_key(*n)) {
        failures.push(format!("{name}: in the baseline but not a benchmark case"));
    }
    failures
}

pub fn baseline_path(root: &Path, os: &str, counter: Counter) -> PathBuf {
    root.join(format!("bench/instructions-{os}-{}.json", counter.name()))
}

/// The counter to use when none is named: `time` on macOS; on Linux, `perf`
/// when it can count user-space instructions here, else `callgrind`.
fn auto_counter(scratch: &Path) -> Result<Counter, String> {
    if cfg!(target_os = "macos") {
        return Ok(Counter::Time);
    }
    let report = scratch.join("perf-probe.txt");
    let probe = Counter::Perf
        .command(Path::new("true"), &[], &report)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(probe, Ok(s) if s.success()) && Counter::Perf.read("", &report).is_ok() {
        return Ok(Counter::Perf);
    }
    let valgrind = Command::new("valgrind")
        .arg("--version")
        .stdout(Stdio::null())
        .status();
    if matches!(valgrind, Ok(s) if s.success()) {
        return Ok(Counter::Callgrind);
    }
    Err("no instruction counter: install perf (with kernel.perf_event_paranoid at most 2) or valgrind, or name one with --counter".into())
}

/// Runs `case` once, counted when `counter` is set.
fn run_case(
    p: &Prepared,
    case: &CaseSpec,
    counter: Option<Counter>,
) -> Result<Option<u64>, String> {
    if case.wipe {
        p.bench.wipe()?;
    }
    let report = p.bench.out.join(format!("{}.count", case.name));
    let mut c = match counter {
        Some(k) => k.command(&case.program, &case.args, &report),
        None => {
            let mut c = Command::new(&case.program);
            c.args(&case.args);
            c
        }
    };
    p.bench.env(&mut c);
    c.current_dir(&case.cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    match &case.input {
        Some(i) => c.stdin(fs::File::open(i).map_err(|e| format!("{}: {e}", i.display()))?),
        None => c.stdin(Stdio::null()),
    };
    let out = c.output().map_err(|e| format!("{}: {e}", case.name))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!("{}: {} ({})", case.name, out.status, stderr.trim()));
    }
    counter
        .map(|k| k.read(&stderr, &report))
        .transpose()
        .map_err(|e| format!("{}: {e}", case.name))
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut counter_name = "auto".to_string();
    let mut runs = DEFAULT_RUNS;
    let (mut build, mut write_baseline, mut require_baseline) = (true, false, false);
    let mut json: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--counter" => counter_name = it.next().ok_or(USAGE)?.clone(),
            "--runs" => {
                runs = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| format!("--runs needs a number of at least 1\n{USAGE}"))?
            }
            "--no-build" => build = false,
            "--json" => json = Some(PathBuf::from(it.next().ok_or(USAGE)?)),
            "--write-baseline" => write_baseline = true,
            "--check" => require_baseline = true,
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    let p = bench::prepare(build)?;
    let counter = if counter_name == "auto" {
        auto_counter(&p.bench.out)?
    } else {
        Counter::from_name(&counter_name)
            .ok_or_else(|| format!("unknown counter `{counter_name}`\n{USAGE}"))?
    };
    // A scan that runs out of time reads less and so counts fewer
    // instructions; under Valgrind the default 2 s budgets are easily spent.
    // The budgets only cut work short, so raising them changes no count of a
    // scan that finishes.
    p.bench.write_config(GENEROUS_BUDGETS)?;
    if counter == Counter::Callgrind {
        p.bench
            .recompile_bundle(&["valgrind", "--tool=none", "--quiet"])?;
    }
    let os = std::env::consts::OS;
    println!("counter: {} on {os}, {runs} runs per case", counter.name());

    let mut counts: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for case in &p.cases {
        // One uncounted run first, as the wall-clock benchmark warms up.
        run_case(&p, case, None)?;
        let mut v = Vec::with_capacity(runs as usize);
        for _ in 0..runs {
            v.extend(run_case(&p, case, Some(counter))?);
        }
        counts.insert(case.name.to_string(), v);
    }
    let measured: BTreeMap<String, u64> = counts
        .iter()
        .map(|(k, v)| (k.clone(), Summary::of(v).min))
        .collect();

    if let Some(path) = &json {
        let doc = serde_json::json!({
            "os": os,
            "counter": counter.name(),
            "runs": runs,
            "cases": counts,
        });
        fs::write(path, format!("{doc:#}\n")).map_err(|e| format!("{}: {e}", path.display()))?;
    }

    let path = baseline_path(&p.root, os, counter);
    let shown = path
        .strip_prefix(&p.root)
        .unwrap_or(&path)
        .display()
        .to_string();
    if write_baseline {
        let doc = serde_json::to_string_pretty(&measured).map_err(|e| e.to_string())?;
        fs::write(&path, format!("{doc}\n")).map_err(|e| format!("{shown}: {e}"))?;
        println!("wrote {shown}");
    }
    let baseline: Option<BTreeMap<String, u64>> = match fs::read_to_string(&path) {
        Ok(s) => Some(serde_json::from_str(&s).map_err(|e| format!("{shown}: {e}"))?),
        Err(_) if require_baseline => {
            return Err(format!(
                "no baseline at {shown}: write one with --write-baseline"
            ))
        }
        Err(_) => {
            println!("no baseline at {shown}: regression check skipped");
            None
        }
    };

    println!(
        "\n{:<28} {:>14} {:>14} {:>8} {:>14} {:>9}",
        "case", "min", "max", "spread", "baseline", "change"
    );
    for (name, v) in &counts {
        let s = Summary::of(v);
        let base = baseline.as_ref().and_then(|b| b.get(name)).copied();
        println!(
            "{:<28} {:>14} {:>14} {:>7.3}% {:>14} {:>9}",
            name,
            s.min,
            s.max,
            s.spread_pct(),
            base.map_or("-".into(), |b| b.to_string()),
            base.map_or("-".into(), |b| format!(
                "{:+.3}%",
                (s.min as f64 / b as f64 - 1.0) * 100.0
            )),
        );
    }
    let Some(baseline) = baseline else {
        return Ok(());
    };
    let failures = check(&measured, &baseline, THRESHOLD);
    if failures.is_empty() {
        println!(
            "\nno case is more than {:.1}% over {shown}",
            THRESHOLD * 100.0
        );
        Ok(())
    } else {
        Err(format!(
            "instruction counts failed against {shown}:\n  {}\nIf the increase is deliberate, rewrite the baseline with `cargo xtask instructions --counter {} --write-baseline` on {os} and state the reason in the pull request.",
            failures.join("\n  "),
            counter.name()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_output_is_parsed() {
        let stderr = "        0.01 real         0.00 user         0.00 sys\n\
                      \x20           1835008  maximum resident set size\n\
                      \x20           35283430  instructions retired\n\
                      \x20           24130380  cycles elapsed\n";
        assert_eq!(parse_time(stderr), Some(35_283_430));
        assert_eq!(parse_time("no counters here\n"), None);
    }

    #[test]
    fn perf_output_is_parsed() {
        let out =
            "# started on Sat Nov  7 12:00:00 2026\n\n123456789,,instructions:u,2003456,100.00,,\n";
        assert_eq!(parse_perf(out), Ok(123_456_789));
        let unsupported = "<not supported>,,instructions:u,0,100.00,,\n";
        assert!(parse_perf(unsupported)
            .unwrap_err()
            .contains("not supported"));
        assert!(parse_perf("# only a comment\n").is_err());
    }

    #[test]
    fn callgrind_output_is_parsed() {
        let out = "version: 1\ncreator: callgrind-3.25.1\nevents: Ir\nsummary: 98765\n\nfn=main\n3 98765\ntotals: 98765\n";
        assert_eq!(parse_callgrind(out), Some(98_765));
        assert_eq!(parse_callgrind("events: Ir\nsummary: 42\n"), Some(42));
        assert_eq!(parse_callgrind("events: Ir\n"), None);
    }

    #[test]
    fn summary_and_spread() {
        let s = Summary::of(&[103, 100, 101, 102, 100]);
        assert_eq!(
            s,
            Summary {
                min: 100,
                median: 101,
                max: 103
            }
        );
        assert!((s.spread_pct() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn judge_uses_the_threshold() {
        assert!(judge(1_020, 1_000, 0.02).is_ok());
        assert!(judge(1_021, 1_000, 0.02).is_err());
        assert!(judge(900, 1_000, 0.02).is_ok());
    }

    #[test]
    fn check_reports_regressions_and_missing_cases() {
        let m = |pairs: &[(&str, u64)]| -> BTreeMap<String, u64> {
            pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        };
        let base = m(&[("a", 1_000), ("b", 1_000), ("gone", 5)]);
        let measured = m(&[("a", 1_000), ("b", 1_100), ("new", 7)]);
        let f = check(&measured, &base, 0.02);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f[0].starts_with("b: "));
        assert!(f[1].starts_with("new: no baseline"));
        assert!(f[2].starts_with("gone: "));
        assert!(check(&m(&[("a", 1_010)]), &m(&[("a", 1_000)]), 0.02).is_empty());
    }

    #[test]
    fn counters_round_trip_by_name() {
        for c in [Counter::Perf, Counter::Callgrind, Counter::Time] {
            assert_eq!(Counter::from_name(c.name()), Some(c));
        }
        assert_eq!(Counter::from_name("cycles"), None);
    }

    #[test]
    fn generous_budgets_parse_as_configuration() {
        let v: toml::Value = toml::from_str(GENEROUS_BUDGETS).unwrap();
        assert_eq!(v["limits"]["time_budget_ms"].as_integer(), Some(600_000));
        assert_eq!(
            v["claude_code"]["time_budget_ms"].as_integer(),
            Some(600_000)
        );
    }

    #[test]
    fn baseline_is_per_os_and_counter() {
        let p = baseline_path(Path::new("/r"), "linux", Counter::Perf);
        assert_eq!(p, Path::new("/r/bench/instructions-linux-perf.json"));
    }
}
