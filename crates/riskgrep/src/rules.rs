//! The `rules list|compile|test` commands.

use crate::cli::RulesCommand;
use crate::scan::load_config;
use crate::{spec, CliError};
use include_dir::{include_dir, Dir};
use riskgrep_core::bundle::{compile_uncached, Bundle};
use riskgrep_core::config::{Config, Overrides};
use riskgrep_core::engine::Engine;
use riskgrep_core::ruleset::Ruleset;
use riskgrep_core::scanner::resolve_rulesets;
use riskgrep_core::{Category, RiskGrep, TargetReport};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

static BUILTIN: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../rulesets");

/// Scores are printed to one decimal, so cases compare at that precision.
const SCORE_TOLERANCE: f64 = 0.05;

pub fn run(cmd: RulesCommand) -> Result<i32, CliError> {
    match cmd {
        RulesCommand::List => list(),
        RulesCommand::Compile => compile(),
        RulesCommand::Test => test(),
    }
}

fn enabled() -> Result<(Config, Vec<Ruleset>), CliError> {
    let (cfg, root) = load_config(Overrides::default())?;
    let base = root.or_else(|| std::env::current_dir().ok());
    let sets = resolve_rulesets(&cfg, base.as_deref())?;
    Ok((cfg, sets))
}

fn compile_all(sets: &[Ruleset]) -> Result<Bundle, CliError> {
    let refs: Vec<&Ruleset> = sets.iter().collect();
    compile_uncached(&refs).map_err(|e| CliError(format!("rules: {e}")))
}

fn list() -> Result<i32, CliError> {
    let (cfg, sets) = enabled()?;
    let mut meta = compile_all(&sets)?.meta;
    cfg.apply_weight_overrides(&mut meta)?;
    let mut rows: Vec<(&str, &str, &str, f64)> = meta
        .iter()
        .filter_map(|(k, m)| {
            let (ns, rule) = k.split_once(':')?;
            Some((ns, rule, m.category.0.as_str(), m.weight))
        })
        .collect();
    rows.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for (ns, rule, cat, w) in rows {
        println!("{ns}  {rule}  {cat}  {w}");
    }
    Ok(0)
}

fn compile() -> Result<i32, CliError> {
    let (_, sets) = enabled()?;
    let start = Instant::now();
    let bundle = compile_all(&sets)?;
    let rules = bundle.meta.len();
    let engine = Engine::new(bundle).map_err(|e| CliError(format!("rules: {e}")))?;
    engine
        .validate_all()
        .map_err(|e| CliError(format!("rules: {e}")))?;
    println!(
        "compiled {rules} rules from {} rulesets in {} ms",
        sets.len(),
        start.elapsed().as_millis()
    );
    Ok(0)
}

// ---- rules test ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestFile {
    #[serde(rename = "case")]
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    /// Bare rule id the case is about.
    rule: String,
    /// Generator spec; see `rulesets/README.md`.
    synth: String,
    /// A score for the rule's category (the rule must fire), or `"none"`
    /// (the rule must not fire).
    expect: Expect,
    /// Name of the sample file inside the temporary directory; its path is
    /// what path rules see. Default `sample.txt`.
    path: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(untagged)]
enum Expect {
    Score(f64),
    Word(NoneWord),
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
enum NoneWord {
    #[serde(rename = "none")]
    None,
}

/// One embedded ruleset directory with a `tests.toml`.
struct Suite {
    ruleset_id: String,
    cases: Vec<Case>,
}

fn embedded_suites() -> Result<Vec<Suite>, CliError> {
    #[derive(Deserialize)]
    struct Manifest {
        id: String,
    }
    let mut out = Vec::new();
    for dir in BUILTIN.dirs() {
        let Some(tests) = dir.get_file(dir.path().join("tests.toml")) else {
            continue;
        };
        let name = dir.path().display();
        let manifest = dir
            .get_file(dir.path().join("ruleset.toml"))
            .and_then(|f| f.contents_utf8())
            .ok_or_else(|| CliError(format!("{name}: no ruleset.toml")))?;
        let id = toml::from_str::<Manifest>(manifest)
            .map_err(|e| CliError(format!("{name}/ruleset.toml: {e}")))?
            .id;
        let text = tests
            .contents_utf8()
            .ok_or_else(|| CliError(format!("{name}/tests.toml is not UTF-8")))?;
        let file: TestFile =
            toml::from_str(text).map_err(|e| CliError(format!("{name}/tests.toml: {e}")))?;
        out.push(Suite {
            ruleset_id: id,
            cases: file.cases,
        });
    }
    out.sort_by(|a, b| a.ruleset_id.cmp(&b.ruleset_id));
    Ok(out)
}

fn test() -> Result<i32, CliError> {
    let (_, sets) = enabled()?;
    let all_rules = compile_all(&sets)?.meta;
    let suites = embedded_suites()?;
    let scratch = tempdir()?;
    let original_cwd = std::env::current_dir()?;
    // Path rules see the path relative to the working directory, so scan
    // from inside the scratch directory.
    std::env::set_current_dir(&scratch)?;
    let outcome = run_suites(&sets, &suites, &all_rules, &scratch);
    let _ = std::env::set_current_dir(original_cwd);
    let _ = std::fs::remove_dir_all(&scratch);
    outcome
}

fn run_suites(
    sets: &[Ruleset],
    suites: &[Suite],
    all_rules: &std::collections::HashMap<String, riskgrep_core::meta::RuleMeta>,
    scratch: &Path,
) -> Result<i32, CliError> {
    let (mut passed, mut failed) = (0usize, 0usize);
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for suite in suites {
        let Some(set) = sets.iter().find(|s| s.id == suite.ruleset_id) else {
            continue;
        };
        // One ruleset per scanner and no cache: a case depends on its own
        // ruleset and nothing else.
        let cfg = Config {
            rulesets: vec![set.id.clone()],
            ..Config::default()
        };
        let mut rg = RiskGrep::with_cache_dir(cfg, None, None)?;
        for (n, case) in suite.cases.iter().enumerate() {
            let key = format!("{}:{}", set.id, case.rule);
            let label = format!("{}  {}", set.id, case.rule);
            let verdict = if !all_rules.contains_key(&key) {
                Err(format!("no rule `{}` in ruleset `{}`", case.rule, set.id))
            } else {
                run_case(&mut rg, scratch, n, case, &all_rules[&key].category)
            };
            match verdict {
                Ok(detail) => {
                    passed += 1;
                    if matches!(case.expect, Expect::Score(_)) {
                        covered.insert(key);
                    }
                    println!("ok  {label}  {detail}");
                }
                Err(why) => {
                    failed += 1;
                    println!("FAIL  {label}  {} : {why}", case.synth);
                }
            }
        }
    }
    let total = all_rules.len();
    println!(
        "{passed} passed, {failed} failed; {} of {total} rules have a passing positive case",
        covered.len()
    );
    Ok(if failed == 0 { 0 } else { 1 })
}

fn run_case(
    rg: &mut RiskGrep,
    scratch: &Path,
    n: usize,
    case: &Case,
    category: &Category,
) -> Result<String, String> {
    let bytes = spec::generate(&case.synth)?;
    let rel = PathBuf::from(format!("case{n}")).join(case.path.as_deref().unwrap_or("sample.txt"));
    let file = scratch.join(&rel);
    let write = || -> std::io::Result<()> {
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&file, &bytes)
    };
    write().map_err(|e| format!("cannot write sample: {e}"))?;
    let report = rg.scan_paths(std::slice::from_ref(&rel));
    let target = report
        .targets
        .first()
        .ok_or_else(|| "no target in report".to_string())?;
    judge(target, case, category)
}

fn judge(target: &TargetReport, case: &Case, category: &Category) -> Result<String, String> {
    if let riskgrep_core::TargetStatus::Unscanned { reason } = &target.status {
        return Err(format!("sample unscanned: {reason}"));
    }
    let fired = target.evidence.iter().any(|e| e.rule == case.rule);
    let score = target.scores.get(category).copied().unwrap_or(0.0);
    match case.expect {
        Expect::Word(_) if fired => Err("rule fired, expected none".into()),
        Expect::Word(_) => Ok("none".into()),
        Expect::Score(_) if !fired => Err(format!(
            "rule did not fire (fired: {})",
            fired_rules(target)
        )),
        Expect::Score(want) if (score - want).abs() > SCORE_TOLERANCE => Err(format!(
            "{} score {score:.1}, expected {want:.1}",
            category.0
        )),
        Expect::Score(_) => Ok(format!("{} {score:.1}", category.0)),
    }
}

fn fired_rules(t: &TargetReport) -> String {
    let by: BTreeMap<&str, u32> = t
        .evidence
        .iter()
        .map(|e| (e.rule.as_str(), e.count))
        .collect();
    if by.is_empty() {
        "nothing".into()
    } else {
        by.keys().copied().collect::<Vec<_>>().join(", ")
    }
}

fn tempdir() -> Result<PathBuf, CliError> {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::temp_dir();
    for i in 0..100u32 {
        let p = base.join(format!("riskgrep-rules-test-{}-{i}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return std::fs::canonicalize(&p).map_err(Into::into),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(CliError("cannot create a scratch directory".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::{Evidence, TargetStatus};

    fn target(rules: &[&str], score: f64) -> TargetReport {
        let cat = Category("secret".into());
        TargetReport {
            target: "t".into(),
            status: TargetStatus::Scanned,
            scores: BTreeMap::from([(cat.clone(), score)]),
            evidence: rules
                .iter()
                .map(|r| Evidence {
                    rule: (*r).into(),
                    category: cat.clone(),
                    weight: score,
                    count: 1,
                    locations: vec![],
                    shape: vec![],
                    fingerprints: vec![],
                })
                .collect(),
            suppressed: 0,
        }
    }

    fn case(expect: Expect) -> Case {
        Case {
            rule: "r".into(),
            synth: "text:x".into(),
            expect,
            path: None,
        }
    }

    #[test]
    fn verdicts() {
        let cat = Category("secret".into());
        let hit = target(&["r"], 95.0);
        assert!(judge(&hit, &case(Expect::Score(95.0)), &cat).is_ok());
        assert!(judge(&hit, &case(Expect::Score(90.0)), &cat).is_err());
        assert!(judge(&hit, &case(Expect::Word(NoneWord::None)), &cat).is_err());
        let miss = target(&["other"], 80.0);
        assert!(judge(&miss, &case(Expect::Score(80.0)), &cat).is_err());
        assert!(judge(&miss, &case(Expect::Word(NoneWord::None)), &cat).is_ok());
    }

    #[test]
    fn expect_parses_numbers_and_none() {
        #[derive(Deserialize)]
        struct W {
            e: Expect,
        }
        let w: W = toml::from_str("e = 95").unwrap();
        assert_eq!(w.e, Expect::Score(95.0));
        let w: W = toml::from_str("e = 57.5").unwrap();
        assert_eq!(w.e, Expect::Score(57.5));
        let w: W = toml::from_str("e = \"none\"").unwrap();
        assert_eq!(w.e, Expect::Word(NoneWord::None));
        assert!(toml::from_str::<W>("e = \"nope\"").is_err());
    }

    #[test]
    fn shipped_cases_parse() {
        let suites = embedded_suites().unwrap();
        assert_eq!(suites.len(), 2);
        assert!(suites.iter().all(|s| !s.cases.is_empty()));
    }
}
