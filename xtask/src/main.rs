//! Repository tasks: `cargo xtask <task>`.

mod eval;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str =
    "usage: cargo xtask convert-gitleaks --config <gitleaks.toml> --tag <release tag> --out <dir>
       cargo xtask eval [--skip-oss]";

fn convert(args: &[String]) -> Result<(), String> {
    let (mut config, mut tag, mut out) = (None, None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--config" => &mut config,
            "--tag" => &mut tag,
            "--out" => &mut out,
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        };
        *slot = Some(it.next().ok_or(format!("{flag} needs a value"))?.clone());
    }
    let (Some(config), Some(tag), Some(out)) = (config, tag, out) else {
        return Err(USAGE.into());
    };
    let bytes = std::fs::read(&config).map_err(|e| format!("{config}: {e}"))?;
    let out_dir = PathBuf::from(&out);
    xtask::convert_gitleaks(&bytes, &tag, &out_dir)?;
    eprintln!("wrote {out}/gitleaks.yar, {out}/UPSTREAM.md, {out}/stopwords/");
    validate(&out_dir)
}

/// Compiles the ruleset in `dir` and every rule's post-processors, when the
/// directory has a manifest.
fn validate(dir: &std::path::Path) -> Result<(), String> {
    use riskgrep_core::{bundle::compile_uncached, engine::Engine, ruleset::Ruleset};
    if !dir.join("ruleset.toml").exists() {
        eprintln!("no ruleset.toml in {}: not validated", dir.display());
        return Ok(());
    }
    let rs = Ruleset::load_dir(dir).map_err(|e| e.to_string())?;
    let bundle = compile_uncached(&[&rs]).map_err(|e| e.to_string())?;
    let rules = bundle.meta.len();
    let engine = Engine::new(bundle).map_err(|e| e.to_string())?;
    engine.validate_all().map_err(|e| e.to_string())?;
    eprintln!("validated {rules} rules in {}", dir.display());
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("convert-gitleaks") => convert(&args[1..]),
        Some("eval") => eval::run(&args[1..]),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
