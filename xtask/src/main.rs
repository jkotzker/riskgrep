//! Repository tasks: `cargo xtask <task>`.

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str =
    "usage: cargo xtask convert-gitleaks --config <gitleaks.toml> --tag <release tag> --out <dir>";

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
    xtask::convert_gitleaks(&bytes, &tag, &PathBuf::from(&out))?;
    eprintln!("wrote {out}/gitleaks.yar, {out}/UPSTREAM.md, {out}/stopwords/");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("convert-gitleaks") => convert(&args[1..]),
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
