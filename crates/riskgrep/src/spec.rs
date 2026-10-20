//! The generator mini-language of `tests.toml`: a `synth` string such as
//! `secret:aws_access_key` or `npy:<f4:10x192` becomes the bytes of a
//! synthetic test file. The grammar is documented in `rulesets/README.md`.

use riskgrep_core::synth::{self, FloatStyle, Rng};

/// Seed used when a spec names none.
const DEFAULT_SEED: u64 = 7;

/// Bytes of random data after a `der` prefix.
const DER_BODY: usize = 300;

pub fn generate(spec: &str) -> Result<Vec<u8>, String> {
    let (kind, rest) = spec.split_once(':').unwrap_or((spec, ""));
    let bad = |what: &str| format!("synth `{spec}`: {what}");
    match kind {
        "secret" => {
            let (name, seed) = split_seed(rest).map_err(|e| bad(&e))?;
            if !synth::FAKE_SECRET_KINDS.contains(&name) {
                return Err(bad(&format!(
                    "unknown secret kind `{name}` (known: {})",
                    synth::FAKE_SECRET_KINDS.join(", ")
                )));
            }
            Ok(embed_secret(name, seed).into_bytes())
        }
        "keyed" => {
            let (name, seed) = split_seed(rest).map_err(|e| bad(&e))?;
            let ok = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
            if !ok {
                return Err(bad(
                    "want keyed:NAME[:SEED] with NAME of letters, digits, _ . -",
                ));
            }
            let line = synth::fake_secret("generic_api_key_assignment", seed);
            let open = line.find('"').expect("quoted value") + 1;
            let close = line.rfind('"').expect("quoted value");
            Ok(format!("{name} = \"{}\"\n", &line[open..close]).into_bytes())
        }
        "npy" => {
            let (dtype, dims) = rest
                .split_once(':')
                .ok_or_else(|| bad("want npy:DTYPE:DIMS"))?;
            Ok(synth::npy(dtype, &dims_of(dims).map_err(|e| bad(&e))?))
        }
        "npz" => {
            let (dtype, dims) = rest
                .split_once(':')
                .ok_or_else(|| bad("want npz:DTYPE:DIMS"))?;
            let npy = synth::npy(dtype, &dims_of(dims).map_err(|e| bad(&e))?);
            Ok(synth::npz(&[("emb.npy", npy)]))
        }
        "safetensors" => {
            let mut tensors: Vec<(String, String, Vec<u64>)> = Vec::new();
            for item in rest.split(';') {
                let (name, tail) = item
                    .split_once('=')
                    .ok_or_else(|| bad("want NAME=DTYPE@DIMS"))?;
                let (dtype, dims) = tail
                    .split_once('@')
                    .ok_or_else(|| bad("want NAME=DTYPE@DIMS"))?;
                tensors.push((
                    name.into(),
                    dtype.into(),
                    dims_of(dims).map_err(|e| bad(&e))?,
                ));
            }
            let refs: Vec<(&str, &str, &[u64])> = tensors
                .iter()
                .map(|(n, d, s)| (n.as_str(), d.as_str(), s.as_slice()))
                .collect();
            Ok(synth::safetensors(&refs))
        }
        "floats" => {
            let (n, style) = rest
                .split_once(':')
                .ok_or_else(|| bad("want floats:N:STYLE"))?;
            let style = match style {
                "python" => FloatStyle::PythonList,
                "numpy" => FloatStyle::NumpyRepr,
                "json" => FloatStyle::JsonArray,
                other => {
                    return Err(bad(&format!(
                        "unknown style `{other}` (python, numpy, json)"
                    )))
                }
            };
            Ok(synth::printed_floats(count(n).map_err(|e| bad(&e))?, style).into_bytes())
        }
        "csv" => {
            let dims = dims_of(rest).map_err(|e| bad(&e))?;
            let [rows, cols] = dims[..] else {
                return Err(bad("want csv:ROWSxCOLS"));
            };
            Ok(synth::csv_rows(rows as usize, cols as usize).into_bytes())
        }
        "der" => {
            let (hex, seed) = split_seed(rest).map_err(|e| bad(&e))?;
            let mut out = unhex(hex).map_err(|e| bad(&e))?;
            let at = out.len();
            out.resize(at + DER_BODY, 0);
            Rng::new(seed).fill(&mut out[at..]);
            Ok(out)
        }
        "prices" => {
            let n = count(rest).map_err(|e| bad(&e))?;
            Ok((0..n)
                .map(|i| format!("item{i},{}.99,{}\n", i % 90 + 1, i % 7 + 1))
                .collect::<String>()
                .into_bytes())
        }
        "log" => {
            let n = count(rest).map_err(|e| bad(&e))?;
            Ok((0..n)
                .map(|i| {
                    format!(
                        "2026-10-19 12:00:{:02} latency=0.{:03} ok\n",
                        i % 60,
                        i % 1000
                    )
                })
                .collect::<String>()
                .into_bytes())
        }
        "text" => Ok(rest.replace("\\n", "\n").replace("\\t", "\t").into_bytes()),
        other => Err(format!("synth `{spec}`: unknown generator `{other}`")),
    }
}

/// `NAME[:SEED]`.
fn split_seed(s: &str) -> Result<(&str, u64), String> {
    match s.split_once(':') {
        None => Ok((s, DEFAULT_SEED)),
        Some((name, seed)) => Ok((
            name,
            seed.parse()
                .map_err(|_| format!("`{seed}` is not a seed"))?,
        )),
    }
}

fn count(s: &str) -> Result<usize, String> {
    s.parse().map_err(|_| format!("`{s}` is not a count"))
}

/// `10x192` or `64`.
fn dims_of(s: &str) -> Result<Vec<u64>, String> {
    s.split('x')
        .map(|d| d.parse().map_err(|_| format!("`{d}` is not a dimension")))
        .collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(format!("`{s}` is not hex bytes"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("`{s}` is not hex bytes"))
        })
        .collect()
}

/// Source-like text holding the fake credential: whole-line and block kinds
/// as they are, tokens inside a string assignment that names no keyword.
fn embed_secret(kind: &str, seed: u64) -> String {
    let s = synth::fake_secret(kind, seed);
    let line =
        if kind == "pem_private_key" || kind.ends_with("generic") || kind.ends_with("assignment") {
            s
        } else {
            format!("    let id = \"{s}\";")
        };
    format!("fn main() {{\n    let width = 80;\n    // configuration follows\n{line}\n    println!(\"{{}}\", width);\n}}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic() {
        for spec in [
            "secret:github_pat",
            "secret:github_pat:9",
            "keyed:key_sha256",
            "keyed:key_sha256:3",
            "npy:<f4:3x64",
            "npz:<f4:4x256",
            "safetensors:speaker_embedding=F32@1x192;other=F32@1x128",
            "floats:70:numpy",
            "csv:20x5",
            "der:3082012c",
            "prices:20",
            "log:20",
            "text:a\\nb",
        ] {
            assert_eq!(generate(spec), generate(spec), "{spec}");
            assert!(!generate(spec).unwrap().is_empty(), "{spec}");
        }
        assert_ne!(
            generate("secret:github_pat:1"),
            generate("secret:github_pat:2")
        );
        assert_eq!(generate("text:a\\nb").unwrap(), b"a\nb");
    }

    #[test]
    fn der_has_prefix_and_body() {
        let d = generate("der:3082012c").unwrap();
        assert_eq!(&d[..4], &[0x30, 0x82, 0x01, 0x2c]);
        assert_eq!(d.len(), 4 + DER_BODY);
    }

    #[test]
    fn bad_specs_are_errors() {
        for spec in [
            "",
            "nope:1",
            "secret:nope",
            "secret:aws_access_key:x",
            "npy:<f4",
            "npy:<f4:axb",
            "floats:5:binary",
            "csv:10",
            "der:abc",
            "safetensors:x",
            "keyed:",
            "keyed:bad name",
            "keyed:x:y",
        ] {
            assert!(generate(spec).is_err(), "{spec:?}");
        }
    }
}
