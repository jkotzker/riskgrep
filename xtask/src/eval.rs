//! `cargo xtask eval`: accuracy of the shipped rulesets.
//!
//! Scans a synthetic corpus (generated at run time into a temporary
//! directory, never written to the repository) and a pinned set of public
//! repositories with the release `riskgrep` binary, then reports recall and
//! false positives per 1,000 files at the default thresholds. Fails when the
//! release bar is not met or a metric is worse than `eval/baseline-metrics.json`.
//! Only `--write-baseline` rewrites the baseline (from any run; the exit
//! status still reports a failure); otherwise the run prints the changes it
//! would make.
//! Output carries rule ids, paths, lines, and scores only, never file content.

use riskgrep_core::config::Config;
use riskgrep_core::synth::{self, FloatStyle, Rng};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SECRET: &str = "secret";
pub const BIOMETRIC: &str = "biometric";

/// What a synthetic sample measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    /// A credential that a provider-specific (or private key) rule must find.
    Provider,
    /// A generic `name = "value"` credential.
    Generic,
    /// An embedding file or printed float array.
    Biometric,
    /// Ordinary content that must not be flagged.
    Negative,
    /// Not gated: credentials outside the generic rule's key names.
    ProbeSecret,
    /// Not gated: embeddings outside `embedding_dims` or with more leading
    /// dimensions.
    ProbeBiometric,
}

impl Group {
    /// The category a positive sample must be flagged in.
    pub fn category(self) -> Option<&'static str> {
        match self {
            Group::Provider | Group::Generic | Group::ProbeSecret => Some(SECRET),
            Group::Biometric | Group::ProbeBiometric => Some(BIOMETRIC),
            Group::Negative => None,
        }
    }

    pub fn is_probe(self) -> bool {
        matches!(self, Group::ProbeSecret | Group::ProbeBiometric)
    }
}

pub struct Sample {
    pub group: Group,
    /// Format or negative family, e.g. `github_pat`, `npy`, `sensor_csv`.
    pub kind: String,
    /// File name (may include subdirectories) inside the sample's directory.
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Minimum samples per secret provider format and per biometric format.
pub const PER_FORMAT: usize = 20;
/// Generic credential assignments.
pub const GENERIC: usize = 50;
/// Minimum generated hard negatives (the hand-picked existing ones are extra).
pub const GENERATED_NEGATIVES: usize = 200;
/// Minimum OSS files, so a bar of one per 1,000 is measurable.
pub const MIN_OSS_FILES: u64 = 20_000;

/// `synth::fake_secret` kinds in a provider's format.
pub const PROVIDER_KINDS: &[&str] = &[
    "aws_access_key",
    "github_pat",
    "anthropic_key",
    "pem_private_key",
    "stripe_key",
    "slack_bot_token",
    "npm_token",
    "openai_key",
];

/// Key-store file formats (binary), scored by `keystores.yar`.
pub const KEYSTORE_KINDS: &[&str] = &["pkcs12", "der_key"];

/// Probe sets (reported, not gated).
pub const PROBE_KINDS: &[&str] = &[
    "probe_npy_offlist_width",
    "probe_npy_3_leading_dims",
    "probe_safetensors_offlist_width",
    "probe_floats_offlist_width",
    "probe_generic_env_key",
    "probe_generic_other_key",
    "probe_bank_of_2",
    "probe_bank_mixed_shapes",
    "probe_bank_offlist_width",
    "probe_flat_mlp",
];

/// Generated hard-negative families.
pub const NEGATIVE_KINDS: &[&str] = &[
    "sensor_csv",
    "model_safetensors",
    "int_npy",
    "example_key",
    "low_entropy",
    "uuid_list",
    "hex_hash",
    "base64_blob",
    "source",
    "prices_logs",
    "model_checkpoint",
    "reference_npz",
];

pub const BIOMETRIC_KINDS: &[&str] = &[
    "npy",
    "npz",
    "safetensors_named",
    "safetensors_unnamed",
    "floats_python",
    "floats_numpy",
    "floats_json",
    "bank_safetensors",
    "bank_npz",
    "bank_indexed_safetensors",
    "bank_indexed_npz",
];

// ---- synthetic corpus --------------------------------------------------------

fn sample(group: Group, kind: &str, name: String, bytes: impl Into<Vec<u8>>) -> Sample {
    Sample {
        group,
        kind: kind.to_string(),
        name,
        bytes: bytes.into(),
    }
}

/// The whole synthetic corpus, deterministic.
pub fn corpus() -> Vec<Sample> {
    let mut out = Vec::new();
    provider_secrets(&mut out);
    encoded_text(&mut out);
    generic_secrets(&mut out);
    biometric(&mut out);
    banks(&mut out);
    probes(&mut out);
    bank_probes(&mut out);
    mlp_probes(&mut out);
    negatives(&mut out);
    checkpoints(&mut out);
    existing_negatives(&mut out);
    out
}

/// A token placed in one of several file types. Some name a keyword
/// (`token`, `key`), some do not.
fn embed_token(i: usize, tok: &str) -> (String, String) {
    match i % 7 {
        0 => (
            ".env".into(),
            format!("DATABASE_URL=postgres://localhost/app\nSERVICE_TOKEN={tok}\nDEBUG=false\n"),
        ),
        1 => (
            "settings.py".into(),
            format!(
                "import os\n\nclient = Client(\n    url=\"https://api.example.com\",\n    \
                 credential=\"{tok}\",\n    timeout=30,\n)\n"
            ),
        ),
        2 => (
            "config.yaml".into(),
            format!("service:\n  name: billing\n  replicas: 2\n  token: {tok}\n"),
        ),
        3 => (
            "config.json".into(),
            format!("{{\n  \"name\": \"billing\",\n  \"auth\": {{\n    \"token\": \"{tok}\"\n  }}\n}}\n"),
        ),
        4 => (
            "config.js".into(),
            format!("export const config = {{\n  region: 'us-east-1',\n  key: '{tok}',\n}};\n"),
        ),
        5 => (
            "deploy.sh".into(),
            format!("#!/bin/sh\nset -e\nexport CI_SECRET=\"{tok}\"\n./release.sh \"$1\"\n"),
        ),
        _ => (
            "main.rs".into(),
            format!(
                "fn main() {{\n    let width = 80;\n    let id = \"{tok}\";\n    \
                 println!(\"{{}} {{}}\", width, id.len());\n}}\n"
            ),
        ),
    }
}

/// A PEM block in one of several containers.
fn embed_pem(i: usize, pem: &str) -> (String, String) {
    match i % 4 {
        0 => ("id_rsa".into(), format!("{pem}\n")),
        1 => ("server.pem".into(), format!("{pem}\n")),
        2 => {
            let indented: String = pem.lines().map(|l| format!("    {l}\n")).collect();
            (
                "values.yaml".into(),
                format!("tls:\n  enabled: true\n  key: |\n{indented}"),
            )
        }
        _ => (
            "service-account.json".into(),
            format!(
                "{{\n  \"type\": \"service_account\",\n  \"private_key\": \"{}\\n\",\n  \
                 \"client_email\": \"app@example.iam.gserviceaccount.com\"\n}}\n",
                pem.replace('\n', "\\n")
            ),
        ),
    }
}

/// `prefix` then 300 random bytes.
fn der(prefix: &[u8], seed: u64) -> Vec<u8> {
    let mut out = prefix.to_vec();
    let at = out.len();
    out.resize(at + 300, 0);
    Rng::new(seed).fill(&mut out[at..]);
    out
}

fn provider_secrets(out: &mut Vec<Sample>) {
    for kind in PROVIDER_KINDS {
        for i in 0..PER_FORMAT {
            let s = synth::fake_secret(kind, 1000 + i as u64);
            let (name, text) = if *kind == "pem_private_key" {
                embed_pem(i, &s)
            } else {
                embed_token(i, &s)
            };
            out.push(sample(Group::Provider, kind, name, text));
        }
    }
    for i in 0..PER_FORMAT {
        // PKCS #12: SEQUENCE with a two-byte length.
        let name = if i % 2 == 0 {
            "client.p12"
        } else {
            "client.pfx"
        };
        let bytes = der(&[0x30, 0x82, 0x01, 0x2c], 2000 + i as u64);
        out.push(sample(Group::Provider, "pkcs12", name.into(), bytes));
    }
    // DER private keys: PKCS#1 (INTEGER 0, INTEGER), PKCS#8 (INTEGER 0,
    // SEQUENCE), and SEC1 EC keys (INTEGER 1, OCTET STRING), with short-form
    // (Ed25519, Ed448, P-224, P-256) and long-form lengths.
    let prefixes: [&[u8]; 9] = [
        &[0x30, 0x82, 0x01, 0x2c, 0x02, 0x01, 0x00, 0x02],
        &[0x30, 0x82, 0x01, 0x2c, 0x02, 0x01, 0x00, 0x30],
        &[0x30, 0x77, 0x02, 0x01, 0x01, 0x04],
        &[0x30, 0x81, 0xa4, 0x02, 0x01, 0x01, 0x04],
        &[0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30],
        &[0x30, 0x2e, 0x02, 0x01, 0x00, 0x30],
        &[0x30, 0x47, 0x02, 0x01, 0x00, 0x30],
        &[0x30, 0x68, 0x02, 0x01, 0x01, 0x04],
        &[0x30, 0x31, 0x02, 0x01, 0x01, 0x04],
    ];
    for i in 0..PER_FORMAT {
        let name = if i % 2 == 0 { "server.der" } else { "tls.key" };
        let bytes = der(prefixes[i % prefixes.len()], 3000 + i as u64);
        out.push(sample(Group::Provider, "der_key", name.into(), bytes));
    }
}

/// Text to UTF-16 or UTF-32 code-unit bytes.
type Encoder = fn(&str) -> Vec<u8>;

/// UTF-16 and UTF-32 encodings: (name prefix, encoder, byte-order mark).
/// Every provider format is written in each.
const ENCODINGS: [(&str, Encoder, bool); 8] = [
    ("utf16le-bom", utf16le, true),
    ("utf16be-bom", utf16be, true),
    ("utf16le", utf16le, false),
    ("utf16be", utf16be, false),
    ("utf32le-bom", utf32le, true),
    ("utf32be-bom", utf32be, true),
    ("utf32le", utf32le, false),
    ("utf32be", utf32be, false),
];

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn utf32le(s: &str) -> Vec<u8> {
    s.chars().flat_map(|c| (c as u32).to_le_bytes()).collect()
}

fn utf32be(s: &str) -> Vec<u8> {
    s.chars().flat_map(|c| (c as u32).to_be_bytes()).collect()
}

/// `text` in `enc`, after a byte-order mark when `bom` is set, with CRLF
/// line endings when `crlf` is set (as Windows exports have).
fn encoded(enc: Encoder, bom: bool, crlf: bool, text: &str) -> Vec<u8> {
    let mut s = String::new();
    if bom {
        s.push('\u{feff}');
    }
    if crlf {
        s.push_str(&text.replace('\n', "\r\n"));
    } else {
        s.push_str(text);
    }
    enc(&s)
}

/// Provider credentials (kind `encoded_text`) and ordinary text (a hard
/// negative of the same kind) in UTF-16 and UTF-32, with and without a
/// byte-order mark: one sample per provider format and encoding.
fn encoded_text(out: &mut Vec<Sample>) {
    for (k, kind) in PROVIDER_KINDS.iter().enumerate() {
        for (i, &(label, enc, bom)) in ENCODINGS.iter().enumerate() {
            let s = synth::fake_secret(kind, 4000 + (k * ENCODINGS.len() + i) as u64);
            let (name, text) = if *kind == "pem_private_key" {
                embed_pem(i, &s)
            } else {
                embed_token(k + i, &s)
            };
            let bytes = encoded(enc, bom, (k + i) % 2 == 0, &text);
            let name = format!("{label}-{name}");
            out.push(sample(Group::Provider, "encoded_text", name, bytes));
        }
    }
    for (i, &(label, enc, bom)) in ENCODINGS.iter().enumerate() {
        let text = format!(
            "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Example]\n\
             \"Name\"=\"caf\u{e9} \u{65e5}\u{672c}\"\n\n{}",
            synth::source_text(1500, 4100 + i as u64)
        );
        let bytes = encoded(enc, bom, i % 2 == 0, &text);
        let name = format!("{label}-export.reg");
        out.push(sample(Group::Negative, "encoded_text", name, bytes));
    }
}

/// The quoted value of a `name = "value"` line.
fn quoted(line: &str) -> &str {
    let open = line.find('"').expect("quoted value") + 1;
    let close = line.rfind('"').expect("quoted value");
    &line[open..close]
}

fn generic_secrets(out: &mut Vec<Sample>) {
    for i in 0..GENERIC {
        let line = synth::fake_secret("generic_api_key_assignment", 4000 + i as u64);
        let v = quoted(&line);
        let (name, text) = match i % 7 {
            0 => ("settings.py".into(), format!("DEBUG = False\n{line}\n")),
            1 => (
                "config.yaml".into(),
                format!("oauth:\n  client_id: billing\n  client_secret: {v}\n"),
            ),
            2 => (
                "config.json".into(),
                format!("{{\n  \"user\": \"svc\",\n  \"auth_token\": \"{v}\"\n}}\n"),
            ),
            3 => (
                "app.properties".into(),
                format!("db.user=app\ndb.password={v}\n"),
            ),
            4 => (
                "config.toml".into(),
                format!("[storage]\nbucket = \"assets\"\naccess_key = \"{v}\"\n"),
            ),
            5 => (
                "client.js".into(),
                format!("const apiKey = \"{v}\";\nfetch(url, {{ headers: {{ apiKey }} }});\n"),
            ),
            _ => (
                "Settings.java".into(),
                format!("class Settings {{\n    static final String SECRET = \"{v}\";\n}}\n"),
            ),
        };
        out.push(sample(Group::Generic, "generic_api_key", name, text));
    }
}

/// Common embedding widths (face, speaker, and text models).
const EMBED_DIMS: &[u64] = &[128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072];

fn biometric(out: &mut Vec<Sample>) {
    let dtypes = ["<f4", "<f8", "<f2"];
    for i in 0..PER_FORMAT {
        let d = EMBED_DIMS[i % EMBED_DIMS.len()];
        let rows = (i / EMBED_DIMS.len()) as u64 + 1;
        let shape: Vec<u64> = if i % 2 == 0 { vec![rows, d] } else { vec![d] };
        let npy = synth::npy(dtypes[i % 3], &shape);
        out.push(sample(Group::Biometric, "npy", format!("vec_{i}.npy"), npy));
    }
    for i in 0..PER_FORMAT {
        let d = EMBED_DIMS[i % EMBED_DIMS.len()];
        let mut members = vec![("arr_0.npy", synth::npy("<f4", &[i as u64 + 1, d]))];
        if i % 2 == 1 {
            members.push(("ids.npy", synth::npy("<i8", &[i as u64 + 1])));
        }
        out.push(sample(
            Group::Biometric,
            "npz",
            format!("batch_{i}.npz"),
            synth::npz(&members),
        ));
    }
    let named = [
        "speaker_embedding",
        "face_embedding",
        "xvector",
        "ecapa.out",
        "voice",
        "embeddings",
    ];
    let unnamed = ["data", "vectors", "tensor_0", "out", "v"];
    for (kind, names) in [
        ("safetensors_named", &named[..]),
        ("safetensors_unnamed", &unnamed[..]),
    ] {
        for i in 0..PER_FORMAT {
            let d = EMBED_DIMS[i % EMBED_DIMS.len()];
            let rows = (i / EMBED_DIMS.len()) as u64 * 3 + 1;
            let dtype = if i % 3 == 0 { "F16" } else { "F32" };
            let shape = [rows, d];
            let bytes = synth::safetensors(&[(names[i % names.len()], dtype, &shape)]);
            out.push(sample(
                Group::Biometric,
                kind,
                format!("t_{i}.safetensors"),
                bytes,
            ));
        }
    }
    for (kind, style) in [
        ("floats_python", FloatStyle::PythonList),
        ("floats_numpy", FloatStyle::NumpyRepr),
        ("floats_json", FloatStyle::JsonArray),
    ] {
        for i in 0..PER_FORMAT {
            let n = EMBED_DIMS[i % EMBED_DIMS.len()] as usize;
            let floats = synth::printed_floats(n, style);
            let (name, text) = match style {
                FloatStyle::PythonList => (format!("vec_{i}.py"), format!("vec_{i} = {floats}\n")),
                FloatStyle::NumpyRepr => (
                    format!("session_{i}.txt"),
                    format!(">>> model.encode(sample_{i})\n{floats}\n>>> \n"),
                ),
                FloatStyle::JsonArray => (
                    format!("out_{i}.json"),
                    floats.replacen("{\n", &format!("{{\n  \"id\": {i},\n"), 1),
                ),
            };
            out.push(sample(Group::Biometric, kind, name, text));
        }
    }
}

/// Bank sizes (tensors per file) of the embedding-bank positives.
const BANK_SIZES: &[usize] = &[3, 5, 20, 109];

/// Identity keys: VCTK speaker ids (`p225`) or `person_NNN`.
fn bank_key(style: usize, k: usize) -> String {
    if style.is_multiple_of(2) {
        format!("p{}", 225 + k)
    } else {
        format!("person_{k:03}")
    }
}

/// Identity keys with an underscore-delimited number: `spk_N_emb`,
/// `speaker_N_vec`, or LibriSpeech-style `19_198_NNNN`.
fn indexed_bank_key(style: usize, k: usize) -> String {
    match style % 3 {
        0 => format!("spk_{k}_emb"),
        1 => format!("speaker_{k}_vec"),
        _ => format!("19_198_{k:04}"),
    }
}

/// Embedding banks: one identically shaped vector per identity.
fn banks(out: &mut Vec<Sample>) {
    bank_set(out, "", &bank_key);
    bank_set(out, "indexed_", &indexed_bank_key);
}

fn bank_set(out: &mut Vec<Sample>, tag: &str, key: &dyn Fn(usize, usize) -> String) {
    let shapes: [&[u64]; 4] = [&[192], &[1, 256], &[3, 256], &[512]];
    for i in 0..PER_FORMAT {
        let n = BANK_SIZES[i % BANK_SIZES.len()];
        let shape = shapes[(i / BANK_SIZES.len()) % shapes.len()];
        let keys: Vec<String> = (0..n).map(|k| key(i, k + i)).collect();
        let t: Vec<(&str, &str, &[u64])> =
            keys.iter().map(|k| (k.as_str(), "F32", shape)).collect();
        out.push(sample(
            Group::Biometric,
            &format!("bank_{tag}safetensors"),
            format!("{tag}store_{i}.safetensors"),
            synth::safetensors(&t),
        ));
        let members: Vec<(String, Vec<u8>)> = keys
            .iter()
            .map(|k| (format!("{k}.npy"), synth::npy("<f4", shape)))
            .collect();
        let refs: Vec<(&str, Vec<u8>)> = members
            .iter()
            .map(|(a, b)| (a.as_str(), b.clone()))
            .collect();
        out.push(sample(
            Group::Biometric,
            &format!("bank_{tag}npz"),
            format!("{tag}store_{i}.npz"),
            synth::npz(&refs),
        ));
    }
}

/// Tensor-count probes around the bank rule.
fn bank_probes(out: &mut Vec<Sample>) {
    let st = |names: &[String], shapes: &[&[u64]]| {
        let t: Vec<(&str, &str, &[u64])> = names
            .iter()
            .zip(shapes)
            .map(|(n, s)| (n.as_str(), "F32", *s))
            .collect();
        synth::safetensors(&t)
    };
    for i in 0..10 {
        let names: Vec<String> = (0..2).map(|k| bank_key(i, k + i)).collect();
        let d = EMBED_DIMS[i % EMBED_DIMS.len()];
        let bytes = st(&names, &[&[d], &[d]]);
        out.push(sample(
            Group::ProbeBiometric,
            "probe_bank_of_2",
            format!("pair_{i}.safetensors"),
            bytes,
        ));
    }
    for i in 0..10 {
        let names: Vec<String> = (0..5).map(|k| bank_key(i, k + i)).collect();
        let dims: Vec<[u64; 1]> = (0..5)
            .map(|k| [EMBED_DIMS[(i + k) % EMBED_DIMS.len()]])
            .collect();
        let shapes: Vec<&[u64]> = dims.iter().map(|d| &d[..]).collect();
        out.push(sample(
            Group::ProbeBiometric,
            "probe_bank_mixed_shapes",
            format!("mixed_{i}.safetensors"),
            st(&names, &shapes),
        ));
    }
    for i in 0..10 {
        let n = BANK_SIZES[i % BANK_SIZES.len()];
        let w = OFF_LIST_DIMS[i % OFF_LIST_DIMS.len()];
        let names: Vec<String> = (0..n).map(|k| bank_key(i, k + i)).collect();
        let shape = [w];
        let shapes: Vec<&[u64]> = (0..n).map(|_| &shape[..]).collect();
        out.push(sample(
            Group::ProbeBiometric,
            "probe_bank_offlist_width",
            format!("store_{i}.safetensors"),
            st(&names, &shapes),
        ));
    }
}

/// Flat numpy MLPs (`W1`..`W4`, `b1`..`b4`) whose hidden width is an
/// embedding width: the biases are exactly half of the float tensors, so not
/// a bank, but each flat bias is an embedding-shaped tensor (known
/// limitation: ask, not deny).
fn mlp_probes(out: &mut Vec<Sample>) {
    for i in 0..10 {
        let w = EMBED_DIMS[i % EMBED_DIMS.len()];
        let mut mlp = vec![
            ("W1".to_string(), "<f4", vec![784u64, w]),
            ("b1".to_string(), "<f4", vec![w]),
        ];
        for l in 2..=4 {
            mlp.push((format!("W{l}"), "<f4", vec![w, w]));
            mlp.push((format!("b{l}"), "<f4", vec![w]));
        }
        let bytes = if i % 2 == 0 {
            npz_header_only(&mlp)
        } else {
            let st: Vec<(String, &str, Vec<u64>)> = mlp
                .iter()
                .map(|(n, _, s)| (n.clone(), "F32", s.clone()))
                .collect();
            safetensors_header_only(&st)
        };
        let ext = if i % 2 == 0 { "npz" } else { "safetensors" };
        out.push(sample(
            Group::ProbeBiometric,
            "probe_flat_mlp",
            format!("mlp_{i}.{ext}"),
            bytes,
        ));
    }
}

/// Widths outside `embedding_dims`.
const OFF_LIST_DIMS: &[u64] = &[100, 300, 1000];

fn probes(out: &mut Vec<Sample>) {
    let dtypes = ["<f4", "<f8", "<f2"];
    for i in 0..10 {
        let w = OFF_LIST_DIMS[i % 3];
        let shape = if i % 2 == 0 {
            vec![i as u64 / 2 + 1, w]
        } else {
            vec![w]
        };
        let bytes = synth::npy(dtypes[(i / 3) % 3], &shape);
        out.push(sample(
            Group::ProbeBiometric,
            "probe_npy_offlist_width",
            format!("vec_{i}.npy"),
            bytes,
        ));
    }
    for i in 0..10 {
        let d = EMBED_DIMS[i % EMBED_DIMS.len()];
        let bytes = synth::npy("<f4", &[2, 2, 2, d]);
        out.push(sample(
            Group::ProbeBiometric,
            "probe_npy_3_leading_dims",
            format!("vec_{i}.npy"),
            bytes,
        ));
    }
    for i in 0..10 {
        let w = OFF_LIST_DIMS[i % 3];
        let rows = (i / 3) as u64 + 1;
        let bytes = synth::safetensors(&[("data", "F32", &[rows, w])]);
        out.push(sample(
            Group::ProbeBiometric,
            "probe_safetensors_offlist_width",
            format!("t_{i}.safetensors"),
            bytes,
        ));
    }
    for i in 0..10 {
        let n = OFF_LIST_DIMS[i % 3] as usize;
        let floats = synth::printed_floats(n, FloatStyle::PythonList);
        out.push(sample(
            Group::ProbeBiometric,
            "probe_floats_offlist_width",
            format!("vec_{i}.py"),
            format!("vec_{i} = {floats}\n"),
        ));
    }
    let env = [
        "STRIPE_KEY",
        "MAILGUN_KEY",
        "SENDGRID_KEY",
        "TWILIO_KEY",
        "ALGOLIA_KEY",
        "PUSHER_KEY",
        "MAPBOX_KEY",
        "SENTRY_KEY",
        "GOOGLE_MAPS_KEY",
        "DATADOG_KEY",
    ];
    for (i, name) in env.iter().enumerate() {
        let line = synth::fake_secret("generic_api_key_assignment", 9100 + i as u64);
        let text = format!("APP_ENV=production\n{name}={}\n", quoted(&line));
        out.push(sample(
            Group::ProbeSecret,
            "probe_generic_env_key",
            ".env".into(),
            text,
        ));
    }
    let other = ["consumer_key", "app_key", "master_key", "HMAC_KEY"];
    for i in 0..12 {
        let line = synth::fake_secret("generic_api_key_assignment", 9200 + i as u64);
        let text = format!(
            "DEBUG = False\n{} = \"{}\"\n",
            other[i % other.len()],
            quoted(&line)
        );
        out.push(sample(
            Group::ProbeSecret,
            "probe_generic_other_key",
            "settings.py".into(),
            text,
        ));
    }
}

/// A safetensors header with offsets but no tensor data, as a checkpoint's
/// first bytes are; the scanner reads headers only.
fn safetensors_header_only(tensors: &[(String, &str, Vec<u64>)]) -> Vec<u8> {
    let refs: Vec<(&str, &str, &[u64])> = tensors
        .iter()
        .map(|(n, d, s)| (n.as_str(), *d, &s[..]))
        .collect();
    synth::safetensors_header(&refs)
}

/// An `.npz` of header-only `.npy` members named `name` (without `.npy`).
fn npz_header_only(members: &[(String, &str, Vec<u64>)]) -> Vec<u8> {
    let m: Vec<(String, Vec<u8>)> = members
        .iter()
        .map(|(n, d, s)| (format!("{n}.npy"), synth::npy_header(d, s)))
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = m.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
    synth::npz(&refs)
}

/// Header-only model checkpoints: parameters with embedding-like names or
/// shapes, alone, and in real-world layouts.
fn checkpoints(out: &mut Vec<Sample>) {
    let t = |n: &str, d: &'static str, s: &[u64]| (n.to_string(), d, s.to_vec());
    let singles = [
        t("pos_embed", "F32", &[1, 197, 768]),
        t("cls_token", "F32", &[1, 1, 768]),
        t(
            "bert.embeddings.word_embeddings.weight",
            "F32",
            &[30522, 768],
        ),
        t("vit.embeddings.position_embeddings", "F32", &[1, 197, 768]),
        t("positional_embedding", "F32", &[77, 512]),
        t("visual.class_embedding", "F32", &[768]),
        t("time_embedding.linear_1.weight", "F16", &[1280, 320]),
    ];
    for (i, one) in singles.into_iter().enumerate() {
        let bytes = safetensors_header_only(&[one]);
        out.push(sample(
            Group::Negative,
            "model_checkpoint",
            format!("param_{i}.safetensors"),
            bytes,
        ));
    }
    let mut bert = vec![
        t("embeddings.word_embeddings.weight", "F32", &[30522, 768]),
        t("embeddings.position_embeddings.weight", "F32", &[512, 768]),
        t("embeddings.token_type_embeddings.weight", "F32", &[2, 768]),
        t("embeddings.LayerNorm.weight", "F32", &[768]),
        t("embeddings.LayerNorm.bias", "F32", &[768]),
    ];
    for l in 0..12 {
        for (p, s) in [
            ("attention.self.query", &[768u64, 768][..]),
            ("attention.self.key", &[768, 768]),
            ("attention.self.value", &[768, 768]),
            ("attention.output.dense", &[768, 768]),
            ("intermediate.dense", &[3072, 768]),
            ("output.dense", &[768, 3072]),
        ] {
            bert.push(t(&format!("encoder.layer.{l}.{p}.weight"), "F32", s));
            bert.push(t(&format!("encoder.layer.{l}.{p}.bias"), "F32", &s[..1]));
        }
    }
    bert.push(t("pooler.dense.weight", "F32", &[768, 768]));
    bert.push(t("pooler.dense.bias", "F32", &[768]));
    let mut clip = vec![
        t("token_embedding.weight", "F16", &[49408, 512]),
        t("positional_embedding", "F16", &[77, 512]),
        t("ln_final.weight", "F16", &[512]),
        t("ln_final.bias", "F16", &[512]),
        t("text_projection", "F16", &[512, 512]),
        t("logit_scale", "F32", &[]),
        t("visual.class_embedding", "F16", &[768]),
        t("visual.positional_embedding", "F16", &[50, 768]),
        t("visual.conv1.weight", "F16", &[768, 3, 32, 32]),
        t("visual.proj", "F16", &[768, 512]),
    ];
    for l in 0..12 {
        for (tower, w) in [("transformer", 512u64), ("visual.transformer", 768)] {
            clip.push(t(
                &format!("{tower}.resblocks.{l}.attn.in_proj_weight"),
                "F16",
                &[3 * w, w],
            ));
            clip.push(t(
                &format!("{tower}.resblocks.{l}.attn.in_proj_bias"),
                "F16",
                &[3 * w],
            ));
            clip.push(t(
                &format!("{tower}.resblocks.{l}.attn.out_proj.weight"),
                "F16",
                &[w, w],
            ));
            clip.push(t(
                &format!("{tower}.resblocks.{l}.mlp.c_fc.weight"),
                "F16",
                &[4 * w, w],
            ));
            clip.push(t(
                &format!("{tower}.resblocks.{l}.mlp.c_proj.weight"),
                "F16",
                &[w, 4 * w],
            ));
        }
    }
    let mut unet = vec![
        t("time_embedding.linear_1.weight", "F16", &[1280, 320]),
        t("time_embedding.linear_1.bias", "F16", &[1280]),
        t("time_embedding.linear_2.weight", "F16", &[1280, 1280]),
        t("conv_in.weight", "F16", &[320, 4, 3, 3]),
        t("conv_out.weight", "F16", &[4, 320, 3, 3]),
    ];
    for (b, ch) in [(0, 320u64), (1, 640), (2, 1280)] {
        let p = format!("down_blocks.{b}.attentions.0.transformer_blocks.0");
        unet.push(t(&format!("{p}.attn1.to_q.weight"), "F16", &[ch, ch]));
        unet.push(t(&format!("{p}.attn2.to_k.weight"), "F16", &[ch, 768]));
        unet.push(t(
            &format!("{p}.ff.net.0.proj.weight"),
            "F16",
            &[8 * ch, ch],
        ));
        unet.push(t(
            &format!("down_blocks.{b}.resnets.0.time_emb_proj.weight"),
            "F16",
            &[ch, 1280],
        ));
    }
    let mut vit = vec![
        t("cls_token", "F32", &[1, 1, 768]),
        t("pos_embed", "F32", &[1, 197, 768]),
        t("patch_embed.proj.weight", "F32", &[768, 3, 16, 16]),
        t("norm.weight", "F32", &[768]),
        t("head.weight", "F32", &[1000, 768]),
    ];
    for l in 0..12 {
        vit.push(t(
            &format!("blocks.{l}.attn.qkv.weight"),
            "F32",
            &[2304, 768],
        ));
        vit.push(t(
            &format!("blocks.{l}.mlp.fc1.weight"),
            "F32",
            &[3072, 768],
        ));
    }
    let reduced_openclip = vec![
        t("positional_embedding", "F32", &[77, 512]),
        t("text_projection", "F32", &[512, 512]),
        t("token_embedding.weight", "F32", &[49408, 512]),
        t("visual.class_embedding", "F32", &[768]),
    ];
    for (name, layout) in [
        ("openclip-reduced", reduced_openclip),
        ("bert-base", bert),
        ("clip-vit-b-32", clip),
        ("sd-unet", unet),
        ("timm-vit-base", vit),
        ("mamba-130m", mamba()),
        ("rwkv4-169m", rwkv4()),
        ("flax-bert-base", flax_bert()),
        ("tf-bert-base", tf_bert()),
    ] {
        out.push(sample(
            Group::Negative,
            "model_checkpoint",
            format!("{name}.safetensors"),
            safetensors_header_only(&layout),
        ));
    }
    out.push(sample(
        Group::Negative,
        "model_checkpoint",
        "ViT-B_16.npz".into(),
        npz_header_only(&google_vit_npz()),
    ));
}

type Layout = Vec<(String, &'static str, Vec<u64>)>;

fn tensor(n: &str, d: &'static str, s: &[u64]) -> (String, &'static str, Vec<u64>) {
    (n.to_string(), d, s.to_vec())
}

/// Mamba-130m (`mamba_ssm` names): `mixer.D` [1536] in each of 24 layers.
fn mamba() -> Layout {
    let t = tensor;
    let mut l = vec![t("backbone.embedding.weight", "F32", &[50280, 768])];
    for i in 0..24 {
        let p = format!("backbone.layers.{i}");
        for (n, s) in [
            ("mixer.A_log", &[1536u64, 16][..]),
            ("mixer.D", &[1536]),
            ("mixer.conv1d.weight", &[1536, 1, 4]),
            ("mixer.conv1d.bias", &[1536]),
            ("mixer.in_proj.weight", &[3072, 768]),
            ("mixer.x_proj.weight", &[80, 1536]),
            ("mixer.dt_proj.weight", &[1536, 48]),
            ("mixer.dt_proj.bias", &[1536]),
            ("mixer.out_proj.weight", &[768, 1536]),
            ("norm.weight", &[768]),
        ] {
            l.push(t(&format!("{p}.{n}"), "F32", s));
        }
    }
    l.push(t("backbone.norm_f.weight", "F32", &[768]));
    l.push(t("lm_head.weight", "F32", &[50280, 768]));
    l
}

/// RWKV-4 169M: `time_mix_*` [1,1,768] and `time_decay`/`time_first` [768].
fn rwkv4() -> Layout {
    let t = tensor;
    let mut l = vec![
        t("emb.weight", "F32", &[50277, 768]),
        t("blocks.0.ln0.weight", "F32", &[768]),
        t("blocks.0.ln0.bias", "F32", &[768]),
    ];
    for i in 0..12 {
        let p = format!("blocks.{i}");
        for (n, s) in [
            ("ln1.weight", &[768u64][..]),
            ("ln1.bias", &[768]),
            ("ln2.weight", &[768]),
            ("ln2.bias", &[768]),
            ("att.time_decay", &[768]),
            ("att.time_first", &[768]),
            ("att.time_mix_k", &[1, 1, 768]),
            ("att.time_mix_v", &[1, 1, 768]),
            ("att.time_mix_r", &[1, 1, 768]),
            ("att.key.weight", &[768, 768]),
            ("att.value.weight", &[768, 768]),
            ("att.receptance.weight", &[768, 768]),
            ("att.output.weight", &[768, 768]),
            ("ffn.time_mix_k", &[1, 1, 768]),
            ("ffn.time_mix_r", &[1, 1, 768]),
            ("ffn.key.weight", &[3072, 768]),
            ("ffn.receptance.weight", &[768, 768]),
            ("ffn.value.weight", &[768, 3072]),
        ] {
            l.push(t(&format!("{p}.{n}"), "F32", s));
        }
    }
    for (n, s) in [
        ("ln_out.weight", &[768u64][..]),
        ("ln_out.bias", &[768]),
        ("head.weight", &[50277, 768]),
    ] {
        l.push(t(n, "F32", s));
    }
    l
}

/// BERT-base layer parameters as `(path, shape)`, joined by `sep` and named
/// with `kernel` and the layer-norm pair `norm`.
fn bert_layers(sep: &str, layer: &dyn Fn(usize) -> String, norm: (&str, &str)) -> Layout {
    let mut l = Vec::new();
    for i in 0..12 {
        let p = layer(i);
        let mut push = |n: String, s: &[u64]| {
            l.push(tensor(
                &format!("{p}{sep}{}", n.replace('.', sep)),
                "F32",
                s,
            ))
        };
        for q in ["query", "key", "value"] {
            push(format!("attention.self.{q}.kernel"), &[768, 768]);
            push(format!("attention.self.{q}.bias"), &[768]);
        }
        push("attention.output.dense.kernel".into(), &[768, 768]);
        push("attention.output.dense.bias".into(), &[768]);
        push("intermediate.dense.kernel".into(), &[768, 3072]);
        push("intermediate.dense.bias".into(), &[3072]);
        push("output.dense.kernel".into(), &[3072, 768]);
        push("output.dense.bias".into(), &[768]);
        for ln in ["attention.output.LayerNorm", "output.LayerNorm"] {
            push(format!("{ln}.{}", norm.0), &[768]);
            push(format!("{ln}.{}", norm.1), &[768]);
        }
    }
    l
}

/// Flax BERT-base (`flax_model.msgpack` names): `kernel`, `scale`,
/// `embedding`, plus a generic Flax module's `LayerNorm_0.scale`.
fn flax_bert() -> Layout {
    let t = tensor;
    let mut l = vec![
        t(
            "bert.embeddings.word_embeddings.embedding",
            "F32",
            &[30522, 768],
        ),
        t(
            "bert.embeddings.position_embeddings.embedding",
            "F32",
            &[512, 768],
        ),
        t(
            "bert.embeddings.token_type_embeddings.embedding",
            "F32",
            &[2, 768],
        ),
        t("bert.embeddings.LayerNorm.scale", "F32", &[768]),
        t("bert.embeddings.LayerNorm.bias", "F32", &[768]),
    ];
    l.extend(bert_layers(
        ".",
        &|i| format!("bert.encoder.layer.{i}"),
        ("scale", "bias"),
    ));
    l.push(t("bert.pooler.dense.kernel", "F32", &[768, 768]));
    l.push(t("bert.pooler.dense.bias", "F32", &[768]));
    l.push(t("LayerNorm_0.scale", "F32", &[768]));
    l.push(t("LayerNorm_0.bias", "F32", &[768]));
    l
}

/// TF BERT-base checkpoint names: `kernel`, `gamma`, `beta`.
fn tf_bert() -> Layout {
    let t = tensor;
    let mut l = vec![
        t("bert/embeddings/word_embeddings", "F32", &[30522, 768]),
        t("bert/embeddings/position_embeddings", "F32", &[512, 768]),
        t("bert/embeddings/token_type_embeddings", "F32", &[2, 768]),
        t("bert/embeddings/LayerNorm/gamma", "F32", &[768]),
        t("bert/embeddings/LayerNorm/beta", "F32", &[768]),
    ];
    l.extend(bert_layers(
        "/",
        &|i| format!("bert/encoder/layer_{i}"),
        ("gamma", "beta"),
    ));
    l.push(t("bert/pooler/dense/kernel", "F32", &[768, 768]));
    l.push(t("bert/pooler/dense/bias", "F32", &[768]));
    l
}

/// Google ViT-B/16 `.npz` (JAX names): `cls`, `kernel`, `scale`.
fn google_vit_npz() -> Layout {
    let t = tensor;
    let f = "<f4";
    let mut l = vec![
        t("cls", f, &[1, 1, 768]),
        t("embedding/kernel", f, &[16, 16, 3, 768]),
        t("embedding/bias", f, &[768]),
        t(
            "Transformer/posembed_input/pos_embedding",
            f,
            &[1, 197, 768],
        ),
        t("Transformer/encoder_norm/scale", f, &[768]),
        t("Transformer/encoder_norm/bias", f, &[768]),
        t("pre_logits/kernel", f, &[768, 768]),
        t("pre_logits/bias", f, &[768]),
        t("head/kernel", f, &[768, 1000]),
        t("head/bias", f, &[1000]),
    ];
    for b in 0..12 {
        let p = format!("Transformer/encoderblock_{b}");
        let a = format!("{p}/MultiHeadDotProductAttention_1");
        for (n, s) in [
            (format!("{p}/LayerNorm_0/scale"), &[768u64][..]),
            (format!("{p}/LayerNorm_0/bias"), &[768]),
            (format!("{p}/LayerNorm_2/scale"), &[768]),
            (format!("{p}/LayerNorm_2/bias"), &[768]),
            (format!("{p}/MlpBlock_3/Dense_0/kernel"), &[768, 3072]),
            (format!("{p}/MlpBlock_3/Dense_0/bias"), &[3072]),
            (format!("{p}/MlpBlock_3/Dense_1/kernel"), &[3072, 768]),
            (format!("{p}/MlpBlock_3/Dense_1/bias"), &[768]),
            (format!("{a}/query/kernel"), &[768, 12, 64]),
            (format!("{a}/query/bias"), &[12, 64]),
            (format!("{a}/key/kernel"), &[768, 12, 64]),
            (format!("{a}/key/bias"), &[12, 64]),
            (format!("{a}/value/kernel"), &[768, 12, 64]),
            (format!("{a}/value/bias"), &[12, 64]),
            (format!("{a}/out/kernel"), &[12, 64, 768]),
            (format!("{a}/out/bias"), &[768]),
        ] {
            l.push(t(&n, f, s));
        }
    }
    l
}

/// Reference vectors in the style of scipy's FFT test data: `sizes` plus
/// `dct_K_N`/`dst_K_N` for K in 1..=4 and N in a list of lengths, several of
/// them embedding widths, so each width repeats 8 times.
fn reference_vectors_npz(dtype: &'static str) -> Vec<u8> {
    const SIZES: &[u64] = &[2, 3, 4, 8, 12, 15, 16, 17, 32, 64, 128, 256, 512, 1024];
    let mut l = vec![tensor("sizes", "<i8", &[SIZES.len() as u64])];
    for kind in ["dct", "dst"] {
        for k in 1..=4 {
            for &n in SIZES {
                l.push(tensor(&format!("{kind}_{k}_{n}"), dtype, &[n]));
            }
        }
    }
    npz_header_only(&l)
}

fn uuid(r: &mut Rng) -> String {
    let a = r.next_u64();
    let b = r.next_u64();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        a >> 32,
        (a >> 16) & 0xffff,
        a & 0xfff,
        0x8000 | ((b >> 48) & 0x3fff),
        b & 0xffff_ffff_ffff
    )
}

fn hex(r: &mut Rng, bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    r.fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn b64(r: &mut Rng, bytes: usize) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b = vec![0u8; bytes];
    r.fill(&mut b);
    b.iter().map(|x| B64[(*x & 63) as usize] as char).collect()
}

fn negatives(out: &mut Vec<Sample>) {
    let neg = |kind: &str, name: String, bytes: Vec<u8>| sample(Group::Negative, kind, name, bytes);
    // Sensor CSVs: plain float matrices (rows of samples, no index) and logs
    // with a header and a timestamp or sample-index column.
    for i in 0..20 {
        let rows = 20 + 37 * i;
        let cols = 2 + i % 11;
        out.push(neg(
            "sensor_csv",
            format!("readings_{i}.csv"),
            synth::csv_rows(rows, cols).into_bytes(),
        ));
    }
    for i in 0..20 {
        let mut r = Rng::new(5000 + i as u64);
        let cols = 3 + i % 6;
        let mut text = String::from(if i % 2 == 0 { "timestamp" } else { "sample" });
        for c in 0..cols {
            text.push_str(&format!(",ch{c}"));
        }
        text.push('\n');
        for row in 0..(50 + 40 * i) {
            if i % 2 == 0 {
                text.push_str(&format!(
                    "2026-10-19T12:{:02}:{:02}.{:03}Z",
                    row / 3600 % 60,
                    row / 60 % 60,
                    row % 1000
                ));
            } else {
                text.push_str(&row.to_string());
            }
            for _ in 0..cols {
                text.push_str(&format!(",{:.4}", r.next_f64() * 9.81));
            }
            text.push('\n');
        }
        out.push(neg("sensor_csv", format!("imu_{i}.csv"), text.into_bytes()));
    }
    // Model weights: many float tensors with layer names.
    for i in 0..25 {
        let h = [64u64, 128, 256][i % 3];
        let tensors: Vec<(String, &str, Vec<u64>)> = match i % 3 {
            0 => vec![
                ("model.embed_tokens.weight".into(), "F16", vec![512, h]),
                (
                    "model.layers.0.self_attn.q_proj.weight".into(),
                    "F16",
                    vec![h, h],
                ),
                (
                    "model.layers.0.mlp.up_proj.weight".into(),
                    "F16",
                    vec![2 * h, h],
                ),
                ("model.norm.weight".into(), "F32", vec![h]),
            ],
            1 => vec![
                ("conv1.weight".into(), "F32", vec![h, 3, 3, 3]),
                ("layer1.0.bn1.running_mean".into(), "F32", vec![h]),
                ("fc.weight".into(), "F32", vec![10, h]),
                ("fc.bias".into(), "F32", vec![10]),
            ],
            _ => vec![
                (
                    "encoder.layer.0.attention.self.query.weight".into(),
                    "F32",
                    vec![h, h],
                ),
                (
                    "encoder.layer.0.intermediate.dense.weight".into(),
                    "BF16",
                    vec![2 * h, h],
                ),
                ("pooler.dense.bias".into(), "F32", vec![h]),
            ],
        };
        let refs: Vec<(&str, &str, &[u64])> = tensors
            .iter()
            .map(|(n, d, s)| (n.as_str(), *d, s.as_slice()))
            .collect();
        out.push(neg(
            "model_safetensors",
            format!("model_{i}.safetensors"),
            synth::safetensors(&refs),
        ));
    }
    let int_dtypes = ["<i4", "<i8", "|u1", "<u2", "<i2"];
    for i in 0..20 {
        let shape: Vec<u64> = match i % 3 {
            0 => vec![10, 192],
            1 => vec![64 + i as u64, 64],
            _ => vec![1000 + i as u64],
        };
        out.push(neg(
            "int_npy",
            format!("labels_{i}.npy"),
            synth::npy(int_dtypes[i % 5], &shape),
        ));
    }
    let placeholders = [
        "GITHUB_TOKEN=<your-github-token>\n",
        "api_key = \"YOUR_API_KEY\"\n",
        "password = \"${DB_PASSWORD}\"\n",
        "secret_key: \"changeme\"\n",
        "export OPENAI_API_KEY=\"sk-...\"\n",
        "token = \"{{ secrets.DEPLOY_TOKEN }}\"\n",
        "aws_secret_access_key = <secret>\n",
        "client_secret: $CLIENT_SECRET\n",
        "STRIPE_KEY=sk_live_REPLACE_ME\n",
        "auth: { token: process.env.API_TOKEN }\n",
    ];
    for i in 0..10 {
        let key = synth::fake_secret("aws_example_key", 6000 + i as u64);
        let text =
            format!("# Example configuration\naws_access_key_id = {key}\nregion = us-east-1\n");
        out.push(neg(
            "example_key",
            format!("example_{i}.cfg"),
            text.into_bytes(),
        ));
    }
    for (i, p) in placeholders.iter().enumerate() {
        let text = format!("# Copy to .env and fill in\n{p}");
        out.push(neg(
            "example_key",
            format!("env_{i}.example"),
            text.into_bytes(),
        ));
    }
    let low = [
        "api_key = \"aaaaaaaaaaaaaaaaaaaaaaaa\"",
        "password = \"password\"",
        "token = \"0000000000000000\"",
        "secret = \"abababababababab\"",
        "auth_key = \"aaaabbbbaaaabbbb\"",
        "PASSWORD=passwordpassword",
        "access_token: \"test-test-test-test\"",
        "api_key: 1111111111111111",
        "credentials = \"none\"",
        "secret_key = \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"",
    ];
    for i in 0..20 {
        let line = if i < low.len() {
            low[i].to_string()
        } else {
            synth::fake_secret("low_entropy_generic", i as u64)
        };
        out.push(neg(
            "low_entropy",
            format!("defaults_{i}.py"),
            format!("# defaults\n{line}\n").into_bytes(),
        ));
    }
    for i in 0..20 {
        let mut r = Rng::new(7000 + i as u64);
        let n = 5 + i * 3;
        let text: String = match i % 4 {
            0 => {
                let items: Vec<String> = (0..n)
                    .map(|j| format!("  {{\"id\": \"{}\", \"name\": \"item{j}\"}}", uuid(&mut r)))
                    .collect();
                format!("[\n{}\n]\n", items.join(",\n"))
            }
            1 => (0..n)
                .map(|_| format!("request_id: {}\n", uuid(&mut r)))
                .collect(),
            2 => {
                let mut t = String::from("uuid,name\n");
                for j in 0..n {
                    t.push_str(&format!("{},row{j}\n", uuid(&mut r)));
                }
                t
            }
            _ => (0..n)
                .map(|j| format!("  <Row key=\"{}\" index={{{j}}} />\n", uuid(&mut r)))
                .collect(),
        };
        out.push(neg("uuid_list", format!("ids_{i}.txt"), text.into_bytes()));
    }
    for i in 0..20 {
        let mut r = Rng::new(8000 + i as u64);
        let n = 3 + i;
        let text: String = match i % 5 {
            0 => (0..n).map(|j| format!("{}  release-{j}.tar.gz\n", hex(&mut r, 32))).collect(),
            1 => (0..n)
                .map(|j| {
                    format!(
                        "[[package]]\nname = \"crate{j}\"\nversion = \"1.0.{j}\"\nchecksum = \"{}\"\n\n",
                        hex(&mut r, 32)
                    )
                })
                .collect(),
            2 => (0..n).map(|_| format!("{{\"commit\": \"{}\"}}\n", hex(&mut r, 20))).collect(),
            3 => (0..n).map(|_| format!("ETag: \"{}\"\n", hex(&mut r, 16))).collect(),
            _ => (0..n).map(|j| format!("sha256:{} layer{j}\n", hex(&mut r, 32))).collect(),
        };
        out.push(neg(
            "hex_hash",
            format!("hashes_{i}.txt"),
            text.into_bytes(),
        ));
    }
    for i in 0..20 {
        let mut r = Rng::new(9000 + i as u64);
        let (name, text) = match i % 4 {
            0 => (
                format!("icon_{i}.css"),
                format!(
                    ".icon {{ background: url(data:image/png;base64,{}); }}\n",
                    b64(&mut r, 600)
                ),
            ),
            1 => {
                let body = b64(&mut r, 800);
                let lines: Vec<&str> = body
                    .as_bytes()
                    .chunks(64)
                    .map(|c| std::str::from_utf8(c).unwrap())
                    .collect();
                (
                    format!("ca_{i}.crt"),
                    format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                        lines.join("\n")
                    ),
                )
            }
            2 => (
                format!("blob_{i}.json"),
                format!(
                    "{{\"encoding\": \"base64\", \"content\": \"{}\"}}\n",
                    b64(&mut r, 400)
                ),
            ),
            _ => (format!("font_{i}.b64"), format!("{}\n", b64(&mut r, 2000))),
        };
        out.push(neg("base64_blob", name, text.into_bytes()));
    }
    for i in 0..20 {
        let text = synth::source_text(4096 + 211 * i, 10_000 + i as u64);
        out.push(neg("source", format!("module_{i}.rs"), text.into_bytes()));
    }
    for i in 0..15 {
        let n = 50 + 20 * i;
        let text: String = if i % 3 == 0 {
            (0..n)
                .map(|j| format!("item{j},{}.99,{}\n", j % 90 + 1, j % 7 + 1))
                .collect()
        } else if i % 3 == 1 {
            (0..n)
                .map(|j| {
                    format!(
                        "2026-10-19 12:00:{:02} latency=0.{:03} ok\n",
                        j % 60,
                        j % 1000
                    )
                })
                .collect()
        } else {
            format!(
                "{{\"weights\": {}}}\n",
                synth::printed_floats(3 + i, FloatStyle::PythonList)
            )
        };
        out.push(neg(
            "prices_logs",
            format!("table_{i}.txt"),
            text.into_bytes(),
        ));
    }
    // Reference-vector archives (scipy FFT test data style).
    for (i, dtype) in ["<f8", "<f4"].into_iter().enumerate() {
        out.push(neg(
            "reference_npz",
            format!("fft_ref_{i}.npz"),
            reference_vectors_npz(dtype),
        ));
    }
}

/// The hard negatives already in the ruleset tests.
fn existing_negatives(out: &mut Vec<Sample>) {
    let neg =
        |kind: &str, name: &str, bytes: Vec<u8>| sample(Group::Negative, kind, name.into(), bytes);
    let src = |s: String| format!("fn main() {{\n    let id = \"{s}\";\n}}\n").into_bytes();
    out.push(neg(
        "existing_low_entropy",
        "settings.py",
        synth::fake_secret("low_entropy_generic", 7).into_bytes(),
    ));
    out.push(neg(
        "existing_example_key",
        "src/main.rs",
        src(synth::fake_secret("aws_example_key", 7)),
    ));
    out.push(neg(
        "existing_vendored",
        "node_modules/dep/index.js",
        src(synth::fake_secret("github_pat", 7)),
    ));
    out.push(neg(
        "existing_der_cert",
        "certs/server.der",
        der(&[0x30, 0x82, 0x03, 0x1c, 0x30, 0x82, 0x02, 0x04], 6),
    ));
    out.push(neg(
        "existing_not_der",
        "keys/server.key",
        b"not a der file\n".to_vec(),
    ));
    out.push(neg(
        "existing_int_npy",
        "a.npy",
        synth::npy("<i8", &[10, 192]),
    ));
    out.push(neg(
        "existing_model_weights",
        "w.safetensors",
        synth::safetensors(&[("layer.0.weight", "F32", &[768, 768])]),
    ));
    out.push(neg(
        "existing_sensor_csv",
        "sensor.csv",
        synth::csv_rows(100, 10).into_bytes(),
    ));
    let prices: String = (0..300)
        .map(|i| format!("item{i},{}.99,{}\n", i % 90 + 1, i % 7 + 1))
        .collect();
    out.push(neg("existing_prices", "prices.csv", prices.into_bytes()));
    let logs: String = (0..300)
        .map(|i| {
            format!(
                "2026-10-19 12:00:{:02} latency=0.{:03} ok\n",
                i % 60,
                i % 1000
            )
        })
        .collect();
    out.push(neg("existing_log", "app.log", logs.into_bytes()));
    out.push(neg(
        "existing_small_floats",
        "small.json",
        synth::printed_floats(5, FloatStyle::PythonList).into_bytes(),
    ));
}

/// Ways the corpus falls short of the minimum sample counts.
pub fn shortfalls(c: &[Sample]) -> Vec<String> {
    let mut by: BTreeMap<(Group, &str), usize> = BTreeMap::new();
    for s in c {
        *by.entry((s.group, s.kind.as_str())).or_default() += 1;
    }
    let n = |g, k: &str| by.get(&(g, k)).copied().unwrap_or(0);
    let mut out = Vec::new();
    let mut need = |what: String, have: usize, min: usize| {
        if have < min {
            out.push(format!("{what}: {have} samples, need {min}"));
        }
    };
    for k in PROVIDER_KINDS.iter().chain(KEYSTORE_KINDS) {
        need(format!("provider {k}"), n(Group::Provider, k), PER_FORMAT);
    }
    need(
        "provider encoded_text".into(),
        n(Group::Provider, "encoded_text"),
        PROVIDER_KINDS.len() * ENCODINGS.len(),
    );
    need(
        "generic_api_key".into(),
        n(Group::Generic, "generic_api_key"),
        GENERIC,
    );
    for k in BIOMETRIC_KINDS {
        need(format!("biometric {k}"), n(Group::Biometric, k), PER_FORMAT);
    }
    let generated = c
        .iter()
        .filter(|s| s.group == Group::Negative && !s.kind.starts_with("existing_"))
        .count();
    need("generated negatives".into(), generated, GENERATED_NEGATIVES);
    for k in PROBE_KINDS {
        let have = c
            .iter()
            .filter(|s| s.group.is_probe() && s.kind == *k)
            .count();
        need(format!("probe {k}"), have, 10);
    }
    for k in NEGATIVE_KINDS {
        need(format!("negative {k}"), n(Group::Negative, k), 1);
    }
    need(
        "existing negatives".into(),
        c.iter().filter(|s| s.kind.starts_with("existing_")).count(),
        1,
    );
    out
}

// ---- thresholds and metrics --------------------------------------------------

/// Default thresholds per category: `(label, value)`, e.g.
/// `("claude_code.ask", 80.0)`.
pub fn thresholds(cfg: &Config) -> BTreeMap<String, Vec<(String, f64)>> {
    let mut out: BTreeMap<String, Vec<(String, f64)>> = BTreeMap::new();
    for (cat, t) in &cfg.claude_code.thresholds {
        let v = out.entry(cat.0.clone()).or_default();
        if let Some(a) = t.ask {
            v.push(("claude_code.ask".into(), a));
        }
        if let Some(d) = t.deny {
            v.push(("claude_code.deny".into(), d));
        }
    }
    for (cat, b) in &cfg.git.block_at {
        out.entry(cat.0.clone())
            .or_default()
            .push(("git.block_at".into(), *b));
    }
    out
}

/// The lowest default threshold per category: a file at or above it is
/// "flagged".
pub fn flag_thresholds(cfg: &Config) -> BTreeMap<String, f64> {
    thresholds(cfg)
        .into_iter()
        .filter_map(|(c, v)| v.iter().map(|(_, t)| *t).reduce(f64::min).map(|m| (c, m)))
        .collect()
}

pub fn per_1000(flagged: u64, files: u64) -> f64 {
    if files == 0 {
        0.0
    } else {
        flagged as f64 * 1000.0 / files as f64
    }
}

/// The release bar: `(metric, at least, at most)`.
const BAR: &[(&str, f64, f64)] = &[
    ("recall.provider", 1.0, 1.0),
    ("recall.biometric", 1.0, 1.0),
    ("recall.generic", 0.9, 1.0),
    ("fp_per_1000.synthetic.secret", 0.0, 1.0),
    ("fp_per_1000.synthetic.biometric", 0.0, 1.0),
    ("fp_per_1000.oss.secret", 0.0, 1.0),
    ("fp_per_1000.oss.biometric", 0.0, 1.0),
];

const EPS: f64 = 1e-9;

/// Release-bar violations, one message each. `oss` says whether OSS
/// metrics are part of this run.
pub fn bar_failures(metrics: &BTreeMap<String, f64>, oss: bool) -> Vec<String> {
    let mut out = Vec::new();
    for (key, lo, hi) in BAR {
        if !oss && key.contains(".oss.") {
            continue;
        }
        match metrics.get(*key) {
            None => out.push(format!("{key}: missing")),
            Some(v) if *v < lo - EPS || *v > hi + EPS => {
                out.push(format!("{key} = {v:.4}: bar is {lo}..={hi}"))
            }
            Some(_) => {}
        }
    }
    out
}

/// Metrics worse than the baseline. `recall.*` must not fall,
/// `fp_per_1000.*` must not rise; other keys are informational.
pub fn regressions(
    current: &BTreeMap<String, f64>,
    baseline: &BTreeMap<String, f64>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (key, base) in baseline {
        let Some(cur) = current.get(key) else {
            continue;
        };
        let worse = if key.starts_with("recall.") {
            *cur < base - EPS
        } else if key.starts_with("fp_per_1000.") {
            *cur > base + EPS
        } else {
            false
        };
        if worse {
            out.push(format!("{key}: {cur:.4}, baseline {base:.4}"));
        }
    }
    out
}

/// The baseline to write: `current`, keeping the old OSS metrics when this
/// run skipped them.
pub fn merged_baseline(
    current: &BTreeMap<String, f64>,
    old: &BTreeMap<String, f64>,
    skipped_oss: bool,
) -> BTreeMap<String, f64> {
    let mut out = current.clone();
    if skipped_oss {
        for (k, v) in old {
            if k.contains("oss") && !out.contains_key(k) {
                out.insert(k.clone(), *v);
            }
        }
    }
    out
}

/// Lines describing how `new` differs from `old`: changed, added, and
/// removed keys.
pub fn baseline_diff(old: &BTreeMap<String, f64>, new: &BTreeMap<String, f64>) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in new {
        match old.get(k) {
            Some(o) if (o - v).abs() <= EPS => {}
            Some(o) => out.push(format!("{k}: {o} -> {v}")),
            None => out.push(format!("{k}: added {v}")),
        }
    }
    for (k, o) in old {
        if !new.contains_key(k) {
            out.push(format!("{k}: removed (was {o})"));
        }
    }
    out
}

// ---- scan reports ------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ScanReport {
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    pub target: String,
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub scores: BTreeMap<String, f64>,
    #[serde(default)]
    pub evidence: Vec<Ev>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Ev {
    pub rule: String,
    pub category: String,
    pub weight: f64,
    #[serde(default)]
    pub locations: Vec<Loc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Loc {
    pub line_start: u32,
}

impl Target {
    pub fn content_scanned(&self) -> bool {
        matches!(self.status.as_str(), "scanned" | "partial")
    }

    pub fn score(&self, category: &str) -> f64 {
        self.scores.get(category).copied().unwrap_or(0.0)
    }

    /// `(rule, line)` for each positive-weight location in `category`; line
    /// 0 for evidence without locations (path and whole-file rules).
    pub fn hits(&self, category: &str) -> Vec<(String, u32)> {
        let mut out = Vec::new();
        for e in self
            .evidence
            .iter()
            .filter(|e| e.category == category && e.weight > 0.0)
        {
            if e.locations.is_empty() {
                out.push((e.rule.clone(), 0));
            }
            for l in &e.locations {
                out.push((e.rule.clone(), l.line_start));
            }
        }
        out
    }
}

/// A file the scan could not read or finish (status `unscanned`, for
/// example a scan that ran past the time budget).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unscanned {
    /// `<repo>/<path>`.
    pub path: String,
    pub reason: String,
}

/// The unscanned targets of one repository's report.
pub fn unscanned(report: &ScanReport, repo: &str) -> Vec<Unscanned> {
    report
        .targets
        .iter()
        .filter(|t| t.status == "unscanned")
        .map(|t| Unscanned {
            path: format!("{repo}/{}", t.target),
            reason: t.reason.clone().unwrap_or_default(),
        })
        .collect()
}

impl Unscanned {
    /// The scan ran past the time budget: this depends on machine load, so
    /// the file may be scanned in another run.
    pub fn timed_out(&self) -> bool {
        self.reason == "timeout"
    }
}

/// `files.oss.unscanned` (every unscanned file, including archives, which
/// are never scanned), `files.oss.timed_out`, and one
/// `timed_out.oss.<repo>/<path>` key per timed-out file (value 1), so the
/// baseline lists them. All are informational: neither gated nor compared.
pub fn record_unscanned(list: &[Unscanned], metrics: &mut BTreeMap<String, f64>) {
    metrics.insert("files.oss.unscanned".into(), list.len() as f64);
    let timed_out: Vec<&Unscanned> = list.iter().filter(|u| u.timed_out()).collect();
    metrics.insert("files.oss.timed_out".into(), timed_out.len() as f64);
    for u in timed_out {
        metrics.insert(format!("timed_out.oss.{}", u.path), 1.0);
    }
}

/// An OSS finding judged a true positive (or an embedding by name) and
/// excluded from the false-positive count. `path` is relative to `eval/oss`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
pub struct KnownFinding {
    pub rule: String,
    pub path: String,
    pub line: u32,
}

/// True when every hit behind `t`'s `category` score is a known finding.
pub fn excluded(t: &Target, repo: &str, category: &str, known: &BTreeSet<KnownFinding>) -> bool {
    let path = format!("{repo}/{}", t.target);
    let hits = t.hits(category);
    !hits.is_empty()
        && hits.into_iter().all(|(rule, line)| {
            known.contains(&KnownFinding {
                rule,
                path: path.clone(),
                line,
            })
        })
}

// ---- OSS repository list -----------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Repo {
    pub name: String,
    pub url: String,
    pub commit: String,
    pub language: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoList {
    repo: Vec<Repo>,
}

/// Parse and validate `oss-repos.toml`: at least 10 repositories across at
/// least 5 languages, unique names, `https://github.com/` URLs, and full
/// 40-hex commits.
pub fn parse_repos(text: &str) -> Result<Vec<Repo>, String> {
    let list: RepoList = toml::from_str(text).map_err(|e| format!("oss-repos.toml: {e}"))?;
    let mut names = BTreeSet::new();
    for r in &list.repo {
        let ok_name = !r.name.is_empty()
            && r.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            && !r.name.starts_with('.');
        if !ok_name || !names.insert(r.name.as_str()) {
            return Err(format!(
                "oss-repos.toml: bad or duplicate name `{}`",
                r.name
            ));
        }
        if !r.url.starts_with("https://github.com/") {
            return Err(format!(
                "oss-repos.toml: {}: url must be https://github.com/...",
                r.name
            ));
        }
        if r.commit.len() != 40 || !r.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "oss-repos.toml: {}: commit must be 40 hex digits",
                r.name
            ));
        }
    }
    let langs: BTreeSet<&str> = list.repo.iter().map(|r| r.language.as_str()).collect();
    if list.repo.len() < 10 || langs.len() < 5 {
        return Err(format!(
            "oss-repos.toml: need at least 10 repositories in 5 languages, have {} in {}",
            list.repo.len(),
            langs.len()
        ));
    }
    Ok(list.repo)
}

/// The workspace root (the parent of the `xtask` crate).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

// ---- running -----------------------------------------------------------------

const USAGE: &str = "usage: cargo xtask eval [--skip-oss] [--write-baseline] [--keep-corpus DIR]";

/// Metric values are stored rounded, so reruns compare equal.
fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

struct Ctx {
    root: PathBuf,
    bin: PathBuf,
    home: PathBuf,
    out_dir: PathBuf,
    flags: BTreeMap<String, f64>,
    thresholds: BTreeMap<String, Vec<(String, f64)>>,
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"))
}

fn build_release(root: &Path) -> Result<PathBuf, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "--release", "-p", "riskgrep"])
        .current_dir(root)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build --release -p riskgrep: {status}"));
    }
    Ok(target_dir(root).join("release/riskgrep"))
}

/// `riskgrep scan --no-cache --format json -- ARGS` in `cwd`, with `HOME`
/// pointing at an empty eval home (no user config, no cache). The raw
/// report (rule ids, paths, lines, scores: no content) is kept at `save`.
fn scan(ctx: &Ctx, cwd: &Path, args: &[String], save: &Path) -> Result<ScanReport, String> {
    let out = Command::new(&ctx.bin)
        .args(["scan", "--no-cache", "--format", "json", "--"])
        .args(args)
        .current_dir(cwd)
        .env("HOME", &ctx.home)
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("{}: {e}", ctx.bin.display()))?;
    if !out.status.success() {
        return Err(format!(
            "riskgrep scan in {}: {}",
            cwd.display(),
            out.status
        ));
    }
    fs::write(save, &out.stdout).map_err(|e| format!("{}: {e}", save.display()))?;
    serde_json::from_slice(&out.stdout).map_err(|e| format!("riskgrep report: {e}"))
}

/// `rule@line` list of the hits behind a category score.
fn hit_list(t: &Target, category: &str) -> String {
    t.hits(category)
        .iter()
        .map(|(r, l)| format!("{r}@{l}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn run(args: &[String]) -> Result<(), String> {
    let (mut skip_oss, mut write_baseline) = (false, false);
    let mut keep: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--skip-oss" => skip_oss = true,
            "--write-baseline" => write_baseline = true,
            "--keep-corpus" => {
                let d = PathBuf::from(
                    it.next()
                        .ok_or(format!("--keep-corpus needs a directory\n{USAGE}"))?,
                );
                if d.exists()
                    && fs::read_dir(&d)
                        .map_err(|e| e.to_string())?
                        .next()
                        .is_some()
                {
                    return Err(format!("--keep-corpus: {} is not empty", d.display()));
                }
                keep = Some(d);
            }
            other => return Err(format!("unknown argument `{other}`\n{USAGE}")),
        }
    }
    let root = workspace_root();
    let bin = build_release(&root)?;
    let tmp = tempfile::Builder::new()
        .prefix("riskgrep-eval-")
        .tempdir()
        .map_err(|e| format!("temp dir: {e}"))?;
    let home = tmp.path().join("home");
    let cfg_dir = home.join(".config/riskgrep");
    fs::create_dir_all(&cfg_dir).map_err(|e| e.to_string())?;
    // Repositories are larger than the default walk limit.
    fs::write(
        cfg_dir.join("config.toml"),
        "[limits]\nwalk_files = 10000000\n",
    )
    .map_err(|e| e.to_string())?;
    let out_dir = target_dir(&root).join("eval");
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let cfg = Config::default();
    let ctx = Ctx {
        bin,
        home,
        out_dir,
        flags: flag_thresholds(&cfg),
        thresholds: thresholds(&cfg),
        root,
    };
    for (cat, f) in &ctx.flags {
        let at: Vec<String> = ctx.thresholds[cat]
            .iter()
            .map(|(l, t)| format!("{l} {t}"))
            .collect();
        println!("{cat}: flagged at >= {f} ({})", at.join(", "));
    }

    let mut metrics = BTreeMap::new();
    let corpus_dir = keep.unwrap_or_else(|| tmp.path().join("corpus"));
    synthetic(&ctx, &corpus_dir, &mut metrics)?;
    if !skip_oss {
        oss(&ctx, &mut metrics)?;
    }

    println!("\nmetrics:");
    for (k, v) in &metrics {
        println!("  {k:<44} {v}");
    }
    let json =
        |m: &BTreeMap<String, f64>| serde_json::to_string_pretty(m).expect("metrics json") + "\n";
    let latest = ctx.out_dir.join("metrics.json");
    fs::write(&latest, json(&metrics)).map_err(|e| e.to_string())?;

    let baseline_path = ctx.root.join("eval/baseline-metrics.json");
    let old: BTreeMap<String, f64> = match fs::read(&baseline_path) {
        Ok(b) => {
            serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", baseline_path.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(format!("{}: {e}", baseline_path.display())),
    };
    let mut failures = bar_failures(&metrics, !skip_oss);
    failures.extend(
        regressions(&metrics, &old)
            .into_iter()
            .map(|r| format!("worse than baseline: {r}")),
    );
    let merged = merged_baseline(&metrics, &old, skip_oss);
    if write_baseline {
        fs::write(&baseline_path, json(&merged)).map_err(|e| e.to_string())?;
        println!("\nwrote {}", baseline_path.display());
    } else {
        let diff = baseline_diff(&old, &merged);
        if diff.is_empty() {
            println!("\nbaseline unchanged");
        } else {
            println!(
                "\n--write-baseline would change {}:",
                baseline_path.display()
            );
            for d in &diff {
                println!("  {d}");
            }
        }
    }
    if !failures.is_empty() {
        println!("\nFAIL:");
        for f in &failures {
            println!("  {f}");
        }
        return Err(format!(
            "eval failed ({} problems); metrics in {}",
            failures.len(),
            latest.display()
        ));
    }
    println!("\nPASS: release bar met and no metric worse than the baseline");
    Ok(())
}

#[derive(Default)]
struct Tally {
    files: u64,
    /// Flagged count per threshold label (and "flag").
    flagged: BTreeMap<String, u64>,
}

impl Tally {
    fn add(&mut self, ctx: &Ctx, category: &str, score: f64) {
        self.files += 1;
        if score >= ctx.flags[category] {
            *self.flagged.entry("flag".into()).or_default() += 1;
        }
        for (label, t) in &ctx.thresholds[category] {
            if score >= *t {
                *self.flagged.entry(label.clone()).or_default() += 1;
            }
        }
    }

    fn count(&self, label: &str) -> u64 {
        self.flagged.get(label).copied().unwrap_or(0)
    }

    fn recall(&self, label: &str) -> f64 {
        if self.files == 0 {
            0.0
        } else {
            self.count(label) as f64 / self.files as f64
        }
    }
}

/// Writes the corpus to `dir` (sample `i` in `dir/sNNNN/`) and scans it.
fn synthetic(ctx: &Ctx, dir: &Path, metrics: &mut BTreeMap<String, f64>) -> Result<(), String> {
    let samples = corpus();
    let short = shortfalls(&samples);
    if !short.is_empty() {
        return Err(format!("synthetic corpus: {}", short.join("; ")));
    }
    let mut dirs = Vec::with_capacity(samples.len());
    for (i, s) in samples.iter().enumerate() {
        let d = format!("s{i:04}");
        let p = dir.join(&d).join(&s.name);
        fs::create_dir_all(p.parent().expect("sample parent")).map_err(|e| e.to_string())?;
        fs::write(&p, &s.bytes).map_err(|e| format!("{}: {e}", p.display()))?;
        dirs.push(d);
    }
    let report = scan(ctx, dir, &dirs, &ctx.out_dir.join("synthetic.json"))?;
    let mut by_sample: BTreeMap<usize, &Target> = BTreeMap::new();
    for t in &report.targets {
        let idx = t
            .target
            .strip_prefix('s')
            .and_then(|r| r.split('/').next())
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| format!("unexpected target `{}`", t.target))?;
        by_sample.insert(idx, t);
    }

    // Positives: tallies by (group, kind) and by group.
    let mut kinds: BTreeMap<(Group, String), Tally> = BTreeMap::new();
    let mut groups: BTreeMap<Group, Tally> = BTreeMap::new();
    let mut neg: BTreeMap<String, Tally> = BTreeMap::new();
    let mut neg_kinds: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut neg_files = 0u64;
    let mut probes: BTreeMap<String, Tally> = BTreeMap::new();
    // Misses and flagged negatives by (what, kind), listed up to 3 each.
    let mut notes: BTreeMap<(&str, String), Vec<String>> = BTreeMap::new();
    for (i, s) in samples.iter().enumerate() {
        let t = by_sample
            .get(&i)
            .ok_or_else(|| format!("sample s{i:04} ({}) missing from the report", s.kind))?;
        if !t.content_scanned() {
            return Err(format!(
                "sample {} ({}) not scanned: {}",
                t.target, s.kind, t.status
            ));
        }
        match s.group.category() {
            Some(cat) if s.group.is_probe() => {
                probes
                    .entry(s.kind.clone())
                    .or_default()
                    .add(ctx, cat, t.score(cat));
            }
            Some(cat) => {
                let score = t.score(cat);
                kinds
                    .entry((s.group, s.kind.clone()))
                    .or_default()
                    .add(ctx, cat, score);
                groups.entry(s.group).or_default().add(ctx, cat, score);
                if score < ctx.flags[cat] {
                    notes
                        .entry(("miss", s.kind.clone()))
                        .or_default()
                        .push(format!(
                            "{:<40} {cat}={score:.1} {}",
                            t.target,
                            hit_list(t, cat)
                        ));
                }
            }
            None => {
                neg_files += 1;
                for cat in ctx.flags.keys() {
                    let score = t.score(cat);
                    neg.entry(cat.clone()).or_default().add(ctx, cat, score);
                    if score >= ctx.flags[cat] {
                        *neg_kinds.entry((cat.clone(), s.kind.clone())).or_default() += 1;
                        notes
                            .entry(("flagged", s.kind.clone()))
                            .or_default()
                            .push(format!(
                                "{:<40} {cat}={score:.1} {}",
                                t.target,
                                hit_list(t, cat)
                            ));
                    }
                }
            }
        }
    }

    println!("\nsynthetic positives (recall)");
    let labels = |cat: &str| -> Vec<String> {
        std::iter::once("flag".to_string())
            .chain(ctx.thresholds[cat].iter().map(|(l, _)| l.clone()))
            .collect()
    };
    for ((g, kind), t) in &kinds {
        let cat = g.category().expect("positive");
        let cols: Vec<String> = labels(cat)
            .iter()
            .map(|l| format!("{l} {:.3}", t.recall(l)))
            .collect();
        println!(
            "  {:<9} {kind:<20} n={:<3} {}",
            format!("{g:?}"),
            t.files,
            cols.join("  ")
        );
    }
    for (g, t) in &groups {
        let cat = g.category().expect("positive");
        let cols: Vec<String> = labels(cat)
            .iter()
            .map(|l| format!("{l} {:.3}", t.recall(l)))
            .collect();
        println!(
            "  {:<9} {:<20} n={:<3} {}",
            format!("{g:?}"),
            "(all)",
            t.files,
            cols.join("  ")
        );
    }
    println!("\nprobes (not gated: widths outside embedding_dims, other key names)");
    for (kind, t) in &probes {
        let cat = if kind.starts_with("probe_generic") {
            SECRET
        } else {
            BIOMETRIC
        };
        let cols: Vec<String> = labels(cat)
            .iter()
            .map(|l| format!("{l} {:.3}", t.recall(l)))
            .collect();
        println!("  {kind:<32} n={:<3} {}", t.files, cols.join("  "));
    }
    println!("\nsynthetic hard negatives: {neg_files} files (false positives per 1,000)");
    for (cat, t) in &neg {
        let cols: Vec<String> = labels(cat)
            .iter()
            .map(|l| format!("{l} {} ({:.1})", t.count(l), per_1000(t.count(l), t.files)))
            .collect();
        println!("  {cat:<10} {}", cols.join("  "));
    }
    for ((cat, kind), n) in &neg_kinds {
        println!("  {cat:<10} {kind:<24} {n} flagged");
    }
    if !notes.is_empty() {
        println!();
        for ((what, kind), list) in &notes {
            for n in list.iter().take(3) {
                println!("  {what:<8} {kind:<20} {n}");
            }
            if list.len() > 3 {
                println!("  {what:<8} {kind:<20} ... and {} more", list.len() - 3);
            }
        }
    }

    for ((g, kind), t) in &kinds {
        let key = match g {
            Group::Provider => format!("recall.provider.{kind}"),
            Group::Biometric => format!("recall.biometric.{kind}"),
            _ => continue,
        };
        metrics.insert(key, round4(t.recall("flag")));
    }
    for (g, t) in &groups {
        let key = format!("recall.{}", format!("{g:?}").to_ascii_lowercase());
        metrics.insert(key, round4(t.recall("flag")));
    }
    for (cat, t) in &neg {
        metrics.insert(
            format!("fp_per_1000.synthetic.{cat}"),
            round4(per_1000(t.count("flag"), t.files)),
        );
    }
    metrics.insert(
        "files.synthetic.positive".into(),
        groups.values().map(|t| t.files).sum::<u64>() as f64,
    );
    metrics.insert("files.synthetic.negative".into(), neg_files as f64);
    // Informational: `probe.*` keys are neither gated nor compared.
    for (kind, t) in &probes {
        metrics.insert(
            format!("probe.{}", kind.trim_start_matches("probe_")),
            round4(t.recall("flag")),
        );
    }
    Ok(())
}

/// Run git in `dir` with hooks and LFS downloads disabled.
fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "advice.detachedHead=false",
        ])
        .args(args)
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} in {}: {}",
            args.join(" "),
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// True when the checkout differs from its commit: modified, staged, or
/// untracked (not ignored) files. An untracked file would be scanned as if it
/// were part of the pinned repository.
fn has_local_changes(dir: &Path) -> Result<bool, String> {
    Ok(!git(dir, &["status", "--porcelain", "--untracked-files=all"])?.is_empty())
}

/// Ignored files and directories present in a clone (build output left by a
/// build run inside it): the count of ignored entries and their top-level
/// names. They are not part of the corpus, which is the tracked files only.
fn ignored_in_clone(dir: &Path) -> Result<(usize, BTreeSet<String>), String> {
    let out = git(dir, &["status", "--porcelain", "--ignored"])?;
    let mut n = 0;
    let mut tops = BTreeSet::new();
    for line in out.lines().filter_map(|l| l.strip_prefix("!! ")) {
        n += 1;
        let top = line.trim_end_matches('/').split('/').next().unwrap_or(line);
        tops.insert(top.to_string());
    }
    Ok((n, tops))
}

/// Warn (never fail) when a clone holds ignored files.
fn warn_ignored(dir: &Path, name: &str) {
    if let Ok((n, tops)) = ignored_in_clone(dir) {
        if n > 0 {
            let tops: Vec<&str> = tops.iter().map(String::as_str).collect();
            eprintln!(
                "warning: {name}: {n} ignored entries in the clone ({}); they are not scanned, the corpus is the tracked files only",
                tops.join(", ")
            );
        }
    }
}

/// Upper bound on the bytes of path arguments for one scanner invocation,
/// far below the OS argument limit (1 MiB on macOS, 2 MiB on Linux).
const ARGV_BUDGET: usize = 128 * 1024;

/// The corpus of a clone: regular files tracked at its checked-out commit,
/// relative to `dir`. Untracked and ignored files, symlinks, and submodules
/// are not included.
fn tracked_files(dir: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.hooksPath=/dev/null", "ls-files", "-z"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut files = BTreeSet::new();
    for raw in out.stdout.split(|&b| b == 0).filter(|p| !p.is_empty()) {
        let rel = std::str::from_utf8(raw)
            .map_err(|_| format!("{}: tracked path is not UTF-8", dir.display()))?;
        let is_file = fs::symlink_metadata(dir.join(rel))
            .map(|m| m.file_type().is_file())
            .unwrap_or(false);
        if is_file {
            // A bare `-` would mean standard input to the scanner.
            files.insert(if rel == "-" {
                "./-".into()
            } else {
                rel.to_string()
            });
        }
    }
    Ok(files.into_iter().collect())
}

/// Split `paths` into batches whose combined length stays under `budget` bytes.
fn batches(paths: &[String], budget: usize) -> Vec<&[String]> {
    let mut out = Vec::new();
    let (mut start, mut size) = (0, 0);
    for (i, p) in paths.iter().enumerate() {
        let cost = p.len() + 1;
        if i > start && size + cost > budget {
            out.push(&paths[start..i]);
            start = i;
            size = 0;
        }
        size += cost;
    }
    if start < paths.len() {
        out.push(&paths[start..]);
    }
    out
}

/// A clean shallow checkout of `r` at its pinned commit under `oss`.
fn ensure_clone(oss: &Path, r: &Repo) -> Result<PathBuf, String> {
    let dir = oss.join(&r.name);
    if dir.join(".git").exists() {
        if git(&dir, &["rev-parse", "HEAD"]).ok().as_deref() == Some(r.commit.as_str()) {
            if has_local_changes(&dir)? {
                return Err(format!(
                    "{}: checkout has local changes or untracked files",
                    dir.display()
                ));
            }
            warn_ignored(&dir, &r.name);
            return Ok(dir);
        }
    } else {
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        git(&dir, &["init", "-q"])?;
    }
    println!("fetching {} at {}", r.url, r.commit);
    git(
        &dir,
        &[
            "fetch",
            "-q",
            "--depth",
            "1",
            "--no-tags",
            &r.url,
            &r.commit,
        ],
    )?;
    git(
        &dir,
        &["checkout", "-q", "--detach", "--force", "FETCH_HEAD"],
    )?;
    let head = git(&dir, &["rev-parse", "HEAD"])?;
    if head != r.commit {
        return Err(format!("{}: HEAD is {head}, expected {}", r.name, r.commit));
    }
    warn_ignored(&dir, &r.name);
    Ok(dir)
}

fn oss(ctx: &Ctx, metrics: &mut BTreeMap<String, f64>) -> Result<(), String> {
    let list_path = ctx.root.join("eval/oss-repos.toml");
    let repos = parse_repos(
        &fs::read_to_string(&list_path).map_err(|e| format!("{}: {e}", list_path.display()))?,
    )?;
    let known_path = ctx.root.join("eval/oss-known-findings.json");
    let known: BTreeSet<KnownFinding> = match fs::read(&known_path) {
        Ok(b) => serde_json::from_slice::<Vec<KnownFinding>>(&b)
            .map_err(|e| format!("{}: {e}", known_path.display()))?
            .into_iter()
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(format!("{}: {e}", known_path.display())),
    };
    let oss_dir = ctx.root.join("eval/oss");
    let mut used: BTreeSet<KnownFinding> = BTreeSet::new();
    let mut total: BTreeMap<String, Tally> = BTreeMap::new();
    let mut excluded_n: BTreeMap<String, u64> = BTreeMap::new();
    let mut flagged_lines = Vec::new();
    let mut not_scanned: Vec<Unscanned> = Vec::new();
    let mut files = 0u64;
    println!("\nOSS repositories");
    for r in &repos {
        let dir = ensure_clone(&oss_dir, r)?;
        let tracked = tracked_files(&dir)?;
        let mut targets: Vec<Target> = Vec::new();
        for (i, batch) in batches(&tracked, ARGV_BUDGET).into_iter().enumerate() {
            let report = scan(
                ctx,
                &dir,
                batch,
                &ctx.out_dir.join(format!("oss-{}-{i:03}.json", r.name)),
            )?;
            targets.extend(report.targets);
        }
        let report = ScanReport { targets };
        let (mut scanned, mut skipped) = (0u64, 0u64);
        let repo_unscanned = unscanned(&report, &r.name);
        let mut repo_flags: BTreeMap<String, u64> = BTreeMap::new();
        for t in &report.targets {
            if !t.content_scanned() {
                if t.status != "unscanned" {
                    skipped += 1;
                }
                continue;
            }
            scanned += 1;
            for cat in ctx.flags.keys() {
                let score = t.score(cat);
                if score >= ctx.flags[cat] {
                    let path = format!("{}/{}", r.name, t.target);
                    if excluded(t, &r.name, cat, &known) {
                        *excluded_n.entry(cat.clone()).or_default() += 1;
                        for (rule, line) in t.hits(cat) {
                            used.insert(KnownFinding {
                                rule,
                                path: path.clone(),
                                line,
                            });
                        }
                        // Counted as a file, not as a false positive.
                        total.entry(cat.clone()).or_default().add(ctx, cat, 0.0);
                        continue;
                    }
                    *repo_flags.entry(cat.clone()).or_default() += 1;
                    flagged_lines.push(format!(
                        "  {cat:<10} {score:>5.1}  {path}  {}",
                        hit_list(t, cat)
                    ));
                }
                total.entry(cat.clone()).or_default().add(ctx, cat, score);
            }
        }
        files += scanned;
        let flags: Vec<String> = repo_flags.iter().map(|(c, n)| format!("{c} {n}")).collect();
        println!(
            "  {:<16} {:<10} {:>6} files scanned, {:>5} skipped, {:>2} unscanned  flagged: {}",
            r.name,
            r.language,
            scanned,
            skipped,
            repo_unscanned.len(),
            if flags.is_empty() {
                "none".into()
            } else {
                flags.join(", ")
            }
        );
        not_scanned.extend(repo_unscanned);
    }
    println!(
        "\nOSS: {files} files scanned, {} unscanned, {} of them timed out (false positives per 1,000 scanned files, known findings excluded)",
        not_scanned.len(),
        not_scanned.iter().filter(|u| u.timed_out()).count()
    );
    for u in &not_scanned {
        println!("  unscanned  {}  ({})", u.path, u.reason);
    }
    record_unscanned(&not_scanned, metrics);
    for (cat, t) in &total {
        let mut labels = vec!["flag".to_string()];
        labels.extend(ctx.thresholds[cat].iter().map(|(l, _)| l.clone()));
        let cols: Vec<String> = labels
            .iter()
            .map(|l| format!("{l} {} ({:.2})", t.count(l), per_1000(t.count(l), t.files)))
            .collect();
        println!(
            "  {cat:<10} {}  known excluded {}",
            cols.join("  "),
            excluded_n.get(cat).copied().unwrap_or(0)
        );
        metrics.insert(
            format!("fp_per_1000.oss.{cat}"),
            round4(per_1000(t.count("flag"), t.files)),
        );
    }
    if !flagged_lines.is_empty() {
        println!("\nOSS flagged files (category, score, path, rule@line):");
        for l in &flagged_lines {
            println!("{l}");
        }
    }
    let stale: Vec<&KnownFinding> = known.difference(&used).collect();
    for k in &stale {
        println!(
            "  note: known finding not seen: {} {}@{}",
            k.path, k.rule, k.line
        );
    }
    metrics.insert("files.oss".into(), files as f64);
    if files < MIN_OSS_FILES {
        return Err(format!(
            "OSS corpus has {files} scanned files; the bar needs at least {MIN_OSS_FILES}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn corpus_meets_the_minimums() {
        assert_eq!(shortfalls(&corpus()), Vec::<String>::new());
    }

    #[test]
    fn corpus_is_deterministic_and_distinct() {
        let (a, b) = (corpus(), corpus());
        assert_eq!(a.len(), b.len());
        assert!(a.iter().zip(&b).all(|(x, y)| x.bytes == y.bytes));
        // Positives of one format differ from each other.
        let mut seen = BTreeSet::new();
        for s in a.iter().filter(|s| s.group != Group::Negative) {
            assert!(seen.insert(&s.bytes), "duplicate {} sample", s.kind);
        }
    }

    #[test]
    fn positive_names_do_not_lean_on_path_rules() {
        let path_rule =
            regex::Regex::new("(?i)(voiceprint|embedding|speaker|enroll|faceprint)").unwrap();
        for s in corpus().iter().filter(|s| s.group != Group::Negative) {
            assert!(
                !path_rule.is_match(&s.name),
                "{} sample is path-named",
                s.kind
            );
        }
    }

    #[test]
    fn default_thresholds() {
        let cfg = Config::default();
        let f = flag_thresholds(&cfg);
        assert_eq!(f[SECRET], 80.0);
        assert_eq!(f[BIOMETRIC], 50.0);
        let t = thresholds(&cfg);
        assert!(t[SECRET].contains(&("claude_code.ask".into(), 80.0)));
        assert!(t[SECRET].contains(&("claude_code.deny".into(), 95.0)));
        assert!(t[SECRET].contains(&("git.block_at".into(), 80.0)));
        assert!(t[BIOMETRIC].contains(&("claude_code.deny".into(), 75.0)));
    }

    #[test]
    fn rate_per_1000() {
        assert_eq!(per_1000(1, 2000), 0.5);
        assert_eq!(per_1000(0, 0), 0.0);
    }

    #[test]
    fn bar() {
        let good = m(&[
            ("recall.provider", 1.0),
            ("recall.generic", 0.9),
            ("recall.biometric", 1.0),
            ("fp_per_1000.synthetic.secret", 0.0),
            ("fp_per_1000.synthetic.biometric", 1.0),
            ("fp_per_1000.oss.secret", 0.9),
            ("fp_per_1000.oss.biometric", 0.0),
        ]);
        assert!(bar_failures(&good, true).is_empty());
        let mut bad = good.clone();
        bad.insert("recall.generic".into(), 0.89);
        bad.insert("recall.biometric".into(), 0.99);
        bad.insert("fp_per_1000.oss.secret".into(), 1.1);
        assert_eq!(bar_failures(&bad, true).len(), 3);
        // OSS metrics are required only when OSS ran.
        let mut no_oss = good.clone();
        no_oss.retain(|k, _| !k.contains(".oss."));
        assert!(bar_failures(&no_oss, false).is_empty());
        assert_eq!(bar_failures(&no_oss, true).len(), 2);
    }

    #[test]
    fn regressions_by_direction() {
        let base = m(&[
            ("recall.generic", 0.9),
            ("fp_per_1000.oss.secret", 0.5),
            ("files.oss", 30000.0),
        ]);
        assert!(regressions(&base, &base).is_empty());
        let better = m(&[
            ("recall.generic", 0.95),
            ("fp_per_1000.oss.secret", 0.1),
            ("files.oss", 1.0),
        ]);
        assert!(regressions(&better, &base).is_empty());
        let worse = m(&[("recall.generic", 0.8), ("fp_per_1000.oss.secret", 0.6)]);
        assert_eq!(regressions(&worse, &base).len(), 2);
    }

    #[test]
    fn baseline_diff_lists_changes() {
        let old = m(&[("a", 1.0), ("b", 2.0), ("gone", 3.0)]);
        let new = m(&[("a", 1.0), ("b", 2.5), ("new", 4.0)]);
        assert_eq!(
            baseline_diff(&old, &new),
            vec!["b: 2 -> 2.5", "new: added 4", "gone: removed (was 3)"]
        );
        assert!(baseline_diff(&old, &old).is_empty());
    }

    #[test]
    fn skipped_oss_keeps_old_oss_metrics() {
        let old = m(&[("fp_per_1000.oss.secret", 0.5), ("recall.generic", 0.9)]);
        let cur = m(&[("recall.generic", 0.95)]);
        let out = merged_baseline(&cur, &old, true);
        assert_eq!(out["fp_per_1000.oss.secret"], 0.5);
        assert_eq!(out["recall.generic"], 0.95);
        assert!(!merged_baseline(&cur, &old, false).contains_key("fp_per_1000.oss.secret"));
    }

    fn target(evidence: Vec<Ev>) -> Target {
        Target {
            target: "src/a.py".into(),
            status: "scanned".into(),
            reason: None,
            scores: BTreeMap::from([(SECRET.into(), 95.0)]),
            evidence,
        }
    }

    #[test]
    fn unscanned_targets_are_listed_with_their_reason() {
        let report: ScanReport = serde_json::from_str(
            r#"{"targets": [
                {"target": "a.txt", "status": "scanned"},
                {"target": "big.txt", "status": "partial"},
                {"target": "x.bin", "status": "skipped", "reason": "binary file of unknown format"},
                {"target": "slow.txt", "status": "unscanned", "reason": "timeout"},
                {"target": "a.tgz", "status": "unscanned", "reason": "gzip not scanned in v1"}
            ]}"#,
        )
        .unwrap();
        let list = unscanned(&report, "repo");
        assert_eq!(
            list,
            vec![
                Unscanned {
                    path: "repo/slow.txt".into(),
                    reason: "timeout".into()
                },
                Unscanned {
                    path: "repo/a.tgz".into(),
                    reason: "gzip not scanned in v1".into()
                }
            ]
        );
        let mut metrics = BTreeMap::new();
        record_unscanned(&list, &mut metrics);
        assert_eq!(metrics["files.oss.unscanned"], 2.0);
        assert_eq!(metrics["files.oss.timed_out"], 1.0);
        assert_eq!(metrics["timed_out.oss.repo/slow.txt"], 1.0);
        assert!(!metrics.contains_key("timed_out.oss.repo/a.tgz"));
        // Informational: neither gated nor compared.
        assert!(regressions(&metrics, &m(&[("files.oss.unscanned", 0.0)])).is_empty());
    }

    #[test]
    fn untracked_files_count_as_local_changes() {
        let d = tempfile::tempdir().unwrap();
        git(d.path(), &["init", "-q"]).unwrap();
        assert!(!has_local_changes(d.path()).unwrap());
        fs::write(d.path().join("planted.txt"), "x").unwrap();
        assert!(has_local_changes(d.path()).unwrap());
    }

    fn tmp_repo() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        git(d.path(), &["init", "-q"]).unwrap();
        d
    }

    fn commit_all(d: &Path) {
        git(d, &["add", "-A"]).unwrap();
        git(
            d,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                "x",
            ],
        )
        .unwrap();
    }

    #[test]
    fn corpus_is_the_tracked_regular_files() {
        let d = tmp_repo();
        let p = d.path();
        fs::write(p.join(".gitignore"), "target/\n").unwrap();
        fs::create_dir_all(p.join("src")).unwrap();
        fs::write(p.join("src/a.txt"), "a").unwrap();
        fs::write(p.join("with space.txt"), "b").unwrap();
        std::os::unix::fs::symlink("src/a.txt", p.join("link.txt")).unwrap();
        commit_all(p);
        fs::create_dir_all(p.join("target")).unwrap();
        fs::write(p.join("target/build.log"), "ignored").unwrap();
        fs::write(p.join("untracked.txt"), "u").unwrap();

        let files = tracked_files(p).unwrap();
        assert_eq!(files, vec![".gitignore", "src/a.txt", "with space.txt"]);
    }

    #[test]
    fn ignored_entries_are_reported_by_top_level_name() {
        let d = tmp_repo();
        let p = d.path();
        fs::write(p.join(".gitignore"), "target/\n").unwrap();
        fs::write(p.join("a.txt"), "a").unwrap();
        commit_all(p);
        assert_eq!(ignored_in_clone(p).unwrap().0, 0);
        fs::create_dir_all(p.join("m/target")).unwrap();
        fs::write(p.join("m/target/x.log"), "x").unwrap();
        fs::create_dir_all(p.join("target")).unwrap();
        fs::write(p.join("target/y.log"), "y").unwrap();
        let (n, tops) = ignored_in_clone(p).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            tops.iter().map(String::as_str).collect::<Vec<_>>(),
            ["m", "target"]
        );
        // Ignored files are a warning, not a local change.
        assert!(!has_local_changes(p).unwrap());
    }

    #[test]
    fn batches_respect_the_byte_budget() {
        let paths: Vec<String> = (0..10).map(|i| format!("file{i}")).collect();
        let b = batches(&paths, 20);
        assert!(b
            .iter()
            .all(|c| c.iter().map(|p| p.len() + 1).sum::<usize>() <= 20));
        assert_eq!(b.iter().map(|c| c.len()).sum::<usize>(), 10);
        assert!(batches(&[], 20).is_empty());
        let long = vec!["x".repeat(50)];
        assert_eq!(batches(&long, 20).len(), 1);
    }

    fn ev(rule: &str, cat: &str, weight: f64, lines: &[u32]) -> Ev {
        Ev {
            rule: rule.into(),
            category: cat.into(),
            weight,
            locations: lines.iter().map(|&l| Loc { line_start: l }).collect(),
        }
    }

    #[test]
    fn known_findings_exclude_only_fully_known_targets() {
        let t = target(vec![
            ev("github_pat", SECRET, 95.0, &[3]),
            ev("generic_api_key", SECRET, 50.0, &[9]),
            ev("path_biometric_name", BIOMETRIC, 30.0, &[]),
        ]);
        assert_eq!(
            t.hits(SECRET),
            vec![("github_pat".into(), 3), ("generic_api_key".into(), 9)]
        );
        assert_eq!(t.hits(BIOMETRIC), vec![("path_biometric_name".into(), 0)]);
        let k = |rule: &str, line| KnownFinding {
            rule: rule.into(),
            path: "r/src/a.py".into(),
            line,
        };
        let one = BTreeSet::from([k("github_pat", 3)]);
        assert!(!excluded(&t, "r", SECRET, &one));
        let both = BTreeSet::from([k("github_pat", 3), k("generic_api_key", 9)]);
        assert!(excluded(&t, "r", SECRET, &both));
        assert!(!excluded(&t, "other", SECRET, &both));
    }

    fn repo_toml(n: usize, langs: usize) -> String {
        (0..n)
            .map(|i| {
                format!(
                    "[[repo]]\nname = \"r{i}\"\nurl = \"https://github.com/o/r{i}\"\n\
                     commit = \"{}\"\nlanguage = \"L{}\"\n",
                    "a".repeat(40),
                    i % langs
                )
            })
            .collect()
    }

    #[test]
    fn repo_list_validation() {
        assert_eq!(parse_repos(&repo_toml(10, 5)).unwrap().len(), 10);
        assert!(parse_repos(&repo_toml(9, 5)).is_err());
        assert!(parse_repos(&repo_toml(10, 4)).is_err());
        let short = repo_toml(10, 5).replacen(&"a".repeat(40), "abc", 1);
        assert!(parse_repos(&short).is_err());
        let dup = repo_toml(10, 5).replace("name = \"r1\"", "name = \"r0\"");
        assert!(parse_repos(&dup).is_err());
        let http = repo_toml(10, 5).replacen("https://github.com", "http://example.com", 1);
        assert!(parse_repos(&http).is_err());
    }

    #[test]
    fn shipped_repo_list_is_valid() {
        let text = std::fs::read_to_string(workspace_root().join("eval/oss-repos.toml")).unwrap();
        parse_repos(&text).unwrap();
    }
}
