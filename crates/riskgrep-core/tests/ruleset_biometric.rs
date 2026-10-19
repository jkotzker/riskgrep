//! The shipped `biometric_embeddings` ruleset against synthetic data. Nothing
//! here prints file content or float arrays; assertions use scores and shapes.

use riskgrep_core::bundle::{compile_uncached, Bundle};
use riskgrep_core::engine::Engine;
use riskgrep_core::meta::RuleMeta;
use riskgrep_core::model::{Category, Evidence, ShapeFacts};
use riskgrep_core::ruleset::builtin_rulesets;
use riskgrep_core::score::score_target;
use riskgrep_core::synth::{self, FloatStyle};
use std::collections::{BTreeMap, HashMap};

struct Fixture {
    engine: Engine,
    meta: HashMap<String, RuleMeta>,
}

fn fixture() -> Fixture {
    let all = builtin_rulesets();
    let rs: Vec<_> = all
        .iter()
        .filter(|r| r.id == "biometric_embeddings")
        .collect();
    assert_eq!(rs.len(), 1, "ruleset biometric_embeddings is embedded");
    let bundle: Bundle = compile_uncached(&rs).unwrap();
    let meta = bundle.meta.clone();
    Fixture {
        engine: Engine::new(bundle).unwrap(),
        meta,
    }
}

fn scan(f: &Fixture, path: &str, content: &[u8]) -> Vec<Evidence> {
    let mut sc = yara_x::Scanner::new(f.engine.rules());
    f.engine.scan_content(&mut sc, path, content).unwrap()
}

fn score_of(evidence: &[Evidence], f: &Fixture) -> BTreeMap<Category, f64> {
    score_target(evidence, &f.meta)
}

fn biometric(f: &Fixture, path: &str, content: &[u8]) -> Option<f64> {
    let ev = scan(f, path, content);
    score_of(&ev, f).get(&Category("biometric".into())).copied()
}

fn assert_score(got: Option<f64>, want: f64) {
    let got = got.expect("biometric score present");
    assert!((got - want).abs() < 1e-9, "score {got}, want {want}");
}

fn rules_of(f: &Fixture, path: &str, content: &[u8]) -> Vec<String> {
    scan(f, path, content).into_iter().map(|e| e.rule).collect()
}

#[test]
fn named_safetensors() {
    let f = fixture();
    let data = synth::safetensors(&[
        ("speaker_embedding", "F32", &[1, 192]),
        ("other", "F32", &[1, 128]),
    ]);
    let rules = rules_of(&f, "model.safetensors", &data);
    assert!(rules.contains(&"safetensors_named_embedding".to_string()));
    assert!(rules.contains(&"safetensors_float_tensor".to_string()));
    assert_score(biometric(&f, "model.safetensors", &data), 85.0);
}

#[test]
fn npy_f32_10x192() {
    let f = fixture();
    let data = synth::npy("<f4", &[10, 192]);
    let ev = scan(&f, "a.npy", &data);
    assert_eq!(ev.len(), 1);
    assert_eq!(
        ev[0].shape,
        vec![ShapeFacts::Tensor {
            dtype: "<f4".into(),
            shape: vec![10, 192],
            name: None
        }]
    );
    assert_score(biometric(&f, "a.npy", &data), 70.0);
}

#[test]
fn npz_float_member() {
    let f = fixture();
    let data = synth::npz(&[("emb.npy", synth::npy("<f4", &[4, 256]))]);
    assert_score(biometric(&f, "a.npz", &data), 70.0);
}

#[test]
fn int_npy() {
    let f = fixture();
    let data = synth::npy("<i8", &[10, 192]);
    assert!(scan(&f, "a.npy", &data).is_empty());
    assert_eq!(biometric(&f, "a.npy", &data), None);
}

#[test]
fn model_weights_safetensors() {
    let f = fixture();
    let data = synth::safetensors(&[("layer.0.weight", "F32", &[768, 768])]);
    assert_score(biometric(&f, "w.safetensors", &data), 30.0);
}

#[test]
fn printed_embedding_styles() {
    let f = fixture();
    for style in [
        FloatStyle::PythonList,
        FloatStyle::NumpyRepr,
        FloatStyle::JsonArray,
    ] {
        let text = synth::printed_floats(256, style);
        let ev = scan(&f, "notes.txt", text.as_bytes());
        assert_eq!(ev.len(), 1, "{style:?}");
        assert_eq!(ev[0].rule, "printed_float_run");
        assert_eq!(ev[0].count, 1, "{style:?}: one location per run");
        assert_score(biometric(&f, "notes.txt", text.as_bytes()), 40.0);
    }
}

#[test]
fn path_plus_floats() {
    let f = fixture();
    let text = synth::printed_floats(256, FloatStyle::PythonList);
    assert_score(
        biometric(&f, "speaker_embedding.txt", text.as_bytes()),
        58.0,
    );
}

#[test]
fn path_alone() {
    let f = fixture();
    assert_score(biometric(&f, "VoicePrint/notes.txt", b"hello"), 30.0);
}

#[test]
fn sensor_csv_100x10() {
    let f = fixture();
    let text = synth::csv_rows(100, 10);
    assert_score(biometric(&f, "sensor.csv", text.as_bytes()), 40.0);
}

#[test]
fn hard_negatives() {
    let f = fixture();
    let prices: String = (0..300)
        .map(|i| format!("item{i},{}.99,{}\n", i % 90 + 1, i % 7 + 1))
        .collect();
    let logs: String = (0..300)
        .map(|i| format!("2026-10-19 12:00:{:02} latency=0.{:03} ok\n", i % 60, i))
        .collect();
    let small = format!(
        "{{\"v\": {}}}",
        synth::printed_floats(5, FloatStyle::PythonList)
    );
    for (path, text) in [
        ("prices.csv", prices),
        ("app.log", logs),
        ("small.json", small),
    ] {
        assert!(scan(&f, path, text.as_bytes()).is_empty(), "{path}");
        assert_eq!(biometric(&f, path, text.as_bytes()), None, "{path}");
    }
}

#[test]
fn synth_is_deterministic() {
    assert_eq!(synth::npy("<f4", &[3, 64]), synth::npy("<f4", &[3, 64]));
    assert_eq!(
        synth::printed_floats(70, FloatStyle::NumpyRepr),
        synth::printed_floats(70, FloatStyle::NumpyRepr)
    );
}

fn timed_scan(f: &Fixture, bytes: usize) -> (std::time::Duration, u32) {
    // Dense CSV of 10 floats per row, trimmed to about `bytes` bytes.
    let rows = bytes / 60 + 1;
    let text = synth::csv_rows(rows, 10);
    let t = text.as_bytes();
    let t = &t[..t.len().min(bytes)];
    let start = std::time::Instant::now();
    let ev = scan(f, "data.csv", t);
    let elapsed = start.elapsed();
    assert_eq!(ev.len(), 1);
    (elapsed, ev[0].count)
}

#[test]
fn dense_float_scan_is_fast() {
    let f = fixture();
    for bytes in [256 << 10, 1 << 20] {
        let (d, count) = timed_scan(&f, bytes);
        eprintln!("debug {bytes} bytes: {d:?}");
        assert_eq!(count, 1, "one run");
        // Debug builds are several times slower than release; 1 s covers 1 MiB.
        assert!(d.as_secs_f64() < 1.0, "{bytes} bytes took {d:?}");
    }
}

#[test]
#[ignore = "release timing; run with --release -- --ignored"]
fn dense_float_scan_8mib_release() {
    let f = fixture();
    let (d, _) = timed_scan(&f, 8 << 20);
    eprintln!("release 8 MiB: {d:?}");
    assert!(d.as_millis() < 250, "took {d:?}");
}

#[test]
fn pathological_digit_text_is_fast_and_negative() {
    let f = fixture();
    for text in [
        "1".repeat(1 << 20),
        "1.".repeat(1 << 19),
        "-".repeat(1 << 20),
    ] {
        let start = std::time::Instant::now();
        assert!(scan(&f, "x.txt", text.as_bytes()).is_empty());
        assert!(start.elapsed().as_secs_f64() < 1.0);
    }
}
