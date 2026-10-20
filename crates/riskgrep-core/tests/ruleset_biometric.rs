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
    let mut rules: Vec<&str> = ev.iter().map(|e| e.rule.as_str()).collect();
    rules.sort();
    assert_eq!(rules, ["npy_embedding_tensor", "npy_float_tensor"]);
    for e in &ev {
        assert_eq!(
            e.shape,
            vec![ShapeFacts::Tensor {
                dtype: "<f4".into(),
                shape: vec![10, 192],
                name: None
            }]
        );
    }
    // Both rules are in family `npy`, capped at the embedding weight.
    assert_score(biometric(&f, "a.npy", &data), 70.0);
}

#[test]
fn npy_not_embedding_shaped() {
    let f = fixture();
    // A data table (last dimension 7) and a 3-D volume.
    for shape in [&[500u64, 7][..], &[4, 4, 4, 192]] {
        let data = synth::npy("<f8", shape);
        assert_eq!(
            rules_of(&f, "a.npy", &data),
            ["npy_float_tensor"],
            "{shape:?}"
        );
        assert_score(biometric(&f, "a.npy", &data), 30.0);
    }
}

#[test]
fn npz_not_embedding_shaped() {
    let f = fixture();
    let data = synth::npz(&[("x.npy", synth::npy("<f8", &[500, 7]))]);
    assert_score(biometric(&f, "a.npz", &data), 30.0);
}

#[test]
fn unnamed_embedding_safetensors() {
    let f = fixture();
    let data = synth::safetensors(&[("data", "F32", &[4, 512])]);
    let mut rules = rules_of(&f, "t.safetensors", &data);
    rules.sort();
    assert_eq!(
        rules,
        ["safetensors_embedding_tensor", "safetensors_float_tensor"]
    );
    // 60 and 25 by noisy-or: 1 - 0.4 * 0.75, below the deny threshold.
    assert_score(biometric(&f, "t.safetensors", &data), 70.0);
}

#[test]
fn checkpoint_parameters_are_not_embeddings() {
    let f = fixture();
    // Model parameters with embedding-like names or shapes (timm ViT, BERT,
    // HF ViT, OpenCLIP, diffusers), each alone in a file: only the plain
    // float-tensor rule fires.
    let cases: [(&str, &[u64]); 7] = [
        ("pos_embed", &[1, 197, 768]),
        ("cls_token", &[1, 1, 768]),
        ("bert.embeddings.word_embeddings.weight", &[64, 768]),
        ("vit.embeddings.position_embeddings", &[1, 197, 768]),
        ("positional_embedding", &[77, 512]),
        ("visual.class_embedding", &[768]),
        ("time_embedding.linear_1.weight", &[1280, 320]),
    ];
    for (name, shape) in cases {
        let data = synth::safetensors(&[(name, "F32", shape)]);
        assert_eq!(
            rules_of(&f, "model.safetensors", &data),
            ["safetensors_float_tensor"],
            "{name}"
        );
        assert_score(biometric(&f, "model.safetensors", &data), 25.0);
    }
}

#[test]
fn embedding_names_still_count() {
    let f = fixture();
    for name in [
        "embedding",
        "speaker_embedding",
        "voiceprint",
        "xvector",
        "dvector",
        "spk_emb",
        "face_embedding",
    ] {
        let data = synth::safetensors(&[(name, "F32", &[1, 192])]);
        let rules = rules_of(&f, "t.safetensors", &data);
        assert!(
            rules.contains(&"safetensors_named_embedding".to_string()),
            "{name}"
        );
        assert_score(biometric(&f, "t.safetensors", &data), 85.0);
    }
}

fn bank(keys: &dyn Fn(usize) -> String, n: usize, shape: &[u64]) -> Vec<u8> {
    let names: Vec<String> = (0..n).map(keys).collect();
    let t: Vec<(&str, &str, &[u64])> = names.iter().map(|k| (k.as_str(), "F32", shape)).collect();
    synth::safetensors(&t)
}

#[test]
fn embedding_banks_are_flagged() {
    let f = fixture();
    let vctk = |i: usize| format!("p{}", 225 + i);
    let person = |i: usize| format!("person_{i:03}");
    for (keys, n, shape) in [
        (&vctk as &dyn Fn(usize) -> String, 3usize, &[192u64][..]),
        (&vctk, 5, &[192]),
        (&vctk, 20, &[192]),
        (&vctk, 109, &[192]),
        (&person, 10, &[3, 256]),
    ] {
        let data = bank(keys, n, shape);
        let rules = rules_of(&f, "store.safetensors", &data);
        assert!(
            rules.contains(&"safetensors_embedding_bank".to_string()),
            "{n}"
        );
        // 80 (bank) with the family's 70: 1 - 0.2 * 0.3.
        assert_score(biometric(&f, "store.safetensors", &data), 94.0);
    }
    let members: Vec<(String, Vec<u8>)> = (0..5)
        .map(|i| (format!("p{}.npy", 225 + i), synth::npy("<f4", &[192])))
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = members
        .iter()
        .map(|(a, b)| (a.as_str(), b.clone()))
        .collect();
    let data = synth::npz(&refs);
    assert!(rules_of(&f, "store.npz", &data).contains(&"npz_embedding_bank".to_string()));
    assert_score(biometric(&f, "store.npz", &data), 94.0);
}

#[test]
fn single_unnamed_tensor_and_reduced_openclip() {
    let f = fixture();
    // One unnamed embedding-shaped tensor is not a bank.
    let one = synth::safetensors(&[("p225", "F32", &[192])]);
    assert_score(biometric(&f, "one.safetensors", &one), 70.0);
    // Reduced OpenCLIP checkpoint: projections and embeddings by name.
    let clip = synth::safetensors(&[
        ("positional_embedding", "F32", &[77, 512]),
        ("text_projection", "F32", &[512, 512]),
        ("token_embedding.weight", "F32", &[64, 512]),
        ("visual.class_embedding", "F32", &[768]),
    ]);
    assert_eq!(
        rules_of(&f, "clip.safetensors", &clip),
        ["safetensors_float_tensor"]
    );
    assert_score(biometric(&f, "clip.safetensors", &clip), 25.0);
}

#[test]
fn named_rule_is_token_bounded() {
    let f = fixture();
    for name in ["invoice_total", "surface_normals", "interface.dense"] {
        let data = synth::safetensors(&[(name, "F32", &[1, 192])]);
        let rules = rules_of(&f, "t.safetensors", &data);
        assert!(
            !rules.contains(&"safetensors_named_embedding".to_string()),
            "{name}"
        );
    }
    for name in ["face_embedding", "voice.embedding"] {
        let data = synth::safetensors(&[(name, "F32", &[1, 192])]);
        let rules = rules_of(&f, "t.safetensors", &data);
        assert!(
            rules.contains(&"safetensors_named_embedding".to_string()),
            "{name}"
        );
    }
    // Parameter-like names never count as named embeddings.
    for name in [
        "speaker_encoder.lstm.weight_ih_l0",
        "voice.in_proj",
        "face_embedding.bias_v",
    ] {
        let data = synth::safetensors(&[(name, "F32", &[1, 192])]);
        let rules = rules_of(&f, "t.safetensors", &data);
        assert!(
            !rules.contains(&"safetensors_named_embedding".to_string()),
            "{name}"
        );
    }
}

#[test]
fn layer_parameters_are_not_embeddings() {
    let f = fixture();
    let data = synth::safetensors(&[("fc.weight", "F32", &[10, 512]), ("fc.bias", "F32", &[512])]);
    assert_eq!(
        rules_of(&f, "w.safetensors", &data),
        ["safetensors_float_tensor"]
    );
    assert_score(biometric(&f, "w.safetensors", &data), 25.0);
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
    assert_score(biometric(&f, "w.safetensors", &data), 25.0);
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
        let mut ev = scan(&f, "notes.txt", text.as_bytes());
        ev.sort_by(|a, b| a.rule.cmp(&b.rule));
        let rules: Vec<&str> = ev.iter().map(|e| e.rule.as_str()).collect();
        assert_eq!(
            rules,
            ["printed_embedding_array", "printed_float_run"],
            "{style:?}"
        );
        for e in &ev {
            assert_eq!(e.count, 1, "{style:?}: one location per array or run");
        }
        // Family `printed_floats` caps the pair at 60.
        assert_score(biometric(&f, "notes.txt", text.as_bytes()), 60.0);
    }
}

#[test]
fn printed_run_of_other_length() {
    let f = fixture();
    let text = synth::printed_floats(200, FloatStyle::PythonList);
    assert_eq!(
        rules_of(&f, "notes.txt", text.as_bytes()),
        ["printed_float_run"]
    );
    assert_score(biometric(&f, "notes.txt", text.as_bytes()), 40.0);
}

#[test]
fn path_plus_floats() {
    let f = fixture();
    let text = synth::printed_floats(256, FloatStyle::PythonList);
    // 60 (printed floats) and 30 (path): 1 - 0.4 * 0.7.
    assert_score(
        biometric(&f, "speaker_embedding.txt", text.as_bytes()),
        72.0,
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
