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

type Tensor = (String, &'static str, Vec<u64>);

fn t(name: &str, dtype: &'static str, shape: &[u64]) -> Tensor {
    (name.to_string(), dtype, shape.to_vec())
}

fn st_header(tensors: &[Tensor]) -> Vec<u8> {
    let refs: Vec<(&str, &str, &[u64])> = tensors
        .iter()
        .map(|(n, d, s)| (n.as_str(), *d, &s[..]))
        .collect();
    synth::safetensors_header(&refs)
}

fn npz_headers(members: &[Tensor]) -> Vec<u8> {
    let m: Vec<(String, Vec<u8>)> = members
        .iter()
        .map(|(n, d, s)| (format!("{n}.npy"), synth::npy_header(d, s)))
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = m.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
    synth::npz(&refs)
}

#[test]
fn identity_names_containing_parameter_words() {
    // `tobias` contains `bias`, `patchett` `patch`, `abiasi` `bias`: the
    // parameter words count only as whole tokens.
    let f = fixture();
    let named = st_header(&[t("tobias_embedding", "F32", &[192])]);
    assert_score(biometric(&f, "t.safetensors", &named), 85.0);
    let names = ["tobias", "patchett", "abiasi", "dave"];
    let bank: Vec<Tensor> = names.iter().map(|n| t(n, "F32", &[192])).collect();
    assert_score(biometric(&f, "s.safetensors", &st_header(&bank)), 94.0);
    let bank: Vec<Tensor> = names.iter().map(|n| t(n, "<f4", &[192])).collect();
    assert_score(biometric(&f, "s.npz", &npz_headers(&bank)), 94.0);
    // One flat identity vector: the unnamed single-tensor rules.
    let one = st_header(&[t("tobias", "F32", &[192])]);
    assert_score(biometric(&f, "o.safetensors", &one), 70.0);
    let one = npz_headers(&[t("patchett", "<f4", &[192])]);
    assert_score(biometric(&f, "o.npz", &one), 70.0);
}

#[test]
fn parameter_words_as_tokens_still_do_not_count() {
    let f = fixture();
    for name in [
        "weight",
        "fc.weight",
        "conv.weight_g",
        "bias",
        "attn.qkv_bias",
        "encoder.bias_ih",
        "cls_token",
        "mask_token",
        "register_tokens",
        "token_embedding",
        "patch_embed",
        "patches",
        "transformer.wte",
        "transformer.wpe",
        "lm_head",
        "lm_head.weight",
        "dense/bias:0",
    ] {
        for (file, data) in [
            ("m.safetensors", st_header(&[t(name, "F32", &[1, 768])])),
            ("m.npz", npz_headers(&[t(name, "<f4", &[1, 768])])),
        ] {
            let score = biometric(&f, file, &data).unwrap_or(0.0);
            assert!(score < 50.0, "{name} in {file}: {score}");
        }
    }
}

#[test]
fn foreign_checkpoint_layouts_stay_below_ask() {
    let f = fixture();
    // Mamba: `backbone.layers.N.mixer.D` [1536] in every layer.
    let mut mamba = vec![t("backbone.embedding.weight", "F32", &[64, 768])];
    for l in 0..24 {
        let p = format!("backbone.layers.{l}");
        mamba.push(t(&format!("{p}.mixer.D"), "F32", &[1536]));
        mamba.push(t(&format!("{p}.mixer.A_log"), "F32", &[1536, 16]));
        mamba.push(t(&format!("{p}.mixer.conv1d.bias"), "F32", &[1536]));
        mamba.push(t(&format!("{p}.norm.weight"), "F32", &[768]));
    }
    // RWKV-4: per-block `time_mix_*` [1,1,768], `time_decay`/`time_first` [768].
    let mut rwkv = vec![t("emb.weight", "F32", &[64, 768])];
    for l in 0..12 {
        let p = format!("blocks.{l}");
        for k in [
            "att.time_mix_k",
            "att.time_mix_v",
            "att.time_mix_r",
            "ffn.time_mix_k",
        ] {
            rwkv.push(t(&format!("{p}.{k}"), "F32", &[1, 1, 768]));
        }
        rwkv.push(t(&format!("{p}.att.time_decay"), "F32", &[768]));
        rwkv.push(t(&format!("{p}.att.time_first"), "F32", &[768]));
    }
    // Flax and TF BERT: `kernel`, `scale`, `gamma`, `beta`.
    let mut flax = vec![t("bert.embeddings.LayerNorm.scale", "F32", &[768])];
    let mut tf = vec![
        t("bert/embeddings/LayerNorm/gamma", "F32", &[768]),
        t("bert/embeddings/LayerNorm/beta", "F32", &[768]),
    ];
    for l in 0..2 {
        for q in ["query", "key", "value"] {
            flax.push(t(
                &format!("bert.encoder.layer.{l}.attention.self.{q}.kernel"),
                "F32",
                &[768, 768],
            ));
            tf.push(t(
                &format!("bert/encoder/layer_{l}/attention/self/{q}/kernel"),
                "F32",
                &[768, 768],
            ));
        }
        flax.push(t(
            &format!("bert.encoder.layer.{l}.output.LayerNorm.scale"),
            "F32",
            &[768],
        ));
        tf.push(t(
            &format!("bert/encoder/layer_{l}/output/LayerNorm/gamma"),
            "F32",
            &[768],
        ));
        tf.push(t(
            &format!("bert/encoder/layer_{l}/output/LayerNorm/beta"),
            "F32",
            &[768],
        ));
    }
    flax.push(t("LayerNorm_0.scale", "F32", &[768]));
    flax.push(t("Dense_0.kernel", "F32", &[768, 768]));
    for (name, layout) in [
        ("mamba", mamba),
        ("rwkv4", rwkv),
        ("flax", flax),
        ("tf", tf),
    ] {
        let data = st_header(&layout);
        let score = biometric(&f, "model.safetensors", &data).unwrap_or(0.0);
        assert!(score < 50.0, "{name}: {score}");
    }
    // Google ViT `.npz` (JAX names) and scipy-style reference vectors.
    let mut vit = vec![
        t("cls", "<f4", &[1, 1, 768]),
        t("embedding/bias", "<f4", &[768]),
        t("pre_logits/kernel", "<f4", &[768, 768]),
        t("Transformer/encoder_norm/scale", "<f4", &[768]),
    ];
    for b in 0..2 {
        let p = format!("Transformer/encoderblock_{b}");
        vit.push(t(&format!("{p}/LayerNorm_0/scale"), "<f4", &[768]));
        vit.push(t(&format!("{p}/LayerNorm_0/bias"), "<f4", &[768]));
        vit.push(t(&format!("{p}/MlpBlock_3/Dense_1/bias"), "<f4", &[768]));
    }
    let mut refs = vec![t("sizes", "<i8", &[14])];
    for kind in ["dct", "dst"] {
        for k in 1..=4 {
            for n in [16u64, 64, 128, 256, 512, 1024] {
                refs.push(t(&format!("{kind}_{k}_{n}"), "<f8", &[n]));
            }
        }
    }
    for (name, layout) in [("vit", vit), ("scipy", refs)] {
        let data = npz_headers(&layout);
        let score = biometric(&f, "ref.npz", &data).unwrap_or(0.0);
        assert!(score < 50.0, "{name}: {score}");
    }
}

#[test]
fn banks_need_flat_keys_and_a_majority() {
    let f = fixture();
    let flagged = |data: &[u8], file: &str| {
        let rules = rules_of(&f, file, data);
        rules
            .iter()
            .any(|r| r == "safetensors_embedding_bank" || r == "npz_embedding_bank")
    };
    let flat: [&dyn Fn(usize) -> String; 10] = [
        &|i| format!("speakers/p{}", 225 + i),
        &|i| format!("faces.{i}"),
        &|i| format!("p{}", 225 + i),
        &|i| format!("person_{i:03}"),
        &|i| format!("spk_{i}"),
        // Contains `beta`, but not as a token.
        &|i| format!("Betancourt_{i}"),
        // Identity keys with an underscore-delimited number.
        &|i| format!("spk_{i}_emb"),
        &|i| format!("speaker_{i}_vec"),
        &|i| format!("19_198_{i:04}"),
        &|i| format!("h_lee_{i}"),
    ];
    for keys in flat {
        let names: Vec<Tensor> = (0..5).map(|i| t(&keys(i), "F32", &[192])).collect();
        let data = st_header(&names);
        assert!(flagged(&data, "s.safetensors"), "{}", keys(0));
        // At least the deny threshold: 94 with the single-tensor rule, 85
        // for underscore-indexed keys (the single-tensor rule ignores them),
        // 97 when the key is also an embedding name.
        let score = biometric(&f, "s.safetensors", &data).unwrap_or(0.0);
        assert!(score >= 75.0, "{}: {score}", keys(0));
        let npz: Vec<Tensor> = (0..5).map(|i| t(&keys(i), "<f4", &[192])).collect();
        let data = npz_headers(&npz);
        assert!(flagged(&data, "s.npz"), "{} (npz)", keys(0));
        let score = biometric(&f, "s.npz", &data).unwrap_or(0.0);
        assert!(score >= 75.0, "{} (npz): {score}", keys(0));
    }
    let layered: [&dyn Fn(usize) -> String; 4] = [
        &|i| format!("encoder.layer.{i}.out"),
        &|i| format!("model.v{i}"),
        &|i| format!("blocks_{i}_x"),
        &|i| format!("item.{i}.vec"),
    ];
    for keys in layered {
        let names: Vec<Tensor> = (0..5).map(|i| t(&keys(i), "F32", &[192])).collect();
        assert!(!flagged(&st_header(&names), "s.safetensors"), "{}", keys(0));
    }
    // Five identity vectors among six other float tensors: under half.
    let mut mixed: Vec<Tensor> = (0..5)
        .map(|i| t(&format!("p{}", 225 + i), "F32", &[192]))
        .collect();
    for i in 0..6 {
        mixed.push(t(&format!("aux{i}"), "F32", &[7]));
    }
    assert!(!flagged(&st_header(&mixed), "s.safetensors"));
    // A flat MLP: 4 biases [256] are exactly half of 8 float tensors, and 3
    // weights [256, 256] less than half. Neither is a bank.
    let mut mlp = vec![t("W1", "F32", &[784, 256]), t("b1", "F32", &[256])];
    for l in 2..=4 {
        mlp.push(t(&format!("W{l}"), "F32", &[256, 256]));
        mlp.push(t(&format!("b{l}"), "F32", &[256]));
    }
    assert!(!flagged(&st_header(&mlp), "m.safetensors"));
    let npz: Vec<Tensor> = mlp.iter().map(|(n, _, s)| t(n, "<f4", s)).collect();
    assert!(!flagged(&npz_headers(&npz), "m.npz"));
}

#[test]
fn flat_mlp_scores_below_deny() {
    // 4 weights and 4 biases at hidden width 256: a documented false
    // positive that must stay at ask (70), never reach the git block (75).
    let f = fixture();
    let mut mlp = vec![t("W1", "F32", &[784, 256]), t("b1", "F32", &[256])];
    for l in 2..=4 {
        mlp.push(t(&format!("W{l}"), "F32", &[256, 256]));
        mlp.push(t(&format!("b{l}"), "F32", &[256]));
    }
    let st = biometric(&f, "m.safetensors", &st_header(&mlp)).unwrap_or(0.0);
    assert!(st < 75.0, "safetensors MLP scored {st}");
    let npz: Vec<Tensor> = mlp.iter().map(|(n, _, s)| t(n, "<f4", s)).collect();
    let nz = biometric(&f, "m.npz", &npz_headers(&npz)).unwrap_or(0.0);
    assert!(nz < 75.0, "npz MLP scored {nz}");
}

#[test]
fn underscore_numbered_checkpoint_is_a_known_false_positive() {
    // A GPT-2 style checkpoint with flat, underscore-numbered names
    // (`h0_ln_1_g`) is not excluded by the bank rules: `_N_` is an identity
    // index there. Documented in docs/known-limitations.md; if this starts
    // scoring lower, update that entry.
    let f = fixture();
    let names = ["h0_ln_1_g", "h0_ln_1_b", "h0_ln_2_g", "h0_ln_2_b"];
    let members: Vec<Tensor> = names.iter().map(|n| t(n, "<f4", &[768])).collect();
    let score = biometric(&f, "gpt2.npz", &npz_headers(&members)).unwrap_or(0.0);
    assert!((score - 86.0).abs() < 1e-6, "scored {score}");
    // The same names in a safetensors file: the bank (80) with the float
    // tensor rule (25).
    let st = synth::safetensors(&[
        ("h0_ln_1_g", "F32", &[768]),
        ("h0_ln_1_b", "F32", &[768]),
        ("h0_ln_2_g", "F32", &[768]),
        ("h0_ln_2_b", "F32", &[768]),
    ]);
    let score = biometric(&f, "gpt2.safetensors", &st).unwrap_or(0.0);
    assert!((score - 85.0).abs() < 1e-6, "scored {score}");
}

#[test]
fn embedding_name_with_parameter_suffix_is_not_named() {
    // Documented in docs/known-limitations.md: the parameter exclusion wins
    // over the embedding word, so the by-name rule (85) does not fire.
    let f = fixture();
    let data = synth::safetensors(&[("speaker_embedding.weight", "F32", &[1, 192])]);
    let rules = rules_of(&f, "m.safetensors", &data);
    assert!(
        !rules.iter().any(|r| r == "safetensors_named_embedding"),
        "{rules:?}"
    );
    let score = biometric(&f, "m.safetensors", &data).unwrap_or(0.0);
    assert!((score - 25.0).abs() < 1e-6, "scored {score}");
}

#[test]
fn named_rule_ignores_jax_tf_and_rnn_parameters() {
    let f = fixture();
    for name in [
        "bert/embeddings/LayerNorm/gamma",
        "bert/embeddings/LayerNorm/beta",
        "bert.embeddings.LayerNorm.scale",
        "speaker_encoder.kernel",
        "face_embedding.moving_mean",
        "voice.time_decay",
    ] {
        let data = st_header(&[t(name, "F32", &[768])]);
        let rules = rules_of(&f, "t.safetensors", &data);
        assert!(
            !rules.contains(&"safetensors_named_embedding".to_string()),
            "{name}"
        );
    }
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
