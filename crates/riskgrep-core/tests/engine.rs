use riskgrep_core::bundle::compile_uncached;
use riskgrep_core::engine::{Engine, ScanError};
use riskgrep_core::model::{Evidence, ShapeFacts};
use riskgrep_core::ruleset::Ruleset;
use std::fs;

fn engine_with(stopwords: &[(&str, &str)], src: &str) -> Engine {
    try_engine(stopwords, src).unwrap()
}

fn try_engine(
    stopwords: &[(&str, &str)],
    src: &str,
) -> Result<Engine, riskgrep_core::engine::EngineError> {
    let d = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("ruleset.toml"),
        "id = \"t\"\nversion = \"1\"\nlicence = \"MIT\"\ndescription = \"t\"\ncategories = [\"secrets\"]\n",
    )
    .unwrap();
    fs::write(d.path().join("a.yar"), src).unwrap();
    fs::create_dir_all(d.path().join("stopwords")).unwrap();
    for (name, body) in stopwords {
        fs::write(d.path().join(format!("stopwords/{name}.txt")), body).unwrap();
    }
    let rs = Ruleset::load_dir(d.path()).unwrap();
    Engine::new(compile_uncached(&[&rs]).unwrap())
}

fn scan(e: &Engine, path: &str, content: &[u8]) -> Vec<Evidence> {
    let mut sc = yara_x::Scanner::new(e.rules());
    e.scan_content(&mut sc, path, content).unwrap()
}

#[test]
fn overlapping_matches_deduped() {
    let e = engine_with(
        &[],
        r#"rule tok { meta: category = "secrets" weight = 50
            strings: $re = /tok_[a-z]{4,}/ condition: $re }"#,
    );
    let ev = scan(&e, "f", b"tok_abcdefgh");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].count, 1);
    assert_eq!(ev[0].rule, "tok");
    assert_eq!(ev[0].weight, 50.0);
    assert_eq!(ev[0].category.0, "secrets");
    assert_eq!(ev[0].locations[0].start, 0);
    assert_eq!(ev[0].locations[0].end, 12);
}

#[test]
fn locations_and_lines() {
    let e = engine_with(
        &[],
        r#"rule tok { meta: category = "secrets" weight = 50
            strings: $re = /tok_[a-z]{4,}/ condition: $re }"#,
    );
    let content = b"one\ntwo\nxx tok_abcdefgh yy\nfour\n";
    let ev = scan(&e, "f", content);
    let loc = &ev[0].locations[0];
    assert_eq!(loc.line_start, 3);
    assert_eq!(loc.line_end, 3);
    assert_eq!(loc.start, 11);
    assert_eq!(
        ev[0].fingerprints,
        vec![*blake3::hash(b"tok_abcdefgh").as_bytes()]
    );
}

#[test]
fn condition_only_rule_counts_once() {
    let e = engine_with(
        &[],
        r#"rule vp { meta: category = "voice" weight = 30
            condition: path matches /voiceprint/ }"#,
    );
    let ev = scan(&e, "dir/speaker.voiceprint.bin", b"anything");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].count, 1);
    assert!(ev[0].locations.is_empty() && ev[0].fingerprints.is_empty());
    assert!(scan(&e, "dir/other.bin", b"anything").is_empty());
}

#[test]
fn helper_patterns_are_not_evidence() {
    let e = engine_with(
        &[],
        r#"rule kw { meta: category = "secrets" weight = 10
            strings: $kw = "password" $re = /[a-z]{3}_[0-9]{4}/
            condition: $kw and $re }"#,
    );
    let ev = scan(&e, "f", b"password abc_1234");
    assert_eq!(ev[0].count, 1);
    assert_eq!(ev[0].locations[0].end - ev[0].locations[0].start, 8);
    // helper alone: no anchor match survives, so no evidence
    let e2 = engine_with(
        &[],
        r#"rule kw { meta: category = "secrets" weight = 10
            strings: $kw = "password" $re = /[a-z]{3}_[0-9]{4}/
            condition: any of them }"#,
    );
    assert!(scan(&e2, "f", b"password only").is_empty());
}

#[test]
fn post_chain_span_stopwords_entropy() {
    let e = engine_with(
        &[("common", "example\n")],
        r#"rule kv { meta: category = "secrets" weight = 40
            post = "span,stopwords,entropy" span_regex = "= ([A-Za-z0-9]+)" secret_group = 1
            stopwords = "common" min_entropy = 2.5
            strings: $re = /key = [A-Za-z0-9]{8,}/ condition: $re }"#,
    );
    let content = b"key = aaaaaaaaaaaa\nkey = exampleKeyValue9\nkey = q7Zk2PxW9mLd\n";
    let ev = scan(&e, "f", content);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].count, 1);
    let l = &ev[0].locations[0];
    assert_eq!(&content[l.start as usize..l.end as usize], b"q7Zk2PxW9mLd");
    assert_eq!(l.line_start, 3);
}

#[test]
fn tensor_header_rule_emits_shape() {
    let e = engine_with(
        &[],
        r#"rule st { meta: category = "voice" weight = 60
            post = "safetensors_header" min_dim = 192 name_regex = "embedding"
            strings: $hdr = { 02 00 00 00 00 00 00 00 }
            condition: $hdr at 0 }"#,
    );
    // header length 2 -> "{}" is valid json but has no tensors
    let mut c = 2u64.to_le_bytes().to_vec();
    c.extend(b"{}");
    assert!(scan(&e, "f", &c).is_empty());

    let json = r#"{"speaker_embedding":{"dtype":"F32","shape":[1,256],"data_offsets":[0,1024]}}"#;
    let mut c = (json.len() as u64).to_le_bytes().to_vec();
    c.extend(json.as_bytes());
    let e = engine_with(
        &[],
        &format!(
            r#"rule st {{ meta: category = "voice" weight = 60
            post = "safetensors_header" min_dim = 192 name_regex = "embedding"
            strings: $hdr = {{ {} 00 00 00 00 00 00 }}
            condition: $hdr at 0 }}"#,
            format_args!("{:02x} 00", json.len())
        ),
    );
    let ev = scan(&e, "f", &c);
    assert_eq!(ev[0].count, 1);
    assert_eq!(
        ev[0].shape,
        vec![ShapeFacts::Tensor {
            dtype: "F32".into(),
            shape: vec![1, 256],
            name: Some("speaker_embedding".into())
        }]
    );
}

#[test]
fn bad_regex_names_rule_and_key() {
    let err = try_engine(
        &[],
        r#"rule bad { meta: category = "secrets" weight = 1
            post = "allow_regex" allow_regex = "(unclosed"
            strings: $re = /abc/ condition: $re }"#,
    )
    .err()
    .unwrap();
    let msg = err.to_string();
    assert!(msg.contains("t:bad"), "{msg}");
    assert!(msg.contains("allow_regex"), "{msg}");
}

#[test]
fn timeout_maps_to_scan_error() {
    let e = engine_with(
        &[],
        r#"rule slow { meta: category = "secrets" weight = 1
            strings: $re = /a.*b.*c/ condition: $re }"#,
    );
    let mut sc = yara_x::Scanner::new(e.rules());
    sc.set_timeout(std::time::Duration::from_nanos(1));
    let big = vec![b'a'; 4_000_000];
    match e.scan_content(&mut sc, "f", &big) {
        Err(ScanError::Timeout) => {}
        Ok(_) => panic!("expected timeout"),
        Err(other) => panic!("unexpected {other}"),
    }
}

#[test]
fn bundle_hash_exposed() {
    let e = engine_with(
        &[],
        r#"rule r { meta: category = "secrets" weight = 1 strings: $re = /a/ condition: $re }"#,
    );
    assert_eq!(e.bundle_hash().len(), 64);
}
