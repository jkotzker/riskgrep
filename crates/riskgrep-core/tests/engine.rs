use riskgrep_core::bundle::compile_uncached;
use riskgrep_core::engine::{Engine, ScanError};
use riskgrep_core::model::{Evidence, ShapeFacts};
use riskgrep_core::ruleset::Ruleset;
use std::fs;

fn engine_with(stopwords: &[(&str, &str)], src: &str) -> Engine {
    try_engine(stopwords, src).unwrap()
}

/// An engine whose post-processors have all been compiled and checked.
fn try_engine(
    stopwords: &[(&str, &str)],
    src: &str,
) -> Result<Engine, riskgrep_core::engine::EngineError> {
    let e = unvalidated(stopwords, src)?;
    e.validate_all()?;
    Ok(e)
}

/// An engine as built for scanning: post-processors compile on first use.
fn unvalidated(
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

/// Deterministic pseudo-random base62 text, generated at run time.
fn random_base62(n: usize, seed: u64) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed.to_le_bytes());
    let mut buf = vec![0u8; n * 8];
    hasher.finalize_xof().fill(&mut buf);
    buf.into_iter()
        .filter(|&b| (b as usize) < 62 * 4)
        .map(|b| A[b as usize % 62])
        .take(n)
        .collect()
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
    assert!(ev[0].locations.is_empty());
    // Location-free evidence carries one digest: the scanned content's.
    assert_eq!(
        ev[0].fingerprints,
        vec![*blake3::hash(b"anything").as_bytes()]
    );
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
    let secret = random_base62(16, 11);
    let mut content = b"key = aaaaaaaaaaaa\nkey = exampleKeyValue9\nkey = ".to_vec();
    let start = content.len() as u64;
    content.extend(&secret);
    content.push(b'\n');
    let ev = scan(&e, "f", &content);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].count, 1);
    let l = &ev[0].locations[0];
    assert_eq!((l.start, l.end), (start, start + 16));
    assert_eq!(l.line_start, 3);
    assert_eq!(ev[0].fingerprints, vec![*blake3::hash(&secret).as_bytes()]);
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
    // The verdict depends on the whole header, so the location's digest is
    // the content's, not the anchor's (which every such file shares).
    assert_eq!(ev[0].fingerprints, vec![*blake3::hash(&c).as_bytes()]);
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

const BAD_REGEX: &str = r#"rule bad { meta: category = "secrets" weight = 1
    post = "allow_regex" allow_regex = "(unclosed"
    strings: $re = /abc/ condition: $re }"#;

#[test]
fn bad_regex_compiles_lazily_and_fails_the_scan() {
    let e = unvalidated(&[], BAD_REGEX).expect("Engine::new compiles no regex");
    let mut sc = yara_x::Scanner::new(e.rules());
    // The rule does not match: its chain is never built.
    assert!(e.scan_content(&mut sc, "f", b"xyz").unwrap().is_empty());
    match e.scan_content(&mut sc, "f", b"abc") {
        Err(ScanError::Yara(msg)) => {
            assert!(msg.contains("t:bad"), "{msg}");
            assert!(msg.contains("allow_regex"), "{msg}");
        }
        other => panic!("expected a yara error, got {other:?}"),
    }
}

#[test]
fn identical_regexes_compile_once() {
    let rule = |n: u32| {
        format!(
            r#"rule r{n} {{ meta: category = "secrets" weight = 1
            post = "span,allow_regex" span_regex = "a(b)c" secret_group = 1
            allow_regex = "^x$" strings: $re = /abc/ condition: $re }}"#
        )
    };
    let e = try_engine(&[], &format!("{}\n{}\n{}", rule(1), rule(2), rule(3))).unwrap();
    assert_eq!(e.compiled_regexes(), 2);
}

#[test]
#[ignore = "timing-dependent; run with --ignored"]
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

const DEDUPE_META: &str = r#"meta: category = "secrets" weight = 1"#;

fn spans(ev: &[Evidence]) -> Vec<(u64, u64)> {
    ev.iter()
        .flat_map(|e| e.locations.iter().map(|l| (l.start, l.end)))
        .collect()
}

#[test]
fn matches_sharing_an_end_keep_the_longest() {
    let e = engine_with(
        &[],
        &format!(
            r#"rule r {{ {DEDUPE_META}
            strings: $re1 = /abcdefgh/ $re2 = /cdefgh/ $re3 = /efgh/
            condition: any of them }}"#
        ),
    );
    let ev = scan(&e, "f", b"xabcdefghx");
    assert_eq!(spans(&ev), vec![(1, 9)]);
    assert_eq!(ev[0].count, 1);
}

#[test]
fn contained_match_is_dropped() {
    let e = engine_with(
        &[],
        &format!(
            r#"rule r {{ {DEDUPE_META}
            strings: $re1 = /abcdefgh/ $re2 = /cdef/
            condition: any of them }}"#
        ),
    );
    let ev = scan(&e, "f", b"xabcdefghx");
    assert_eq!(spans(&ev), vec![(1, 9)]);
}

#[test]
fn partially_overlapping_matches_are_both_kept() {
    let e = engine_with(
        &[],
        &format!(
            r#"rule r {{ {DEDUPE_META}
            strings: $re1 = /abcdef/ $re2 = /defghi/
            condition: any of them }}"#
        ),
    );
    let ev = scan(&e, "f", b"abcdefghi");
    assert_eq!(spans(&ev), vec![(0, 6), (3, 9)]);
    assert_eq!(ev[0].count, 2);
}

#[test]
fn matches_narrowed_to_one_range_count_once() {
    let e = engine_with(
        &[],
        r#"rule r { meta: category = "secrets" weight = 1
            post = "span" span_regex = "(SECRET)" secret_group = 1
            strings: $re1 = /a SECRET/ $re2 = /SECRET b/
            condition: any of them }"#,
    );
    let ev = scan(&e, "f", b"a SECRET b");
    assert_eq!(spans(&ev), vec![(2, 8)]);
    assert_eq!(ev[0].count, 1);
    assert_eq!(ev[0].fingerprints.len(), 1);
}

#[test]
fn zero_length_narrowed_range_is_dropped() {
    let e = engine_with(
        &[],
        r#"rule r { meta: category = "secrets" weight = 1
            post = "span" span_regex = "a(x*)b" secret_group = 1
            strings: $re = /ab/ condition: $re }"#,
    );
    assert!(scan(&e, "f", b"ab").is_empty());
}

#[test]
fn whole_content_header_verdict_applies_to_every_match() {
    let e = engine_with(
        &[],
        r#"rule r { meta: category = "voice" weight = 1
            post = "npy_header" min_dim = 8
            strings: $hdr = "MAGIC"
            condition: $hdr }"#,
    );
    // not an npy file: every MAGIC occurrence is dropped
    assert!(scan(&e, "f", b"MAGIC MAGIC").is_empty());
}
