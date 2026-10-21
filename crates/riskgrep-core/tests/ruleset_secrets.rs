//! The shipped `secrets_core` ruleset against secrets generated at run time.
//! Nothing here prints a generated value; assertions use rule ids, scores,
//! counts, and offsets.

use regex::bytes::{Regex, RegexBuilder};
use riskgrep_core::bundle::{compile_uncached, Bundle};
use riskgrep_core::engine::Engine;
use riskgrep_core::meta::RuleMeta;
use riskgrep_core::model::{Category, Evidence};
use riskgrep_core::ruleset::{builtin_rulesets, Ruleset};
use riskgrep_core::score::{score, Contribution};
use riskgrep_core::synth;
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

const NS: &str = "secrets_core";

struct Fixture {
    engine: Engine,
    meta: HashMap<String, RuleMeta>,
}

fn secrets_ruleset() -> Ruleset {
    let mut v: Vec<Ruleset> = builtin_rulesets()
        .into_iter()
        .filter(|r| r.id == NS)
        .collect();
    assert_eq!(v.len(), 1, "ruleset {NS} is embedded");
    v.remove(0)
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let rs = secrets_ruleset();
        let bundle: Bundle = compile_uncached(&[&rs]).unwrap();
        let meta = bundle.meta.clone();
        let engine = Engine::new(bundle).unwrap();
        engine.validate_all().unwrap();
        Fixture { engine, meta }
    })
}

fn scan(path: &str, content: &[u8]) -> Vec<Evidence> {
    let f = fixture();
    let mut sc = yara_x::Scanner::new(f.engine.rules());
    f.engine.scan_content(&mut sc, path, content).unwrap()
}

fn secret_score(evidence: &[Evidence]) -> Option<f64> {
    let f = fixture();
    let contribs: Vec<Contribution> = evidence
        .iter()
        .map(|e| {
            let m = &f.meta[&format!("{NS}:{}", e.rule)];
            Contribution {
                rule: e.rule.clone(),
                category: e.category.clone(),
                weight: e.weight,
                count: e.count,
                tiers: m.tiers.clone(),
                family: m.family.clone(),
                family_cap: m.family_cap,
            }
        })
        .collect();
    score(&contribs).get(&Category("secret".into())).copied()
}

fn rule_ids(evidence: &[Evidence]) -> Vec<&str> {
    evidence.iter().map(|e| e.rule.as_str()).collect()
}

/// Source-like text with `line` in the middle; returns the content and the
/// byte offset at which `line` starts.
fn embed(line: &str) -> (Vec<u8>, usize) {
    let head = "fn main() {\n    let width = 80;\n    // configuration follows\n";
    let tail = "\n    println!(\"{}\", width);\n}\n";
    let mut out = head.as_bytes().to_vec();
    let at = out.len();
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(tail.as_bytes());
    (out, at)
}

/// Asserts the evidence for `rule` has exactly one location: `range`.
fn assert_span(evidence: &[Evidence], rule: &str, range: std::ops::Range<usize>) {
    let e = evidence
        .iter()
        .find(|e| e.rule == rule)
        .unwrap_or_else(|| panic!("no evidence for {rule}; got {:?}", rule_ids(evidence)));
    assert_eq!(e.count, 1, "{rule}: count");
    let l = &e.locations[0];
    assert_eq!(
        (l.start as usize, l.end as usize),
        (range.start, range.end),
        "{rule}: span"
    );
}

fn assert_score(evidence: &[Evidence], want: f64) {
    let got = secret_score(evidence).unwrap_or_else(|| {
        panic!("no secret score; rules {:?}", rule_ids(evidence));
    });
    assert!(
        (got - want).abs() < 1e-9,
        "score {got}, want {want}; rules {:?}",
        rule_ids(evidence)
    );
}

/// A token embedded as `let id = "<token>";`, which names no secret keyword.
fn token_case(kind: &str, rule: &str, want: f64) {
    let s = synth::fake_secret(kind, 7);
    let prefix = "    let id = \"";
    let (content, at) = embed(&format!("{prefix}{s}\";"));
    let start = at + prefix.len();
    let ev = scan("src/main.rs", &content);
    assert_span(&ev, rule, start..start + s.len());
    assert_score(&ev, want);
}

#[test]
fn aws_access_key() {
    token_case("aws_access_key", "aws_access_token", 95.0);
}

#[test]
fn github_pat() {
    token_case("github_pat", "github_pat", 95.0);
}

#[test]
fn anthropic_key() {
    token_case("anthropic_key", "anthropic_api_key", 95.0);
}

#[test]
fn pem_private_key() {
    let s = synth::fake_secret("pem_private_key", 7);
    let mut content = b"# deploy key\n".to_vec();
    let at = content.len();
    content.extend_from_slice(s.as_bytes());
    content.extend_from_slice(b"\n");
    let ev = scan("deploy/id_rsa", &content);
    assert_span(&ev, "private_key", at..at + s.len());
    assert_score(&ev, 95.0);
}

#[test]
fn generic_api_key_assignment() {
    let line = synth::fake_secret("generic_api_key_assignment", 7);
    let (content, at) = embed(&line);
    let open = line.find('"').unwrap() + 1;
    let close = line.rfind('"').unwrap();
    let ev = scan("settings.py", &content);
    assert_span(&ev, "generic_api_key", at + open..at + close);
    assert_score(&ev, 80.0);
}

#[test]
fn generic_needs_a_credential_named_key() {
    // Local change (UPSTREAM.md): containing a keyword is not enough.
    let value = &synth::fake_secret("github_pat", 9)[4..];
    for name in ["key_sha256", "tokenizer_name", "first_key", "public_key"] {
        let (content, _) = embed(&format!("    {name} = \"{value}\""));
        let ev = scan("settings.py", &content);
        assert!(ev.is_empty(), "{name}: rules {:?}", rule_ids(&ev));
    }
    for name in [
        "api_key",
        "client_secret",
        "db_password",
        "authToken",
        "SECRET_KEY",
        "STRIPE_KEY",
        "HMAC_KEY",
    ] {
        let (content, _) = embed(&format!("    {name} = \"{value}\""));
        let ev = scan("settings.py", &content);
        assert_eq!(rule_ids(&ev), ["generic_api_key"], "{name}");
    }
}

#[test]
fn low_entropy_generic() {
    let (content, _) = embed(&synth::fake_secret("low_entropy_generic", 7));
    let ev = scan("settings.py", &content);
    assert!(ev.is_empty(), "rules {:?}", rule_ids(&ev));
    assert_eq!(secret_score(&ev), None);
}

#[test]
fn example_key_allowlisted() {
    let s = synth::fake_secret("aws_example_key", 7);
    assert!(s.ends_with("EXAMPLE"));
    let (content, _) = embed(&format!("    let id = \"{s}\";"));
    let ev = scan("src/main.rs", &content);
    assert!(ev.is_empty(), "rules {:?}", rule_ids(&ev));
}

/// A minimal DER SEQUENCE with a two-byte length, as PKCS #12 files start.
fn der_blob(seed: u64) -> Vec<u8> {
    let mut body = vec![0u8; 300];
    synth::Rng::new(seed).fill(&mut body);
    let mut out = vec![0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

#[test]
fn p12_file() {
    let ev = scan("certs/client.p12", &der_blob(3));
    assert!(
        rule_ids(&ev).contains(&"pkcs12_keystore"),
        "{:?}",
        rule_ids(&ev)
    );
    assert_score(&ev, 90.0);
}

/// `prefix` followed by random bytes.
fn der_with(prefix: &[u8], seed: u64) -> Vec<u8> {
    let mut body = vec![0u8; 300];
    synth::Rng::new(seed).fill(&mut body);
    let mut out = prefix.to_vec();
    out.extend_from_slice(&body);
    out
}

#[test]
fn der_key_file() {
    // PKCS#1 (`SEQUENCE { INTEGER 0, INTEGER ...`), PKCS#8
    // (`SEQUENCE { INTEGER 0, SEQUENCE ...`), and SEC1 EC keys
    // (`SEQUENCE { INTEGER 1, OCTET STRING ...`), with one-byte and long-form
    // lengths. `der_private_key_kinds` covers whole keys.
    for (n, prefix) in [
        &[0x30, 0x82, 0x01, 0x2c, 0x02, 0x01, 0x00, 0x02][..],
        &[0x30, 0x82, 0x01, 0x2c, 0x02, 0x01, 0x00, 0x30],
        &[0x30, 0x77, 0x02, 0x01, 0x01, 0x04],
        &[0x30, 0x81, 0x87, 0x02, 0x01, 0x01, 0x04],
        &[0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30],
        &[0x30, 0x2e, 0x02, 0x01, 0x00, 0x30],
    ]
    .into_iter()
    .enumerate()
    {
        let ev = scan("keys/server.der", &der_with(prefix, 4));
        assert_eq!(rule_ids(&ev), vec!["der_key_file"], "prefix {n}");
        assert_score(&ev, 90.0);
        let ev = scan("keys/server.key", &der_with(prefix, 5));
        assert_eq!(rule_ids(&ev), vec!["der_key_file"], "prefix {n}");
    }
}

/// A DER length.
fn der_len(n: usize) -> Vec<u8> {
    match n {
        0..=127 => vec![n as u8],
        128..=255 => vec![0x81, n as u8],
        _ => vec![0x82, (n >> 8) as u8, n as u8],
    }
}

/// A DER tag-length-value.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn random_bytes(n: usize, seed: u64) -> Vec<u8> {
    let mut b = vec![0u8; n];
    synth::Rng::new(seed).fill(&mut b);
    b
}

const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P224: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x21];
const OID_SECP256K1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];
const OID_BRAINPOOL_P256R1: &[u8] = &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_ED448: &[u8] = &[0x2b, 0x65, 0x71];

/// SEC1 `ECPrivateKey` (RFC 5915) with random key bytes: version 1, the
/// private scalar, the curve, and optionally the public point.
fn sec1_key(curve: Option<&[u8]>, scalar: usize, point: Option<usize>, seed: u64) -> Vec<u8> {
    let mut body = vec![0x02, 0x01, 0x01];
    body.extend(tlv(0x04, &random_bytes(scalar, seed)));
    if let Some(oid) = curve {
        body.extend(tlv(0xa0, &tlv(0x06, oid)));
    }
    if let Some(n) = point {
        let mut bits = vec![0x00, 0x04];
        bits.extend(random_bytes(n - 1, seed + 1));
        body.extend(tlv(0xa1, &tlv(0x03, &bits)));
    }
    tlv(0x30, &body)
}

/// PKCS #8 `PrivateKeyInfo` (version 0), or RFC 5958 `OneAsymmetricKey`
/// version 1 with a public key, around `key`.
fn pkcs8_key(alg: &[u8], params: Option<&[u8]>, key: &[u8], public: Option<usize>) -> Vec<u8> {
    let mut algid = tlv(0x06, alg);
    match params {
        Some([]) => algid.extend([0x05, 0x00]),
        Some(p) => algid.extend(tlv(0x06, p)),
        None => {}
    }
    let mut body = vec![0x02, 0x01, u8::from(public.is_some())];
    body.extend(tlv(0x30, &algid));
    body.extend(tlv(0x04, key));
    if let Some(n) = public {
        let mut bits = vec![0x00];
        bits.extend(random_bytes(n, 99));
        body.extend(tlv(0x81, &bits));
    }
    tlv(0x30, &body)
}

/// PKCS #1 `RSAPrivateKey` (version 0, then the modulus and other integers).
fn pkcs1_rsa(bits: usize, seed: u64) -> Vec<u8> {
    let mut body = vec![0x02, 0x01, 0x00];
    let mut modulus = vec![0x00];
    modulus.extend(random_bytes(bits / 8, seed));
    body.extend(tlv(0x02, &modulus));
    body.extend(tlv(0x02, &[0x01, 0x00, 0x01]));
    for i in 0..6 {
        body.extend(tlv(0x02, &random_bytes(bits / 16, seed + 10 + i)));
    }
    tlv(0x30, &body)
}

/// DER private keys of the kinds OpenSSL writes, with random key bytes: the
/// header bytes and total lengths match OpenSSL 3.5's output for each kind.
fn der_private_keys() -> Vec<(&'static str, Vec<u8>)> {
    let raw = |n: usize, seed: u64| tlv(0x04, &random_bytes(n, seed));
    vec![
        ("pkcs1 rsa 2048", pkcs1_rsa(2048, 1)),
        (
            "pkcs8 rsa 2048",
            pkcs8_key(OID_RSA, Some(&[]), &pkcs1_rsa(2048, 2), None),
        ),
        ("sec1 p-256", sec1_key(Some(OID_P256), 32, Some(65), 3)),
        (
            "sec1 p-256 without public key",
            sec1_key(Some(OID_P256), 32, None, 4),
        ),
        ("sec1 p-384", sec1_key(Some(OID_P384), 48, Some(97), 5)),
        ("sec1 p-224", sec1_key(Some(OID_P224), 28, Some(57), 6)),
        (
            "sec1 secp256k1",
            sec1_key(Some(OID_SECP256K1), 32, Some(65), 7),
        ),
        (
            "sec1 brainpoolP256r1",
            sec1_key(Some(OID_BRAINPOOL_P256R1), 32, Some(65), 8),
        ),
        (
            "pkcs8 p-256",
            pkcs8_key(
                OID_EC_PUBLIC_KEY,
                Some(OID_P256),
                &sec1_key(None, 32, Some(65), 9),
                None,
            ),
        ),
        (
            "pkcs8 ed25519",
            pkcs8_key(OID_ED25519, None, &raw(32, 10), None),
        ),
        (
            "pkcs8 x25519",
            pkcs8_key(OID_X25519, None, &raw(32, 11), None),
        ),
        (
            "pkcs8 ed448",
            pkcs8_key(OID_ED448, None, &raw(57, 12), None),
        ),
        (
            "pkcs8 v2 ed25519 with public key",
            pkcs8_key(OID_ED25519, None, &raw(32, 13), Some(32)),
        ),
    ]
}

#[test]
fn der_private_key_kinds() {
    // Header bytes as OpenSSL 3.5 writes them (checked against its output).
    let keys = der_private_keys();
    let head = |name: &str| keys.iter().find(|(n, _)| *n == name).unwrap().1[..7].to_vec();
    assert_eq!(head("sec1 p-224")[..2], [0x30, 0x68]);
    assert_eq!(head("sec1 secp256k1")[..2], [0x30, 0x74]);
    assert_eq!(head("sec1 brainpoolP256r1")[..2], [0x30, 0x78]);
    assert_eq!(head("sec1 p-256 without public key")[..2], [0x30, 0x31]);
    assert_eq!(head("sec1 p-384")[..3], [0x30, 0x81, 0xa4]);
    assert_eq!(head("pkcs8 ed25519")[..2], [0x30, 0x2e]);
    assert_eq!(head("pkcs8 ed448")[..2], [0x30, 0x47]);
    assert_eq!(head("pkcs8 p-256")[..3], [0x30, 0x81, 0x87]);
    for (name, key) in &keys {
        for path in ["keys/server.der", "keys/server.key", "KEYS/SERVER.KEY"] {
            let ev = scan(path, key);
            assert_eq!(rule_ids(&ev), vec!["der_key_file"], "{name} at {path}");
            assert_score(&ev, 90.0);
        }
        // The rule needs the extension.
        assert!(scan("keys/server.bin", key).is_empty(), "{name}");
    }
}

#[test]
fn der_structures_that_are_not_private_keys() {
    let spki = {
        let mut algid = tlv(0x06, OID_EC_PUBLIC_KEY);
        algid.extend(tlv(0x06, OID_P256));
        let mut body = tlv(0x30, &algid);
        let mut bits = vec![0x00, 0x04];
        bits.extend(random_bytes(64, 20));
        body.extend(tlv(0x03, &bits));
        tlv(0x30, &body)
    };
    let rsa_public = {
        let mut modulus = vec![0x00];
        modulus.extend(random_bytes(256, 21));
        let mut body = tlv(0x02, &modulus);
        body.extend(tlv(0x02, &[0x01, 0x00, 0x01]));
        tlv(0x30, &body)
    };
    let ecdsa_signature = {
        let mut body = tlv(0x02, &random_bytes(32, 22));
        body.extend(tlv(0x02, &random_bytes(32, 23)));
        tlv(0x30, &body)
    };
    let certificate = der_with(&[0x30, 0x82, 0x03, 0x1c, 0x30, 0x82, 0x02, 0x04], 24);
    for (name, der) in [
        ("subjectPublicKeyInfo", spki),
        ("pkcs1 rsa public key", rsa_public),
        ("ecdsa signature", ecdsa_signature),
        ("x.509 certificate", certificate),
    ] {
        let ev = scan("keys/server.der", &der);
        assert!(ev.is_empty(), "{name}: rules {:?}", rule_ids(&ev));
    }
}

#[test]
fn ec_key_file_end_to_end() {
    use riskgrep_core::classify::{classify_sized, read_for_scan, FileClass, Known, Limits};
    use std::io::Write;
    let mut f = tempfile::Builder::new().suffix(".key").tempfile().unwrap();
    f.write_all(&der_with(&[0x30, 0x77, 0x02, 0x01, 0x01, 0x04], 9))
        .unwrap();
    f.flush().unwrap();
    let file = std::fs::File::open(f.path()).unwrap();
    let size = file.metadata().unwrap().len();
    let limits = Limits::default();
    let mut head = vec![0u8; (limits.sniff as u64).min(size) as usize];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut head, 0).unwrap();
    let name = f.path().to_string_lossy().into_owned();
    let class = classify_sized(&name, &head, size);
    assert_eq!(class, FileClass::KnownBinary(Known::KeyStore));
    let content = read_for_scan(&file, size, &class, &limits).unwrap();
    assert_eq!(content.bytes.len() as u64, size);
    let ev = scan(&name, &content.bytes);
    assert_eq!(rule_ids(&ev), vec!["der_key_file"]);
    assert_score(&ev, 90.0);
}

/// Scores and rules for each file, scanned as `riskgrep scan --no-cache`
/// does (classification, reading, rules), with the default configuration.
fn scan_files(paths: &[std::path::PathBuf]) -> Vec<(String, Option<f64>, Vec<String>)> {
    use riskgrep_core::config::Config;
    use riskgrep_core::RiskGrep;
    let cfg = Config {
        no_cache: true,
        ..Config::default()
    };
    let mut rg = RiskGrep::with_cache_dir(cfg, None, None).unwrap();
    rg.scan_paths(paths)
        .targets
        .into_iter()
        .map(|t| {
            let rules = t.evidence.iter().map(|e| e.rule.clone()).collect();
            let secret = t.scores.get(&Category("secret".into())).copied();
            (t.target, secret, rules)
        })
        .collect()
}

#[test]
fn der_private_keys_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for (i, (_, key)) in der_private_keys().iter().enumerate() {
        for ext in ["der", "key"] {
            let p = dir.path().join(format!("k{i}.{ext}"));
            std::fs::write(&p, key).unwrap();
            paths.push(p);
        }
    }
    let got = scan_files(&paths);
    assert_eq!(got.len(), paths.len());
    let names: HashMap<String, &str> = (0..der_private_keys().len())
        .flat_map(|i| {
            let n = der_private_keys()[i].0;
            [(format!("k{i}.der"), n), (format!("k{i}.key"), n)]
        })
        .collect();
    for (target, secret, rules) in &got {
        let file = target.rsplit('/').next().unwrap();
        let kind = names[file];
        assert_eq!(rules, &vec!["der_key_file".to_string()], "{kind} ({file})");
        assert_eq!(*secret, Some(90.0), "{kind} ({file})");
    }
}

#[test]
fn text_key_file_starting_with_a_digit_is_still_scanned_for_tokens() {
    // `0` (0x30) followed by a printable byte reads as a DER SEQUENCE header
    // with a short-form length; the file is read as a key store, and the
    // text rules still run on all of it.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("deploy.key");
    let token = synth::fake_secret("github_pat", 12);
    std::fs::write(&p, format!("0 token follows\nid = \"{token}\"\n")).unwrap();
    let got = scan_files(&[p]);
    assert!(
        got[0].2.contains(&"github_pat".to_string()),
        "{:?}",
        got[0].2
    );
    assert_eq!(got[0].1, Some(95.0));
}

#[test]
fn large_text_key_file_starting_with_a_digit_is_scanned_whole() {
    // Over 1 MiB the leading `0x` is not read as a DER header, so the file
    // takes the text path (first and last megabyte past 8 MiB) and a secret
    // on its last line is found; the same bytes named `.txt` score the same.
    let dir = tempfile::tempdir().unwrap();
    let secret = synth::fake_secret("aws_access_key", 21);
    let mut body = b"0x header\n".to_vec();
    let filler = b"lorem ipsum dolor sit amet, consectetur adipiscing elit\n";
    while body.len() < 9 << 20 {
        body.extend_from_slice(filler);
    }
    body.extend_from_slice(format!("aws_access_key_id = \"{secret}\"\n").as_bytes());
    let mut paths = Vec::new();
    for name in ["big.key", "big.der", "big.txt"] {
        let p = dir.path().join(name);
        std::fs::write(&p, &body).unwrap();
        paths.push(p);
    }
    for (target, secret, rules) in scan_files(&paths) {
        assert_eq!(secret, Some(95.0), "{target} {rules:?}");
    }
}

#[test]
fn der_header_with_a_three_byte_length_is_not_a_key_store() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("k.key");
    std::fs::write(
        &p,
        der_with(&[0x30, 0x83, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00], 8),
    )
    .unwrap();
    let got = scan_files(&[p]);
    assert_eq!(got[0].1, None, "{:?}", got[0].2);
}

#[test]
fn der_certificate_is_not_a_key() {
    // X.509: `SEQUENCE { SEQUENCE (tbsCertificate) ...`.
    let cert = der_with(&[0x30, 0x82, 0x03, 0x1c, 0x30, 0x82, 0x02, 0x04], 6);
    for path in ["certs/server.der", "certs/server.key"] {
        let ev = scan(path, &cert);
        assert!(ev.is_empty(), "{path}: rules {:?}", rule_ids(&ev));
    }
}

#[test]
fn keystore_extension_without_der_header() {
    let ev = scan("keys/server.key", b"not a der file\n");
    assert!(ev.is_empty(), "rules {:?}", rule_ids(&ev));
}

#[test]
fn global_path_allowlist() {
    let s = synth::fake_secret("github_pat", 9);
    let (content, _) = embed(&format!("    let id = \"{s}\";"));
    assert!(scan("node_modules/pkg/index.js", &content).is_empty());
    assert!(!scan("src/index.js", &content).is_empty());
}

#[test]
fn fake_secrets_are_deterministic_and_seeded() {
    // Compared with `==` so a failure never prints a generated value.
    for kind in synth::FAKE_SECRET_KINDS {
        assert!(
            synth::fake_secret(kind, 1) == synth::fake_secret(kind, 1),
            "{kind}"
        );
        if *kind != "low_entropy_generic" {
            assert!(
                synth::fake_secret(kind, 1) != synth::fake_secret(kind, 2),
                "{kind}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Agreement with a reference implementation of gitleaks' semantics.

/// Go reads a `{` that starts no repetition as a literal; Rust needs `\{`.
fn go_literal_braces(src: &str) -> String {
    let b = src.as_bytes();
    let rep = Regex::new(r"^\{[0-9]+(,[0-9]*)?\}").unwrap();
    let (mut out, mut i, mut class) = (String::new(), 0, false);
    while i < b.len() {
        let c = b[i] as char;
        if c == '\\' {
            out.push_str(&src[i..(i + 2).min(b.len())]);
            i += 2;
            continue;
        }
        match c {
            '[' if !class => class = true,
            ']' if class => class = false,
            '{' if !class && !rep.is_match(&b[i..]) => out.push('\\'),
            _ => {}
        }
        out.push(c);
        i += 1;
    }
    out
}

fn compile(src: &str) -> Regex {
    RegexBuilder::new(&go_literal_braces(src))
        .unicode(false)
        .size_limit(1 << 28)
        .build()
        .unwrap_or_else(|e| panic!("reference regex does not compile: {e}"))
}

#[derive(Clone, Copy, PartialEq)]
enum Target {
    Secret,
    Match,
    Line,
}

struct RefAllow {
    and: bool,
    target: Target,
    regexes: Vec<Regex>,
    paths: Vec<Regex>,
    stopwords: Vec<String>,
}

struct RefRule {
    ident: String,
    regex: Option<Regex>,
    path: Option<Regex>,
    keywords: Vec<String>,
    secret_group: Option<usize>,
    entropy: Option<f64>,
    allow: Vec<RefAllow>,
}

fn strings(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

fn ref_allow(v: &toml::Value) -> RefAllow {
    RefAllow {
        and: v.get("condition").and_then(|c| c.as_str()) == Some("AND"),
        target: match v.get("regexTarget").and_then(|c| c.as_str()) {
            Some("match") => Target::Match,
            Some("line") => Target::Line,
            _ => Target::Secret,
        },
        regexes: strings(v.get("regexes"))
            .iter()
            .map(|s| compile(s))
            .collect(),
        paths: strings(v.get("paths")).iter().map(|s| compile(s)).collect(),
        stopwords: strings(v.get("stopwords"))
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
    }
}

fn reference() -> (Vec<RefRule>, Vec<RefAllow>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../xtask/upstream/gitleaks.toml"
    );
    let cfg: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut global: Vec<RefAllow> = cfg.get("allowlist").map(ref_allow).into_iter().collect();
    if let Some(a) = cfg.get("allowlists").and_then(|a| a.as_array()) {
        global.extend(a.iter().map(ref_allow));
    }
    let rules = cfg["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let mut allow: Vec<RefAllow> = r.get("allowlist").map(ref_allow).into_iter().collect();
            if let Some(a) = r.get("allowlists").and_then(|a| a.as_array()) {
                allow.extend(a.iter().map(ref_allow));
            }
            RefRule {
                ident: r["id"].as_str().unwrap().replace('-', "_"),
                regex: r.get("regex").map(|s| compile(s.as_str().unwrap())),
                path: r.get("path").map(|s| compile(s.as_str().unwrap())),
                keywords: strings(r.get("keywords"))
                    .into_iter()
                    .map(|k| k.to_ascii_lowercase())
                    .collect(),
                secret_group: r
                    .get("secretGroup")
                    .and_then(|g| g.as_integer())
                    .map(|g| g as usize),
                entropy: r
                    .get("entropy")
                    .and_then(|e| e.as_float().or(e.as_integer().map(|i| i as f64))),
                allow,
            }
        })
        .collect();
    (rules, global)
}

/// Shannon entropy in bits per byte, as gitleaks computes it for ASCII.
fn entropy_of(b: &[u8]) -> f64 {
    let mut freq = [0usize; 256];
    for &x in b {
        freq[x as usize] += 1;
    }
    let n = b.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// gitleaks: an allowlist matches when any (OR) or all (AND) of its
/// configured checks match.
fn allowed(a: &RefAllow, path: &str, secret: &[u8], whole: &[u8], line: &[u8]) -> bool {
    let mut checks = Vec::new();
    if !a.paths.is_empty() {
        checks.push(a.paths.iter().any(|r| r.is_match(path.as_bytes())));
    }
    if !a.regexes.is_empty() {
        let hay = match a.target {
            Target::Secret => secret,
            Target::Match => whole,
            Target::Line => line,
        };
        checks.push(a.regexes.iter().any(|r| r.is_match(hay)));
    }
    if !a.stopwords.is_empty() {
        let low = secret.to_ascii_lowercase();
        checks.push(a.stopwords.iter().any(|w| contains(&low, w.as_bytes())));
    }
    if a.and {
        !checks.is_empty() && checks.iter().all(|c| *c)
    } else {
        checks.iter().any(|c| *c)
    }
}

/// gitleaks' verdict for one rule on one file.
fn reference_verdict(r: &RefRule, global: &[RefAllow], path: &str, content: &[u8]) -> bool {
    let path_allowed = |a: &RefAllow| !a.and && a.paths.iter().any(|p| p.is_match(path.as_bytes()));
    if global.iter().chain(&r.allow).any(path_allowed) {
        return false;
    }
    if let Some(p) = &r.path {
        if !p.is_match(path.as_bytes()) {
            return false;
        }
    }
    let Some(re) = &r.regex else {
        return r.path.is_some();
    };
    let low = content.to_ascii_lowercase();
    if !r.keywords.is_empty() && !r.keywords.iter().any(|k| contains(&low, k.as_bytes())) {
        return false;
    }
    for caps in re.captures_iter(content) {
        let whole = caps.get(0).unwrap();
        let secret = match r.secret_group {
            Some(g) => match caps.get(g) {
                Some(m) => m.as_bytes(),
                None => continue,
            },
            None => (1..caps.len())
                .filter_map(|i| caps.get(i))
                .map(|m| m.as_bytes())
                .find(|s| !s.is_empty())
                .unwrap_or(whole.as_bytes()),
        };
        if let Some(e) = r.entropy {
            if e != 0.0 && entropy_of(secret) <= e {
                continue;
            }
        }
        let ls = content[..whole.start()]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let le = content[whole.end()..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(content.len(), |i| whole.end() + i);
        let line = &content[ls..le];
        if global
            .iter()
            .chain(&r.allow)
            .any(|a| allowed(a, path, secret, whole.as_bytes(), line))
        {
            continue;
        }
        return true;
    }
    false
}

/// A synthetic file and whether gitleaks should report anything in it.
struct Sample {
    path: String,
    content: Vec<u8>,
    expect_hit: bool,
}

/// Synthetic files: each secret kind in three contexts and two seeds, plus
/// negatives and allowlisted paths.
fn samples() -> Vec<Sample> {
    let mut out = Vec::new();
    let filler = synth::source_text(2048, 11);
    let negative = ["aws_example_key", "low_entropy_generic"];
    for kind in synth::FAKE_SECRET_KINDS {
        for seed in [1u64, 2] {
            let s = synth::fake_secret(kind, seed);
            let lines = if kind.ends_with("generic") || kind.ends_with("assignment") {
                vec![s.clone()]
            } else {
                vec![
                    format!("    let id = \"{s}\";"),
                    format!("EXPORTED_VALUE={s}"),
                    format!("{{\"auth_token\": \"{s}\"}}"),
                ]
            };
            for (i, line) in lines.into_iter().enumerate() {
                let mut body = filler.as_bytes()[..1024].to_vec();
                body.extend_from_slice(b"\n");
                body.extend_from_slice(line.as_bytes());
                body.extend_from_slice(b"\n");
                body.extend_from_slice(&filler.as_bytes()[1024..]);
                out.push(Sample {
                    path: ["src/app.rs", ".env", "config/settings.json"][i % 3].into(),
                    content: body,
                    expect_hit: !negative.contains(kind),
                });
            }
        }
    }
    let pat = synth::fake_secret("github_pat", 5);
    for path in [
        "node_modules/x/index.js",
        "vendor/github.com/x/y.go",
        "@octokit/auth-token/README.md",
    ] {
        out.push(Sample {
            path: path.into(),
            content: format!("id = {pat}\n").into_bytes(),
            expect_hit: false,
        });
    }
    // gitleaks allowlists for generic-api-key: a stopword in the secret
    // (translated) and a key name allowlisted on the whole match (not
    // translated; the local change also rejects that key name).
    let random = &synth::fake_secret("github_pat", 6)[4..];
    for line in [
        format!(
            "api_key = \"{}dashboard{}\"",
            &random[..12],
            &random[12..24]
        ),
        format!("public_key = \"{random}\""),
    ] {
        out.push(Sample {
            path: "settings.py".into(),
            content: format!("{line}\n").into_bytes(),
            expect_hit: false,
        });
    }
    // A key name that only contains a keyword: gitleaks reports it, the
    // local change to generic-api-key (UPSTREAM.md) does not.
    out.push(Sample {
        path: "settings.py".into(),
        content: format!("key_sha256 = \"{random}\"\n").into_bytes(),
        expect_hit: true,
    });
    out.extend(secret_group_samples());
    out.push(Sample {
        path: "src/plain.rs".into(),
        content: filler.into_bytes(),
        expect_hit: false,
    });
    out.push(Sample {
        path: "certs/client.p12".into(),
        content: der_blob(8),
        expect_hit: true,
    });
    out
}

/// `n` characters drawn from `alphabet`.
fn random_from(rng: &mut synth::Rng, alphabet: &[u8], n: usize) -> String {
    (0..n)
        .map(|_| alphabet[(rng.next_u64() % alphabet.len() as u64) as usize] as char)
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// base64url without padding, as JWT segments are written.
fn base64url(data: &[u8]) -> String {
    base64(data)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Rules without `secretGroup` whose secret can be in a capture group other
/// than group 1 (gitleaks takes the first non-empty group): current Atlassian
/// tokens, curl `Authorization: Bearer` headers in both quote styles, a
/// base64-encoded JWT whose header starts with `typ` or `kid`, and a
/// Kubernetes Secret with `data:` before `kind:`.
fn secret_group_samples() -> Vec<Sample> {
    let mut rng = synth::Rng::new(41);
    let mut out = Vec::new();
    let mut push = |path: &str, text: String| {
        out.push(Sample {
            path: path.into(),
            content: text.into_bytes(),
            expect_hit: true,
        })
    };
    let atl = format!(
        "ATATT3{}",
        random_from(
            &mut rng,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=",
            186
        )
    );
    push("deploy/.env", format!("export SERVICE_TOKEN={atl}\n"));
    let bearer = random_from(&mut rng, ALNUM, 40);
    push(
        "scripts/call.sh",
        format!(
            "curl -s -H \"Authorization: Bearer {bearer}\" https://api.example.test/v1/items\n"
        ),
    );
    let bearer = random_from(&mut rng, ALNUM, 40);
    push(
        "scripts/call.sh",
        format!("curl -s -H 'Authorization: Bearer {bearer}' https://api.example.test/v1/items\n"),
    );
    for header in [
        r#"{"typ":"JWT","alg":"HS256"}"#.to_string(),
        format!(
            r#"{{"kid":"{}","alg":"RS256"}}"#,
            random_from(&mut rng, ALNUM, 16)
        ),
    ] {
        let payload = format!(
            r#"{{"sub":"{}","iat":1700000000}}"#,
            random_from(&mut rng, ALNUM, 12)
        );
        let mut sig = vec![0u8; 32];
        rng.fill(&mut sig);
        let jwt = format!(
            "{}.{}.{}",
            base64url(header.as_bytes()),
            base64url(payload.as_bytes()),
            base64url(&sig)
        );
        push(
            "config/settings.json",
            format!("{{\"session\": \"{}\"}}\n", base64(jwt.as_bytes())),
        );
    }
    let mut value = vec![0u8; 24];
    rng.fill(&mut value);
    push(
        "deploy/app-secret.yaml",
        format!(
            "apiVersion: v1\ndata:\n  password: {}\nkind: Secret\nmetadata:\n  name: app\ntype: Opaque\n",
            base64(&value)
        ),
    );
    out
}

#[test]
fn secret_group_forms_are_reported() {
    // Each sample is reported by the rule gitleaks reports it with.
    let want = [
        "atlassian_api_token",
        "curl_auth_header",
        "curl_auth_header",
        "jwt_base64",
        "jwt_base64",
        "kubernetes_secret_yaml",
    ];
    let samples = secret_group_samples();
    assert_eq!(samples.len(), want.len());
    for (s, rule) in samples.iter().zip(want) {
        let ev = scan(&s.path, &s.content);
        assert!(
            rule_ids(&ev).contains(&rule),
            "{}: {rule} not reported; rules {:?}",
            s.path,
            rule_ids(&ev)
        );
    }
}

#[test]
fn agreement_with_reference() {
    let (rules, global) = reference();
    let samples = samples();
    let mut total = 0usize;
    let mut disagree: BTreeSet<String> = BTreeSet::new();
    let mut disagreements = 0usize;
    for (n, s) in samples.iter().enumerate() {
        let got: BTreeSet<String> = scan(&s.path, &s.content)
            .into_iter()
            .map(|e| e.rule)
            .collect();
        let mut any = false;
        for r in &rules {
            total += 1;
            let want = reference_verdict(r, &global, &s.path, &s.content);
            any |= want;
            if want != got.contains(&r.ident) {
                disagreements += 1;
                disagree.insert(r.ident.clone());
            }
        }
        assert_eq!(
            any, s.expect_hit,
            "reference verdict on sample {n} ({})",
            s.path
        );
    }
    let agree = (total - disagreements) as f64 / total as f64;
    eprintln!(
        "agreement {agree:.4}: {disagreements} of {total} rule x sample pairs differ ({} samples); rules: {disagree:?}",
        samples.len()
    );
    assert!(
        agree >= 0.99,
        "agreement {agree:.4} < 0.99; disagreeing rules: {disagree:?}"
    );
    // Only documented differences may remain, so one dead or always-firing
    // rule fails:
    // - generic_api_key: the local change requires a credential-named key
    //   (UPSTREAM.md "Local changes"), so `key_sha256 = "..."` is not reported.
    let expected: BTreeSet<String> = ["generic_api_key".to_string()].into();
    assert_eq!(disagree, expected, "disagreeing rules");
}

// ---------------------------------------------------------------------------
// Timing (release): run with
// `cargo test --release -p riskgrep-core --test ruleset_secrets -- --ignored --nocapture`

fn p95(mut v: Vec<std::time::Duration>) -> std::time::Duration {
    v.sort();
    v[(v.len() * 95).div_ceil(100) - 1]
}

#[test]
#[ignore = "release timing; run with --release -- --ignored"]
fn release_timings() {
    use std::time::Instant;
    let all = builtin_rulesets();
    let rs: Vec<&Ruleset> = all.iter().collect();
    assert_eq!(rs.len(), 2, "secrets_core and biometric_embeddings");

    let t = Instant::now();
    let bundle = compile_uncached(&rs).unwrap();
    let compile = t.elapsed();
    let bytes = bundle.rules.serialize().unwrap();

    let mut load = Vec::new();
    // Engine::new and the first scan of a fresh engine (post-processors
    // compile on a rule's first match), on the full two-ruleset bundle.
    let text64 = synth::source_text(64 << 10, 1);
    let mut engine_new = Vec::new();
    let mut first_scan = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let rules = yara_x::Rules::deserialize(&bytes).unwrap();
        load.push(t.elapsed());
        drop(rules);
        let b = compile_uncached(&rs).unwrap();
        let t = Instant::now();
        let e = Engine::new(b).unwrap();
        engine_new.push(t.elapsed());
        let mut sc = yara_x::Scanner::new(e.rules());
        let t = Instant::now();
        std::hint::black_box(
            e.scan_content(&mut sc, "src/a.rs", text64.as_bytes())
                .unwrap(),
        );
        first_scan.push(t.elapsed());
    }
    let engine = Engine::new(bundle).unwrap();
    let t = Instant::now();
    engine.validate_all().unwrap();
    let validate = t.elapsed();
    let mut sc = yara_x::Scanner::new(engine.rules());
    let mut report = format!(
        "compile secrets_core + biometric: {compile:?}; serialized {} bytes; \
         deserialize p95 {:?}; Engine::new p95 {:?}; first scan of 64 KiB (fresh engine) p95 {:?}; \
         validate_all {validate:?} ({} distinct regexes)",
        bytes.len(),
        p95(load),
        p95(engine_new),
        p95(first_scan),
        engine.compiled_regexes()
    );
    for size in [64 << 10, 1 << 20] {
        let text = synth::source_text(size, 1);
        assert_eq!(text.len(), size);
        let mut runs = Vec::new();
        for _ in 0..40 {
            let t = Instant::now();
            let ev = engine
                .scan_content(&mut sc, "src/big.rs", text.as_bytes())
                .unwrap();
            runs.push(t.elapsed());
            std::hint::black_box(ev);
        }
        report.push_str(&format!("; scan {size} B p95 {:?}", p95(runs)));
    }
    eprintln!("{report}");
}

/// Files under `dir`, recursively, sorted.
fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out.sort();
    out
}

#[test]
fn shipped_rule_sources_do_not_trip_the_rules() {
    let repo = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let all = builtin_rulesets();
    let refs: Vec<&Ruleset> = all.iter().collect();
    let engine = Engine::new(compile_uncached(&refs).unwrap()).unwrap();
    engine.validate_all().unwrap();
    let mut sc = yara_x::Scanner::new(engine.rules());
    let mut files = files_under(&repo.join("rulesets"));
    files.push(repo.join("xtask/upstream/gitleaks.toml"));
    assert!(files.len() > 10, "found {} files", files.len());
    let mut hits = Vec::new();
    for f in &files {
        let rel = f.strip_prefix(repo).unwrap().to_string_lossy().into_owned();
        let content = std::fs::read(f).unwrap();
        for e in engine.scan_content(&mut sc, &rel, &content).unwrap() {
            if e.category.0 == "secret" {
                hits.push(format!("{rel}: {}", e.rule));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "secret evidence in shipped files: {hits:?}"
    );
}
