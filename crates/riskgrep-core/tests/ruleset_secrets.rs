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
    // PKCS#1 / PKCS#8 (`SEQUENCE { INTEGER 0, ...`) and SEC1 EC keys
    // (`SEQUENCE { INTEGER 1, ...` with a one- or two-byte length form).
    for (n, prefix) in [
        &[0x30, 0x82, 0x01, 0x2c, 0x02, 0x01, 0x00][..],
        &[0x30, 0x77, 0x02, 0x01, 0x01],
        &[0x30, 0x81, 0x87, 0x02, 0x01, 0x01],
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

#[test]
fn ec_key_file_end_to_end() {
    use riskgrep_core::classify::{classify, read_for_scan, FileClass, Known, Limits};
    use std::io::Write;
    let mut f = tempfile::Builder::new().suffix(".key").tempfile().unwrap();
    f.write_all(&der_with(&[0x30, 0x77, 0x02, 0x01, 0x01], 9))
        .unwrap();
    f.flush().unwrap();
    let file = std::fs::File::open(f.path()).unwrap();
    let size = file.metadata().unwrap().len();
    let limits = Limits::default();
    let mut head = vec![0u8; (limits.sniff as u64).min(size) as usize];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut head, 0).unwrap();
    let name = f.path().to_string_lossy().into_owned();
    let class = classify(&name, &head);
    assert_eq!(class, FileClass::KnownBinary(Known::KeyStore));
    let content = read_for_scan(&file, size, &class, &limits).unwrap();
    assert_eq!(content.bytes.len() as u64, size);
    let ev = scan(&name, &content.bytes);
    assert_eq!(rule_ids(&ev), vec!["der_key_file"]);
    assert_score(&ev, 90.0);
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
