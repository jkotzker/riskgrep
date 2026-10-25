//! The gitleaks converter: regex rewriting, and the generated ruleset.

use riskgrep_core::bundle::load_or_compile;
use riskgrep_core::ruleset::Ruleset;
use std::fs;
use std::path::{Path, PathBuf};
use xtask::{
    can_match_newline, convert_gitleaks, lazy_to_greedy, line_complete, sets_multi_line,
    steer_atoms, PINNED_TAG,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pinned_config() -> Vec<u8> {
    fs::read(repo().join("xtask/upstream/gitleaks.toml")).unwrap()
}

#[test]
fn lazy_counted_repetition_becomes_greedy() {
    assert_eq!(
        lazy_to_greedy("[\\w.-]{0,50}?(?:a|b)"),
        "[\\w.-]{0,50}(?:a|b)"
    );
}

#[test]
fn escaped_brace_is_not_a_quantifier() {
    assert_eq!(lazy_to_greedy(r"\{3}?"), r"\{3}?");
}

#[test]
fn class_contents_are_untouched() {
    assert_eq!(lazy_to_greedy("[?*]+?"), "[?*]+");
}

#[test]
fn other_lazy_forms() {
    assert_eq!(lazy_to_greedy("a*?b+?c??d{2,}?"), "a*b+c?d{2,}");
    // Group flags and a literal `{` that does not start a repetition.
    assert_eq!(lazy_to_greedy("(?i)(?:x)a{b}?"), "(?i)(?:x)a{b}?");
    // POSIX class and a leading `]` inside a class.
    assert_eq!(lazy_to_greedy("[[:alnum:]?]*?[]?]+?"), "[[:alnum:]?]*[]?]+");
    // An escaped backslash does not escape the next quantifier.
    assert_eq!(lazy_to_greedy(r"\\+?"), r"\\+");
}

#[test]
fn newline_reachability() {
    for re in [
        r"AKIA[A-Z2-7]{16}",
        r"ghp_[0-9a-zA-Z]{36}",
        r"(?i)key[ \t]*=[ \t]*([a-z0-9]{8})",
        r"a.b",
        r"(?m)^x$",
        r"[^\n]+",
        r"\\n",
        // `\v` is a vertical tab, not a class.
        r"\v",
    ] {
        assert!(!can_match_newline(re).unwrap(), "{re}");
    }
    for re in [
        r"a\sb",
        r"[\s\S]",
        r"(?s)a.b",
        r"(?s:.)",
        r"[^x]",
        r"[^'\x22]+",
        r"a\nb",
        r"\x0a",
        r"[\x00-\x7f]",
        r"[[:space:]]",
        r"(?-u:\W)",
        r"\D",
        r#"[^"]+"#,
    ] {
        assert!(can_match_newline(re).unwrap(), "{re}");
    }
    assert!(can_match_newline("(").is_err());
}

#[test]
fn line_complete_allows_one_trailing_byte_after_the_secret() {
    // gitleaks' provider form: the trailing delimiter can be a line feed.
    let provider = r#"\b(sk_live_[a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)"#;
    for (re, group) in [
        (provider, Some(1)),
        (r"AKIA[A-Z2-7]{16}", Some(0)),
        (r"AKIA[A-Z2-7]{16}", None),
        (r"x(tok)\s", Some(1)),
        (r"x(tok)[\s;]?\b", Some(1)),
        (r"x(tok)(?:\s|;;|$)", Some(1)),
        (r"x((tok))(?:\s|$)", Some(2)),
        (r"x(tok)(?:(\s)|$)", Some(1)),
        // The secret group nested in an element: nothing up to that
        // element's end can match a line feed either.
        (r"(?:x(tok)|y)\s", Some(1)),
    ] {
        assert!(line_complete(re, group).unwrap(), "{re}");
    }
    for (re, group) in [
        // The whole match or an unknown group is the secret: no line feed at all.
        (provider, Some(0)),
        (provider, None),
        (r"\b(tok)\s", Some(0)),
        // A line feed before or inside the secret.
        (r"key\s*=\s*(tok)", Some(1)),
        (r"x(to\sk)", Some(1)),
        (r"(?:^|\s)(tok)(?:\s|$)", Some(1)),
        // More than one trailing byte that can be a line feed.
        (r"x(tok)\s\s", Some(1)),
        (r"x(tok)\s+", Some(1)),
        (r"x(tok)(?:\s;|$)", Some(1)),
        (r"x(tok);\s", Some(1)),
        // The regex is not a sequence the secret can be found in.
        (r"x(tok)\s|y", Some(1)),
    ] {
        assert!(!line_complete(re, group).unwrap(), "{re}");
    }
    assert!(line_complete("(", Some(1)).is_err());
}

/// The `meta:` block of rule `ident` in the committed `gitleaks.yar`.
fn rule_meta(ident: &str) -> String {
    let src =
        fs::read_to_string(repo().join("crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar"))
            .unwrap();
    let start = src
        .find(&format!("rule {ident} {{"))
        .unwrap_or_else(|| panic!("rule {ident}"));
    let rest = &src[start..];
    rest[..rest.find("condition:").unwrap()].to_string()
}

#[test]
fn line_complete_marks_rules_whose_matches_stay_on_one_line() {
    for ident in [
        "aws_access_token",
        "github_pat",
        "slack_bot_token",
        // A trailing delimiter that can be the line feed ending the line.
        "openai_api_key",
        "anthropic_api_key",
        "stripe_access_token",
    ] {
        assert!(rule_meta(ident).contains("line_complete = true"), "{ident}");
    }
    for ident in [
        "private_key",
        "kubernetes_secret_yaml",
        "pkcs12_file",
        "generic_api_key",
        // Whitespace before the secret.
        "adafruit_api_key",
        "azure_ad_client_secret",
        // The secret is the whole match, trailing delimiter included.
        "sentry_org_token",
    ] {
        assert!(!rule_meta(ident).contains("line_complete"), "{ident}");
    }
}

fn rule_count(config: &[u8]) -> usize {
    let v: toml::Value = toml::from_str(std::str::from_utf8(config).unwrap()).unwrap();
    v["rules"].as_array().unwrap().len()
}

fn convert_to_temp() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    convert_gitleaks(&pinned_config(), PINNED_TAG, d.path()).unwrap();
    d
}

#[test]
fn converted_ruleset_compiles() {
    let d = convert_to_temp();
    fs::copy(
        repo().join("crates/riskgrep-core/rulesets/secrets-core/ruleset.toml"),
        d.path().join("ruleset.toml"),
    )
    .unwrap();
    let rs = Ruleset::load_dir(d.path()).unwrap();
    assert_eq!(rs.id, "secrets_core");
    let cache = tempfile::tempdir().unwrap();
    let bundle = load_or_compile(&[&rs], cache.path()).unwrap();
    let public = bundle.rules.iter().filter(|r| !r.is_private()).count();
    assert_eq!(public, rule_count(&pinned_config()));
    let engine = riskgrep_core::engine::Engine::new(bundle).unwrap();
    engine.validate_all().unwrap();
}

#[test]
fn committed_output_is_current() {
    let d = convert_to_temp();
    let shipped = repo().join("crates/riskgrep-core/rulesets/secrets-core");
    for name in ["gitleaks.yar", "UPSTREAM.md"] {
        let want = fs::read(d.path().join(name)).unwrap();
        let got = fs::read(shipped.join(name)).unwrap();
        assert!(
            want == got,
            "{name} is stale: run cargo xtask convert-gitleaks"
        );
    }
    let list = |p: &Path| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = fs::read_dir(p.join("stopwords"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("secrets_core_")
            })
            .map(|p| {
                let n = p.file_name().unwrap().to_string_lossy().into_owned();
                (n, fs::read(&p).unwrap())
            })
            .collect();
        v.sort();
        v
    };
    let (want, got) = (list(d.path()), list(&shipped));
    let names = |v: &[(String, Vec<u8>)]| v.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
    assert_eq!(names(&want), names(&got), "stopword lists are stale");
    assert!(want == got, "stopword lists are stale");
}

#[test]
fn rerun_replaces_stale_stopword_lists() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join("stopwords")).unwrap();
    fs::write(d.path().join("stopwords/secrets_core_gone.txt"), "x\n").unwrap();
    fs::write(d.path().join("stopwords/other.txt"), "y\n").unwrap();
    convert_gitleaks(&pinned_config(), PINNED_TAG, d.path()).unwrap();
    assert!(!d.path().join("stopwords/secrets_core_gone.txt").exists());
    assert!(d.path().join("stopwords/other.txt").exists());
}

#[test]
fn unknown_config_key_is_an_error() {
    let cfg = b"title = \"t\"\nsurprise = 1\n[[rules]]\nid = \"a\"\nregex = 'x'\n";
    let d = tempfile::tempdir().unwrap();
    let err = convert_gitleaks(cfg, "v0", d.path()).unwrap_err();
    assert!(err.contains("surprise"), "{err}");
}

#[test]
fn go_literal_brace_is_escaped() {
    use xtask::go_to_rust;
    assert_eq!(go_to_rust(r"^\$(?:\d+|{\d+})$"), r"^\$(?:\d+|\{\d+})$");
    assert_eq!(go_to_rust(r"a{2,3}[{]\{x"), r"a{2,3}[{]\{x");
}

#[test]
fn defang_wraps_the_last_literal_character() {
    use xtask::defang;
    assert_eq!(defang("key-abc29t").as_deref(), Some("key-abc29[t]"));
    assert_eq!(defang(r"a\x60{2}").as_deref(), Some(r"[a]\x60{2}"));
    assert_eq!(defang(r"ab[cd]\d{3}").as_deref(), Some(r"a[b][cd]\d{3}"));
    assert_eq!(
        defang(r"(?i)ab(?P<n>[x])").as_deref(),
        Some(r"(?i)a[b](?P<n>[x])")
    );
    assert_eq!(defang(r"[a-z]+\w{4}"), None);
}

#[test]
fn digit_runs_are_kept_out_of_atom_selection() {
    // A run of 4 or more from a class of at most 11 digits or symbols is
    // wrapped with an alternative that cannot match a non-empty input.
    assert_eq!(steer_atoms(r"ntn_[0-9]{11}x"), r"ntn_(?:[0-9]{11}|$^)x");
    assert_eq!(
        steer_atoms(r"\b(\d{15,16}(\||%)[0-9a-z]{27,40})"),
        r"\b((?:\d{15,16}|$^)(\||%)[0-9a-z]{27,40})"
    );
    assert_eq!(
        steer_atoms(r"(?i)tw([0-9]{4,})"),
        r"(?i)tw((?:[0-9]{4,}|$^))"
    );
    // Short runs, letter classes, and large classes are left alone.
    for re in [
        r"ntn_[0-9]{3}x",
        r"key[a-f]{8}",
        r"key[a-z0-9]{32}",
        r"(?i)key[A-Fa-f0-9]{40}",
        r"key[0-9a-f]{4}",
    ] {
        assert_eq!(steer_atoms(re), re);
    }
    // Only when the regex cannot match the empty string: then `$^` (start
    // and end of the input at one position) never takes part in a match.
    assert_eq!(steer_atoms(r"(?:[0-9]{4})?"), r"(?:[0-9]{4})?");
}

#[test]
fn multi_line_regexes_are_not_steered() {
    // Under multi-line mode `$^` matches between a line end and the next
    // line start, so the wrapped alternative could match: steering is skipped
    // for any regex with an `m` flag group.
    for re in [
        r"(?m)ntn_[0-9]{11}x",
        r"(?im)ntn_[0-9]{11}x",
        r"(?:(?m)ntn_[0-9]{11})x",
        r"(?m:ntn_[0-9]{11})x",
        r"(?-m:ntn_[0-9]{11})x",
    ] {
        assert!(sets_multi_line(re), "{re}");
        assert_eq!(steer_atoms(re), re, "{re}");
    }
    assert!(!sets_multi_line(r"(?i)ntn_[0-9]{11}x"));
    assert!(!sets_multi_line(r"ntn_[0-9]{11}m"));
    assert!(!sets_multi_line("(?s)ntn_[0-9]{11}x"));
    assert_eq!(
        steer_atoms(r"(?s)ntn_[0-9]{11}x"),
        r"(?s)ntn_(?:[0-9]{11}|$^)x"
    );
}

#[test]
fn converter_records_a_skipped_steering() {
    let cfg = b"title = \"t\"\n[[rules]]\nid = \"multi\"\nregex = '(?m)^ab_[0-9]{11}$'\nkeywords = [\"ab_\"]\n\
[[rules]]\nid = \"plain\"\nregex = 'cd_[0-9]{11}'\nkeywords = [\"cd_\"]\n";
    let d = tempfile::tempdir().unwrap();
    convert_gitleaks(cfg, "v0", d.path()).unwrap();
    let yar = fs::read_to_string(d.path().join("gitleaks.yar")).unwrap();
    assert_eq!(yar.matches("|$^)").count(), 1, "only `plain` is steered");
    let md = fs::read_to_string(d.path().join("UPSTREAM.md")).unwrap();
    assert!(
        md.contains("| `multi` | atom steering not applied: the regex sets multi-line mode |"),
        "{md}"
    );
    assert!(!md.contains("| `plain` |"));
}

#[test]
fn generated_digit_runs_are_wrapped() {
    let d = convert_to_temp();
    let yar = fs::read_to_string(d.path().join("gitleaks.yar")).unwrap();
    let wrapped = yar.matches("|$^)").count();
    assert!(wrapped >= 7, "{wrapped} wrapped runs");
    for line in yar
        .lines()
        .filter(|l| l.trim_start().starts_with("$re = /"))
    {
        let re = &line.trim_start()["$re = /".len()..line.trim_start().len() - 1];
        let re = re.replace("\\/", "/");
        assert_eq!(steer_atoms(&re), re, "not idempotent: {line}");
    }
}

#[test]
fn no_generated_regex_matches_its_own_rule() {
    let d = convert_to_temp();
    let yar = fs::read_to_string(d.path().join("gitleaks.yar")).unwrap();
    for block in yar.split("\nrule ").skip(1) {
        let Some(line) = block
            .lines()
            .find(|l| l.trim_start().starts_with("span_regex = "))
        else {
            continue;
        };
        // Undo the YARA string escaping of the meta value.
        let quoted = line.trim_start().trim_start_matches("span_regex = ");
        let src = quoted[1..quoted.len() - 1]
            .replace("\\\\", "\u{0}")
            .replace("\\\"", "\"")
            .replace('\u{0}', "\\");
        let re = riskgrep_core::post::compile_regex(&src).unwrap();
        let name = block.split_whitespace().next().unwrap();
        assert!(
            !re.is_match(block.as_bytes()),
            "{name} matches its own source"
        );
    }
}
