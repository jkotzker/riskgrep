use riskgrep_core::meta::{MetaError, PostSpec, RuleMeta};

fn parse(meta: &str) -> Result<RuleMeta, MetaError> {
    let src = format!("rule r1 {{ meta:\n{meta}\n strings: $a = \"abc\" condition: $a }}");
    let rules = yara_x::compile(src.as_str()).unwrap();
    let rule = rules.iter().next().unwrap();
    RuleMeta::from_yara(&rule)
}

#[test]
fn meta_parses_all_keys() {
    let m = parse(
        r#"category = "secrets"
weight = 42
tiers = "1:10,3:30"
family = "aws"
family_cap = 80
post = "span, entropy, stopwords, allow_regex, npy_header, npz_members, safetensors_header"
span_regex = "k=(.+)"
secret_group = 1
min_entropy = 3.5
stopwords = "common"
allow_regex = "^x"
min_dim = 128
name_regex = "weight$""#,
    )
    .unwrap();
    assert_eq!(m.category.0, "secrets");
    assert_eq!(m.weight, 42.0);
    assert!(m.tiers.is_some());
    assert_eq!(m.family.as_deref(), Some("aws"));
    assert_eq!(m.family_cap, Some(80.0));
    assert_eq!(
        m.post,
        vec![
            PostSpec::Span {
                regex: "k=(.+)".into(),
                group: 1
            },
            PostSpec::Entropy { min: 3.5 },
            PostSpec::Stopwords {
                list: "common".into()
            },
            PostSpec::AllowRegex { regex: "^x".into() },
            PostSpec::NpyHeader { min_dim: 128 },
            PostSpec::NpzMembers { min_dim: 128 },
            PostSpec::SafetensorsHeader {
                min_dim: 128,
                name_regex: Some("weight$".into())
            },
        ]
    );
}

#[test]
fn meta_float_weight_and_defaults() {
    let m =
        parse("category = \"pii\"\nweight = -12.5\npost = \"span\"\nspan_regex = \"a\"").unwrap();
    assert_eq!(m.weight, -12.5);
    assert_eq!(
        m.post,
        vec![PostSpec::Span {
            regex: "a".into(),
            group: 0
        }]
    );
    assert!(m.tiers.is_none() && m.family.is_none() && m.family_cap.is_none());
}

#[test]
fn meta_rejects_missing_category() {
    let e = parse("weight = 5").unwrap_err();
    assert!(
        e.to_string().contains("r1") && e.to_string().contains("category"),
        "{e}"
    );
}

#[test]
fn meta_rejects_weight_101() {
    let e = parse("category = \"x\"\nweight = 101").unwrap_err();
    assert!(e.to_string().contains("weight"), "{e}");
}

#[test]
fn meta_rejects_unknown_post() {
    let e = parse("category = \"x\"\nweight = 1\npost = \"bogus\"").unwrap_err();
    assert!(e.to_string().contains("bogus"), "{e}");
}

#[test]
fn meta_rejects_missing_processor_argument() {
    let e = parse("category = \"x\"\nweight = 1\npost = \"entropy\"").unwrap_err();
    assert!(
        e.to_string().contains("min_entropy") && e.to_string().contains("r1"),
        "{e}"
    );
}

#[test]
fn meta_rejects_bad_family_cap_and_tiers() {
    assert!(parse("category = \"x\"\nweight = 1\nfamily_cap = 101").is_err());
    assert!(parse("category = \"x\"\nweight = 1\ntiers = \"nope\"").is_err());
}

#[test]
fn meta_string_with_escapes_is_accepted() {
    // YARA-X stores a string literal containing escapes as bytes.
    let m = parse(
        r#"category = "secret"
weight = 50
post = "span,allow_regex"
span_regex = "\\bk=\"(\\w+)\""
allow_regex = "^\\d+$""#,
    )
    .unwrap();
    assert_eq!(
        m.post,
        vec![
            PostSpec::Span {
                regex: r#"\bk="(\w+)""#.into(),
                group: 0
            },
            PostSpec::AllowRegex {
                regex: r"^\d+$".into()
            },
        ]
    );
}

#[test]
fn meta_rejects_non_utf8_string() {
    let e = parse("category = \"secret\"\nweight = 50\nfamily = \"\\xff\"").unwrap_err();
    assert!(e.0.contains("`family` must be a string"), "{e}");
}
