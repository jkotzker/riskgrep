//! Converts gitleaks' rules (`config/gitleaks.toml`) into the `secrets_core`
//! YARA-X ruleset: `gitleaks.yar`, `stopwords/secrets_core_*.txt`, and
//! `UPSTREAM.md`.
//!
//! Each gitleaks rule becomes one YARA-X rule. The regex is rewritten with
//! [`lazy_to_greedy`] for detection (YARA-X refuses mixed greediness) and kept
//! verbatim as `span_regex`, which the `span` post-processor uses to recover
//! the exact secret. Entropy, stopwords, and secret-targeted allowlist regexes
//! become post-processors; path allowlists become `path` conditions. Anything
//! that cannot be expressed is listed in `UPSTREAM.md` under "Not translated".

use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Hir, HirKind};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// The gitleaks release the committed ruleset was generated from.
pub const PINNED_TAG: &str = "v8.30.1";

const NAMESPACE: &str = "secrets_core";
const GLOBAL_PATH_RULE: &str = "gitleaks_global_path_allowlist";
const GLOBAL_STOPWORDS: &str = "secrets_core_global";
/// A literal prefix at least this long makes a rule provider-specific.
const MIN_PREFIX: usize = 3;

/// Rules whose weight combines with a hand-written rule in `keystores.yar`:
/// `(gitleaks id, family, family_cap)`. A `.p12` file with a DER header hits
/// both `pkcs12-file` (name only) and `pkcs12_keystore`; the family keeps the
/// pair at the key-store weight.
const FAMILIES: &[(&str, &str, u32)] = &[("pkcs12-file", "pkcs12", 90)];

const GITLEAKS_LICENSE: &str = "MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
";

/// Removes the `?` that makes a quantifier lazy (`*?`, `+?`, `??`, `{m,n}?`).
/// Escaped characters, character classes (including POSIX classes), group
/// flags such as `(?i)`, and a `{` that does not start a valid repetition are
/// copied unchanged, so `\{3}?` and `[?]` keep their `?`.
pub fn lazy_to_greedy(re: &str) -> String {
    let c: Vec<char> = re.chars().collect();
    let mut out = String::with_capacity(re.len());
    let mut i = 0;
    let lazy_mark = |i: usize| c.get(i) == Some(&'?');
    while i < c.len() {
        match c[i] {
            '\\' => {
                out.extend(&c[i..(i + 2).min(c.len())]);
                i += 2;
            }
            '[' => i = copy_class(&c, i, &mut out),
            '(' if lazy_mark(i + 1) => {
                out.push_str("(?");
                i += 2;
            }
            q @ ('*' | '+' | '?') => {
                out.push(q);
                i += if lazy_mark(i + 1) { 2 } else { 1 };
            }
            '{' => match repetition_end(&c, i) {
                Some(end) => {
                    out.extend(&c[i..=end]);
                    i = end + if lazy_mark(end + 1) { 2 } else { 1 };
                }
                None => {
                    out.push('{');
                    i += 1;
                }
            },
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// Rewrites Go (RE2) syntax that Rust's `regex` rejects with the same
/// meaning: Go reads a `{` that does not start a repetition as a literal,
/// Rust requires it escaped. Everything else is copied unchanged.
pub fn go_to_rust(re: &str) -> String {
    let c: Vec<char> = re.chars().collect();
    let mut out = String::with_capacity(re.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\\' => {
                out.extend(&c[i..(i + 2).min(c.len())]);
                i += 2;
            }
            '[' => i = copy_class(&c, i, &mut out),
            '{' if repetition_end(&c, i).is_none() => {
                out.push_str("\\{");
                i += 1;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// Copies a character class starting at `c[start] == '['`; returns the index
/// after its closing `]`.
fn copy_class(c: &[char], start: usize, out: &mut String) -> usize {
    let mut i = start + 1;
    out.push('[');
    if c.get(i) == Some(&'^') {
        out.push('^');
        i += 1;
    }
    if c.get(i) == Some(&']') {
        out.push(']');
        i += 1;
    }
    while i < c.len() {
        match c[i] {
            '\\' => {
                out.extend(&c[i..(i + 2).min(c.len())]);
                i += 2;
            }
            '[' if c.get(i + 1) == Some(&':') => {
                let close = (i + 2..c.len().saturating_sub(1))
                    .find(|&j| c[j] == ':' && c[j + 1] == ']')
                    .map_or(c.len(), |j| j + 2);
                out.extend(&c[i..close]);
                i = close;
            }
            ']' => {
                out.push(']');
                return i + 1;
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    i
}

/// If `c[start] == '{'` opens `{n}`, `{n,}`, or `{n,m}`, the index of `}`.
fn repetition_end(c: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let digits = |i: &mut usize| {
        let s = *i;
        while c.get(*i).is_some_and(char::is_ascii_digit) {
            *i += 1;
        }
        *i > s
    };
    if !digits(&mut i) {
        return None;
    }
    if c.get(i) == Some(&',') {
        i += 1;
        digits(&mut i);
    }
    (c.get(i) == Some(&'}')).then_some(i)
}

// --- gitleaks configuration ------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[allow(dead_code)]
    title: Option<String>,
    #[serde(rename = "minVersion")]
    #[allow(dead_code)]
    min_version: Option<String>,
    allowlist: Option<Allowlist>,
    #[serde(default)]
    allowlists: Vec<Allowlist>,
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    #[allow(dead_code)]
    description: Option<String>,
    regex: Option<String>,
    path: Option<String>,
    #[serde(rename = "secretGroup")]
    secret_group: Option<usize>,
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tags: Vec<String>,
    allowlist: Option<Allowlist>,
    #[serde(default)]
    allowlists: Vec<Allowlist>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    #[allow(dead_code)]
    description: Option<String>,
    condition: Option<String>,
    #[serde(rename = "regexTarget")]
    regex_target: Option<String>,
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
}

/// Applies [`go_to_rust`] to every regex in the configuration.
fn normalise(cfg: &mut Config) {
    fn list(a: &mut Allowlist) {
        for r in a.regexes.iter_mut().chain(a.paths.iter_mut()) {
            *r = go_to_rust(r);
        }
    }
    cfg.allowlist
        .iter_mut()
        .chain(cfg.allowlists.iter_mut())
        .for_each(list);
    for r in &mut cfg.rules {
        for re in r.regex.iter_mut().chain(r.path.iter_mut()) {
            *re = go_to_rust(re);
        }
        r.allowlist
            .iter_mut()
            .chain(r.allowlists.iter_mut())
            .for_each(list);
    }
}

/// The parts of allowlists this ruleset can express.
#[derive(Default)]
struct Allow {
    paths: Vec<String>,
    secret_regexes: Vec<String>,
    stopwords: Vec<String>,
}

/// Splits allowlists into translatable parts; the rest goes to `skipped`.
fn translate_allowlists<'a>(
    lists: impl Iterator<Item = &'a Allowlist>,
    owner: &str,
    skipped: &mut Vec<(String, String)>,
) -> Result<Allow, String> {
    let mut a = Allow::default();
    for (n, l) in lists.enumerate() {
        let mut skip = |why: String| skipped.push((owner.to_string(), why));
        let and = match l.condition.as_deref() {
            None | Some("OR") => false,
            Some("AND") => true,
            Some(o) => return Err(format!("{owner}: unknown allowlist condition `{o}`")),
        };
        let target = l.regex_target.as_deref().unwrap_or("secret");
        if !matches!(target, "secret" | "match" | "line") {
            return Err(format!("{owner}: unknown regexTarget `{target}`"));
        }
        if !l.commits.is_empty() {
            skip(format!(
                "allowlist {n}: {} commit hashes (not applicable to file scans)",
                l.commits.len()
            ));
        }
        let kinds = [
            !l.paths.is_empty(),
            !l.regexes.is_empty(),
            !l.stopwords.is_empty(),
        ];
        if and && kinds.iter().filter(|k| **k).count() > 1 {
            skip(format!(
                "allowlist {n}: condition AND over {} paths, {} regexes (target {target}), {} stopwords",
                l.paths.len(),
                l.regexes.len(),
                l.stopwords.len()
            ));
            continue;
        }
        a.paths.extend(l.paths.iter().cloned());
        if target == "secret" {
            a.secret_regexes.extend(l.regexes.iter().cloned());
        } else if !l.regexes.is_empty() {
            skip(format!(
                "allowlist {n}: {} regexes with regexTarget = \"{target}\"",
                l.regexes.len()
            ));
        }
        a.stopwords.extend(l.stopwords.iter().cloned());
    }
    Ok(a)
}

// --- rule analysis -----------------------------------------------------------

/// Compiles with the settings of the core's post-processors.
fn check_regex(owner: &str, what: &str, src: &str) -> Result<regex::bytes::Regex, String> {
    regex::bytes::RegexBuilder::new(src)
        .unicode(false)
        .size_limit(1 << 28)
        .build()
        .map_err(|e| format!("{owner}: {what} does not compile: {e}"))
}

fn parse_hir(owner: &str, src: &str) -> Result<Hir, String> {
    regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(src)
        .map_err(|e| format!("{owner}: regex does not parse: {e}"))
}

fn find_capture(h: &Hir, index: u32) -> Option<&Hir> {
    match h.kind() {
        HirKind::Capture(c) if c.index == index => Some(&c.sub),
        HirKind::Capture(c) => find_capture(&c.sub, index),
        HirKind::Repetition(r) => find_capture(&r.sub, index),
        HirKind::Concat(v) | HirKind::Alternation(v) => {
            v.iter().find_map(|s| find_capture(s, index))
        }
        _ => None,
    }
}

/// True when capture group `index` takes part in every match of `h`.
fn always_participates(h: &Hir, index: u32) -> bool {
    match h.kind() {
        HirKind::Capture(c) => c.index == index || always_participates(&c.sub, index),
        HirKind::Concat(v) => v.iter().any(|s| always_participates(s, index)),
        HirKind::Alternation(v) => v.iter().all(|s| always_participates(s, index)),
        HirKind::Repetition(r) => r.min >= 1 && always_participates(&r.sub, index),
        _ => false,
    }
}

/// True when every match of the secret group starts with a literal of at
/// least [`MIN_PREFIX`] bytes (for example `ghp_` or `AKIA`).
fn has_fixed_prefix(hir: &Hir, group: usize) -> bool {
    let sub = if group == 0 {
        Some(hir)
    } else {
        find_capture(hir, group as u32)
    };
    let Some(sub) = sub else { return false };
    let seq = Extractor::new().kind(ExtractKind::Prefix).extract(sub);
    seq.is_finite() && seq.min_literal_len().is_some_and(|n| n >= MIN_PREFIX)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    FixedPrefix,
    PrivateKey,
    Generic,
    Contextual,
}

impl Class {
    fn weight(self) -> u32 {
        match self {
            Class::FixedPrefix | Class::PrivateKey => 95,
            Class::Generic => 50,
            Class::Contextual => 80,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Class::FixedPrefix => "fixed provider prefix",
            Class::PrivateKey => "private key",
            Class::Generic => "generic",
            Class::Contextual => "provider context",
        }
    }
}

// --- YARA source ------------------------------------------------------------

const YARA_KEYWORDS: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "base64",
    "base64wide",
    "condition",
    "contains",
    "defined",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "icontains",
    "iendswith",
    "iequals",
    "import",
    "in",
    "include",
    "istartswith",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "wide",
    "with",
    "xor",
];

/// The gitleaks id with `-` replaced by `_`, and `_` prepended when the id
/// starts with a digit (`1password-secret-key` becomes `_1password_secret_key`).
fn identifier(id: &str) -> Result<String, String> {
    let mut s = id.replace('-', "_");
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    let ok = s
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !YARA_KEYWORDS.contains(&s.as_str())
        && s.len() <= 128;
    if ok {
        Ok(s)
    } else {
        Err(format!("rule id `{id}` does not map to a YARA identifier"))
    }
}

/// A YARA text string literal.
fn yara_str(s: &str) -> String {
    let mut out = String::from("\"");
    for b in s.bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => write!(out, "\\x{b:02x}").unwrap(),
        }
    }
    out.push('"');
    out
}

/// A YARA regex literal: `/.../` with unescaped `/` escaped.
fn yara_regex(re: &str) -> Result<String, String> {
    if re.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
        return Err("regex contains a non-printable or non-ASCII byte".into());
    }
    let mut out = String::from("/");
    let mut esc = false;
    for ch in re.chars() {
        if esc {
            out.push(ch);
            esc = false;
        } else if ch == '\\' {
            out.push(ch);
            esc = true;
        } else if ch == '/' {
            out.push_str("\\/");
        } else {
            out.push(ch);
        }
    }
    out.push('/');
    Ok(out)
}

fn alternation(regexes: &[String]) -> String {
    regexes
        .iter()
        .map(|r| format!("(?:{r})"))
        .collect::<Vec<_>>()
        .join("|")
}

fn number(x: f64) -> String {
    if x.fract() == 0.0 {
        format!("{}", x as i64)
    } else {
        format!("{x}")
    }
}

fn stopword_file(words: &[String]) -> String {
    let mut seen = BTreeSet::new();
    let mut out = String::new();
    for w in words {
        let w = w.trim();
        if !w.is_empty() && seen.insert(w.to_string()) {
            out.push_str(w);
            out.push('\n');
        }
    }
    out
}

struct Generated {
    yar: String,
    stopwords: Vec<(String, String)>,
    upstream: String,
}

fn generate(config: &[u8], tag: &str) -> Result<Generated, String> {
    let text = std::str::from_utf8(config).map_err(|e| format!("config is not UTF-8: {e}"))?;
    let mut cfg: Config = toml::from_str(text).map_err(|e| format!("gitleaks config: {e}"))?;
    normalise(&mut cfg);
    let sha = Sha256::digest(config)
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        });

    let mut skipped: Vec<(String, String)> = Vec::new();
    let global = translate_allowlists(
        cfg.allowlist.iter().chain(&cfg.allowlists),
        "(global)",
        &mut skipped,
    )?;
    for r in &global.secret_regexes {
        check_regex("(global)", "allowlist regex", r)?;
    }
    for p in &global.paths {
        check_regex("(global)", "allowlist path", p)?;
    }

    let mut yar = String::new();
    writeln!(
        yar,
        "// Generated by `cargo xtask convert-gitleaks` from gitleaks {tag}\n\
         // (config/gitleaks.toml, sha256 {sha}). Do not edit: regenerate.\n\
         // Derived from gitleaks, MIT licence; see UPSTREAM.md.\n\
         //\n\
         // Weights by class: fixed provider prefix 95, private key 95,\n\
         // provider context 80, generic 50."
    )
    .unwrap();

    let mut stopwords: Vec<(String, String)> = Vec::new();
    if !global.stopwords.is_empty() {
        stopwords.push((GLOBAL_STOPWORDS.into(), stopword_file(&global.stopwords)));
    }
    let global_paths = !global.paths.is_empty();
    if global_paths {
        writeln!(
            yar,
            "\n// gitleaks' global path allowlist; every rule below excludes these paths.\n\
             private rule {GLOBAL_PATH_RULE} {{\n  meta:\n    category = \"secret\"\n    weight = 0\n  condition:"
        )
        .unwrap();
        let conds: Vec<String> = global
            .paths
            .iter()
            .map(|p| Ok(format!("    path matches {}", yara_regex(p)?)))
            .collect::<Result<_, String>>()?;
        writeln!(yar, "{}\n}}", conds.join(" or\n")).unwrap();
    }

    let mut idents = BTreeSet::new();
    let mut classes: Vec<(Class, String)> = Vec::new();
    for r in &cfg.rules {
        let ident = identifier(&r.id)?;
        if ident == GLOBAL_PATH_RULE || !idents.insert(ident.clone()) {
            return Err(format!("duplicate rule identifier `{ident}`"));
        }
        let list_name = format!("{NAMESPACE}_{ident}");
        if list_name == GLOBAL_STOPWORDS {
            return Err(format!(
                "rule `{}` collides with the global stopword list",
                r.id
            ));
        }
        let allow =
            translate_allowlists(r.allowlist.iter().chain(&r.allowlists), &r.id, &mut skipped)?;

        let mut group = 0usize;
        let mut hir = None;
        if let Some(re) = &r.regex {
            let compiled = check_regex(&r.id, "regex", re)?;
            let explicit = compiled.captures_len() - 1;
            group = match r.secret_group {
                Some(g) if g > explicit => {
                    return Err(format!("{}: secretGroup {g} > {explicit} groups", r.id))
                }
                Some(g) => g,
                None => usize::from(explicit > 0),
            };
            let parsed = parse_hir(&r.id, re)?;
            let group1_nonempty = find_capture(&parsed, 1)
                .is_some_and(|g| g.properties().minimum_len().is_some_and(|n| n > 0))
                && always_participates(&parsed, 1);
            if r.secret_group.is_none() && explicit > 1 && !group1_nonempty {
                skipped.push((
                    r.id.clone(),
                    format!(
                        "secret group: gitleaks takes the first non-empty of {explicit} groups; \
                         the span uses group 1, which can be empty or absent, so those matches are dropped"
                    ),
                ));
            }
            hir = Some(parsed);
        }
        for p in allow.paths.iter().chain(&r.path) {
            check_regex(&r.id, "path regex", p)?;
        }
        for re in &allow.secret_regexes {
            check_regex(&r.id, "allowlist regex", re)?;
        }

        let class = if matches!(r.id.as_str(), "private-key" | "pkcs12-file") {
            Class::PrivateKey
        } else if r.id.starts_with("generic") {
            Class::Generic
        } else if hir.as_ref().is_some_and(|h| has_fixed_prefix(h, group)) {
            Class::FixedPrefix
        } else {
            Class::Contextual
        };
        classes.push((class, r.id.clone()));

        // meta
        let mut meta: Vec<String> = vec![
            "category = \"secret\"".into(),
            format!("weight = {}", class.weight()),
        ];
        if let Some((_, fam, cap)) = FAMILIES.iter().find(|(id, _, _)| *id == r.id) {
            meta.push(format!("family = {}", yara_str(fam)));
            meta.push(format!("family_cap = {cap}"));
        }
        if let Some(re) = &r.regex {
            let mut post = vec!["span"];
            let entropy = r.entropy.filter(|e| *e != 0.0);
            if entropy.is_some() {
                post.push("entropy");
            }
            let words: Vec<String> = allow
                .stopwords
                .iter()
                .chain(&global.stopwords)
                .cloned()
                .collect();
            let list = if !allow.stopwords.is_empty() {
                stopwords.push((list_name.clone(), stopword_file(&words)));
                Some(list_name.clone())
            } else if !global.stopwords.is_empty() {
                Some(GLOBAL_STOPWORDS.to_string())
            } else {
                None
            };
            if list.is_some() {
                post.push("stopwords");
            }
            let allow_res: Vec<String> = allow
                .secret_regexes
                .iter()
                .chain(&global.secret_regexes)
                .cloned()
                .collect();
            if !allow_res.is_empty() {
                post.push("allow_regex");
            }
            meta.push(format!("post = {}", yara_str(&post.join(","))));
            meta.push(format!("span_regex = {}", yara_str(re)));
            meta.push(format!("secret_group = {group}"));
            if let Some(e) = entropy {
                meta.push(format!("min_entropy = {}", number(e)));
            }
            if let Some(l) = list {
                meta.push(format!("stopwords = {}", yara_str(&l)));
            }
            if !allow_res.is_empty() {
                let alt = alternation(&allow_res);
                check_regex(&r.id, "combined allowlist regex", &alt)?;
                meta.push(format!("allow_regex = {}", yara_str(&alt)));
            }
        }

        // strings
        let mut strings: Vec<String> = Vec::new();
        if let Some(re) = &r.regex {
            let y = yara_regex(&lazy_to_greedy(re)).map_err(|e| format!("{}: {e}", r.id))?;
            strings.push(format!("$re = {y}"));
        }
        let mut kws = BTreeSet::new();
        let keywords: Vec<&String> = r
            .keywords
            .iter()
            .filter(|k| !k.is_empty() && kws.insert(k.to_ascii_lowercase()))
            .collect();
        for (j, k) in keywords.iter().enumerate() {
            strings.push(format!("$kw{j} = {} nocase", yara_str(k)));
        }

        // condition
        let mut cond: Vec<String> = Vec::new();
        if let Some(p) = &r.path {
            cond.push(format!("path matches {}", yara_regex(p)?));
        }
        if !keywords.is_empty() {
            cond.push("any of ($kw*)".into());
        }
        if r.regex.is_some() {
            cond.push("$re".into());
        }
        if r.regex.is_none() && r.path.is_none() {
            return Err(format!("{}: rule has neither regex nor path", r.id));
        }
        for p in &allow.paths {
            cond.push(format!("not path matches {}", yara_regex(p)?));
        }
        if global_paths {
            cond.push(format!("not {GLOBAL_PATH_RULE}"));
        }

        writeln!(yar, "\n// {}: {} ({})", r.id, class.label(), class.weight()).unwrap();
        writeln!(yar, "rule {ident} {{\n  meta:").unwrap();
        for m in &meta {
            writeln!(yar, "    {m}").unwrap();
        }
        if !strings.is_empty() {
            writeln!(yar, "  strings:").unwrap();
            for s in &strings {
                writeln!(yar, "    {s}").unwrap();
            }
        }
        writeln!(yar, "  condition:\n    {}\n}}", cond.join(" and\n    ")).unwrap();
    }

    let upstream = upstream_md(tag, &sha, &cfg, &classes, &skipped);
    Ok(Generated {
        yar,
        stopwords,
        upstream,
    })
}

fn upstream_md(
    tag: &str,
    sha: &str,
    cfg: &Config,
    classes: &[(Class, String)],
    skipped: &[(String, String)],
) -> String {
    let mut s = String::new();
    let url = format!("https://github.com/gitleaks/gitleaks/blob/{tag}/config/gitleaks.toml");
    writeln!(
        s,
        "# Upstream: gitleaks\n\n\
         This file is generated by `cargo xtask convert-gitleaks`; do not edit it.\n\n\
         `gitleaks.yar` and `stopwords/secrets_core_*.txt` are generated from gitleaks' default configuration. \
         `keystores.yar` and `ruleset.toml` are written by hand.\n\n\
         | | |\n|---|---|\n\
         | Release | `{tag}` |\n\
         | Source | <{url}> |\n\
         | Raw file | <https://raw.githubusercontent.com/gitleaks/gitleaks/{tag}/config/gitleaks.toml> |\n\
         | SHA-256 | `{sha}` |\n\
         | Rules | {} |\n\n\
         The configuration is kept at `xtask/upstream/gitleaks.toml`. To regenerate, replace that file with the new release's `config/gitleaks.toml`, update `PINNED_TAG` in `xtask/src/convert.rs`, and run:\n\n\
         ```sh\n\
         cargo xtask convert-gitleaks --config xtask/upstream/gitleaks.toml --tag {tag} --out rulesets/secrets-core\n\
         ```\n",
        cfg.rules.len()
    )
    .unwrap();

    writeln!(s, "## Translation\n").unwrap();
    writeln!(
        s,
        "- Each rule becomes one YARA-X rule named after the gitleaks id with `-` replaced by `_` (and `_` prepended to an id starting with a digit).\n\
         - Regexes are read with Go (RE2) syntax: a `{{` that does not start a repetition is escaped for Rust and YARA-X; nothing else changes.\n\
         - The regex is the anchor `$re`, with lazy quantifiers rewritten as greedy (YARA-X refuses mixed greediness). The original regex is kept as `span_regex`; the `span` post-processor re-runs it inside each match to find the secret (`secretGroup`, else the first capture group, else the whole match).\n\
         - Keywords are `nocase` literals `$kw0..n`; the rule needs one of them and `$re`.\n\
         - `entropy` becomes the `entropy` post-processor on the secret. gitleaks drops a secret whose entropy is at most the threshold; the post-processor drops one below it.\n\
         - Allowlist stopwords become `stopwords/secrets_core_<rule>.txt` (rule and global stopwords) or `stopwords/secrets_core_global.txt` (global only).\n\
         - Allowlist regexes that target the secret become one `allow_regex` alternation (rule and global regexes).\n\
         - Allowlist paths become `not path matches` conditions; the global ones are the private rule `{GLOBAL_PATH_RULE}`.\n\
         - A rule `path` becomes a `path matches` condition; a rule with only a path yields one evidence item.\n"
    )
    .unwrap();

    writeln!(s, "## Weights\n").unwrap();
    for class in [
        Class::FixedPrefix,
        Class::PrivateKey,
        Class::Contextual,
        Class::Generic,
    ] {
        let ids: Vec<&str> = classes
            .iter()
            .filter(|(c, _)| *c == class)
            .map(|(_, id)| id.as_str())
            .collect();
        writeln!(
            s,
            "- {} ({}): {} rule{}.",
            class.label(),
            class.weight(),
            ids.len(),
            if ids.len() == 1 { "" } else { "s" }
        )
        .unwrap();
    }
    writeln!(
        s,
        "\nA rule is \"fixed provider prefix\" when every match of its secret starts with a literal of at least {MIN_PREFIX} bytes (for example `ghp_`). \
         `private-key` and `pkcs12-file` are private keys; ids starting `generic` are generic; the rest are \"provider context\" (a provider name near a value). \
         `pkcs12-file` is in family `pkcs12` with cap 90, shared with `pkcs12_keystore` in `keystores.yar`.\n"
    )
    .unwrap();

    writeln!(s, "## Not translated\n").unwrap();
    if skipped.is_empty() {
        writeln!(s, "Nothing.\n").unwrap();
    } else {
        writeln!(s, "| Rule | What |\n|---|---|").unwrap();
        for (id, why) in skipped {
            writeln!(s, "| `{id}` | {why} |").unwrap();
        }
        writeln!(s).unwrap();
    }

    writeln!(s, "## Licence\n\n```text\n{GITLEAKS_LICENSE}```").unwrap();
    s
}

/// Writes `gitleaks.yar`, `UPSTREAM.md`, and `stopwords/secrets_core_*.txt`
/// into `out`, replacing any stopword lists a previous run left there.
pub fn convert_gitleaks(config: &[u8], tag: &str, out: &Path) -> Result<(), String> {
    let g = generate(config, tag)?;
    let io = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let sw = out.join("stopwords");
    fs::create_dir_all(&sw).map_err(|e| io(&sw, e))?;
    for entry in fs::read_dir(&sw).map_err(|e| io(&sw, e))? {
        let p = entry.map_err(|e| io(&sw, e))?.path();
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
        if name.is_some_and(|n| n.starts_with(&format!("{NAMESPACE}_")) && n.ends_with(".txt")) {
            fs::remove_file(&p).map_err(|e| io(&p, e))?;
        }
    }
    for (name, text) in &g.stopwords {
        let p = sw.join(format!("{name}.txt"));
        fs::write(&p, text).map_err(|e| io(&p, e))?;
    }
    let yar = out.join("gitleaks.yar");
    fs::write(&yar, &g.yar).map_err(|e| io(&yar, e))?;
    let md = out.join("UPSTREAM.md");
    fs::write(&md, &g.upstream).map_err(|e| io(&md, e))?;
    Ok(())
}
