//! The masked view (`riskgrep_core::show`). Secrets are generated at run
//! time; no assertion prints the masked text or a secret: failures report
//! counts and positions only.

use riskgrep_core::config::{Config, ShowConfig};
use riskgrep_core::show::{
    mask, parse_lines, select_lines, show_file, Marker, RefusalKind, ShowOptions, Shown, Span,
    FIXED_MARKER,
};
use riskgrep_core::synth::{self, FloatStyle};
use riskgrep_core::{RiskGrep, TargetStatus};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tempfile::TempDir;

fn cache() -> PathBuf {
    static D: OnceLock<TempDir> = OnceLock::new();
    D.get_or_init(|| tempfile::tempdir().unwrap())
        .path()
        .to_path_buf()
}

fn show(path: &Path, opts: &ShowOptions) -> Result<Shown, String> {
    show_file(&ShowConfig::default(), path, opts, Some(cache())).map_err(|r| r.reason)
}

fn masked(path: &Path) -> (Vec<u8>, usize) {
    match show(path, &ShowOptions::default()) {
        Ok(Shown::Masked { text, masks, .. }) => (text, masks),
        Ok(Shown::Summary(_)) => panic!("expected a masked view, got a summary"),
        Err(r) => panic!("refused: {r}"),
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn lf(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.path().join(name);
    fs::write(&p, bytes).unwrap();
    p
}

/// The file masked by hand from the evidence a default scan reports: each
/// merged span replaced by the fixed marker and the line feeds it held.
fn expected_from_evidence(path: &Path) -> Vec<u8> {
    let mut rg = RiskGrep::with_cache_dir(Config::default(), None, Some(cache())).unwrap();
    let r = rg.scan_paths(&[path.to_path_buf()]);
    let t = &r.targets[0];
    assert_eq!(t.status, TargetStatus::Scanned);
    let mut spans: Vec<(usize, usize)> = t
        .evidence
        .iter()
        .flat_map(|e| e.locations.iter())
        .map(|l| (l.start as usize, l.end as usize))
        .collect();
    assert!(!spans.is_empty(), "the fixture must have findings");
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (a, b) in spans {
        match merged.last_mut() {
            Some(m) if a <= m.1 => m.1 = m.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    let src = fs::read(path).unwrap();
    let mut out = Vec::new();
    let mut pos = 0;
    for (a, b) in merged {
        out.extend_from_slice(&src[pos..a]);
        out.extend_from_slice(FIXED_MARKER.as_bytes());
        out.resize(out.len() + lf(&src[a..b]), b'\n');
        pos = b;
    }
    out.extend_from_slice(&src[pos..]);
    out
}

#[test]
fn masks_exactly_the_evidence_spans() {
    let dir = tempfile::tempdir().unwrap();
    let aws = synth::fake_secret("aws_access_key", 1);
    let gh = synth::fake_secret("github_pat", 2);
    let pem = synth::fake_secret("pem_private_key", 3);
    let text = format!(
        "# settings\nregion = \"us-east-1\"\naws_id = \"{aws}\"\ntoken: {gh}\n\n{pem}\nafter = 1\n"
    );
    let p = write(&dir, "settings.conf", text.as_bytes());
    let (out, masks) = masked(&p);
    for s in [&aws, &gh] {
        assert!(!contains(&out, s.as_bytes()), "a secret is in the output");
    }
    for line in pem.lines().filter(|l| !l.starts_with("-----")) {
        assert!(
            !contains(&out, line.as_bytes()),
            "a key line is in the output"
        );
    }
    assert!(masks >= 3, "masks: {masks}");
    assert_eq!(lf(&out), lf(text.as_bytes()), "line count changed");
    assert!(
        out == expected_from_evidence(&p),
        "output differs from the evidence spans masked"
    );
    assert!(contains(&out, b"region = \"us-east-1\"\n"));
    assert!(out.ends_with(b"after = 1\n"));
}

#[test]
fn spans_at_the_start_and_end_of_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 7);
    let p = write(&dir, "only.txt", key.as_bytes());
    let (out, masks) = masked(&p);
    assert_eq!((out.as_slice(), masks), (FIXED_MARKER.as_bytes(), 1));

    let a = synth::fake_secret("github_pat", 8);
    let b = synth::fake_secret("github_pat", 9);
    let p = write(&dir, "ends.txt", format!("{a} middle {b}").as_bytes());
    let (out, masks) = masked(&p);
    assert_eq!(masks, 2);
    assert!(out == format!("{FIXED_MARKER} middle {FIXED_MARKER}").into_bytes());
}

#[test]
fn multi_byte_text_around_a_span_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 11);
    let text = format!("café = «{key}» 🔑\nnaïve ✓\n");
    let p = write(&dir, "utf8.txt", text.as_bytes());
    let (out, _) = masked(&p);
    let out = String::from_utf8(out).expect("valid UTF-8");
    assert!(!out.contains(&key));
    assert_eq!(out, format!("café = «{FIXED_MARKER}» 🔑\nnaïve ✓\n"));
}

#[test]
fn utf16_text_is_masked_and_shown_as_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("aws_access_key", 12);
    let text = format!("first line\naws = \"{key}\"\nlast ü\n");
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    let p = write(&dir, "wide.txt", &bytes);
    let (out, masks) = masked(&p);
    let out = String::from_utf8(out).expect("UTF-8 output");
    assert!(masks >= 1);
    assert!(!out.contains(&key));
    let wide: Vec<u8> = key.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!contains(out.as_bytes(), &wide));
    assert!(out.starts_with("first line\n"), "BOM or first line wrong");
    assert!(out.ends_with("\"\nlast ü\n"));
    assert_eq!(out.lines().count(), 3);
}

#[test]
fn overlapping_findings_become_one_marker_naming_both_rules() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 13);
    let p = write(
        &dir,
        "both.env",
        format!("api_key = \"{key}\"\n").as_bytes(),
    );
    let opts = ShowOptions {
        marker: Marker::RuleIds,
        lines: None,
    };
    let Ok(Shown::Masked { text, .. }) = show(&p, &opts) else {
        panic!("not masked");
    };
    assert!(!contains(&text, key.as_bytes()));
    assert_eq!(count(&text, b"<redacted"), 1, "one marker for nested spans");
    let line = String::from_utf8(text).unwrap();
    assert!(line.contains("secrets_core:github_pat"), "rule ids missing");
    assert!(
        line.contains("secrets_core:generic_api_key"),
        "rule ids missing"
    );
}

#[test]
fn every_finding_is_masked_regardless_of_score_or_category() {
    // A secret-flagged file whose float list only scores biometric 40: the
    // list is masked too.
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("aws_access_key", 14);
    let floats = synth::printed_floats(100, FloatStyle::PythonList);
    let p = write(
        &dir,
        "train.py",
        format!("KEY = \"{key}\"\nexpected = {floats}\n").as_bytes(),
    );
    let (out, masks) = masked(&p);
    assert!(masks >= 2, "masks: {masks}");
    assert!(!contains(&out, key.as_bytes()));
    assert!(!contains(&out, floats.as_bytes()));
}

#[test]
fn line_selection_counts_lines_after_masking() {
    let dir = tempfile::tempdir().unwrap();
    let pem = synth::fake_secret("pem_private_key", 15);
    let text = format!("a\n{pem}\nz1\nz2\n");
    let p = write(&dir, "key.pem", text.as_bytes());
    let total = text.lines().count() as u64;
    let opts = ShowOptions {
        marker: Marker::Fixed,
        lines: Some((total - 1, total)),
    };
    let Ok(Shown::Masked { text: out, .. }) = show(&p, &opts) else {
        panic!("not masked");
    };
    assert!(out == b"z1\nz2\n");
}

#[test]
fn a_file_over_the_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "big.txt", &vec![b'a'; 2048]);
    let cfg = ShowConfig {
        max_bytes: 1024,
        ..ShowConfig::default()
    };
    let r = show_file(&cfg, &p, &ShowOptions::default(), Some(cache())).unwrap_err();
    assert!(r.reason.contains("max_bytes"), "{}", r.reason);
    assert_eq!(r.kind, RefusalKind::File);
}

#[test]
fn a_text_file_over_the_hook_limit_is_scanned_whole() {
    // 9 MiB, past the hook's 8 MiB text limit: keys in the middle, which a
    // sampled scan never reads, are masked.
    let dir = tempfile::tempdir().unwrap();
    let mut text = synth::source_text(9 << 20, 16);
    let key = synth::fake_secret("github_pat", 17);
    let mid = text.len() / 2;
    let mid = (mid..text.len())
        .find(|&i| text.as_bytes()[i] == b'\n')
        .unwrap()
        + 1;
    text.insert_str(mid, &format!("token = {key}\n"));
    let p = write(&dir, "huge.txt", text.as_bytes());
    let (out, masks) = masked(&p);
    assert!(masks >= 1);
    assert!(!contains(&out, key.as_bytes()));
}

#[test]
fn a_file_matched_only_by_its_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "speaker_embedding.txt", b"notes only\n");
    let r = show(&p, &ShowOptions::default()).unwrap_err();
    assert!(r.contains("nothing to mask"), "{r}");
}

#[test]
fn a_name_match_beside_a_content_match_is_masked() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 11);
    let p = write(
        &dir,
        "speaker_embedding.txt",
        format!("notes\n{key}\n").as_bytes(),
    );
    let (out, masks) = masked(&p);
    assert_eq!(masks, 1);
    assert!(
        !contains(&out, key.as_bytes()),
        "the secret is in the output"
    );
    assert!(out.starts_with(b"notes\n"));
}

#[test]
fn a_text_file_no_rule_matches_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in [
        ("clean.txt", b"hello\nworld\n".as_slice()),
        ("empty.txt", b"".as_slice()),
    ] {
        let p = write(&dir, name, body);
        let r = show(&p, &ShowOptions::default()).unwrap_err();
        assert!(r.contains("nothing to mask"), "{name}: {r}");
    }
}

#[test]
fn a_file_that_is_not_text_is_summarised_with_no_match() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(
        &dir,
        "small.safetensors",
        &synth::safetensors(&[("x", "F32", &[2, 2])]),
    );
    assert!(matches!(
        show(&p, &ShowOptions::default()),
        Ok(Shown::Summary(_))
    ));
}

#[test]
fn an_archive_read_only_in_part_is_refused() {
    // One member past the default limit of 1000 members.
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..1001).map(|i| format!("{i}.txt")).collect();
    let members: Vec<(&str, Vec<u8>)> = names
        .iter()
        .map(|n| (n.as_str(), b"plain\n".to_vec()))
        .collect();
    let p = write(&dir, "many.zip", &synth::npz(&members));
    let r = show(&p, &ShowOptions::default()).unwrap_err();
    assert!(r.contains("part of the content was not scanned"), "{r}");
}

#[test]
fn a_file_that_is_not_text_and_could_not_be_scanned_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut unknown = vec![0u8, 1, 2, 3];
    unknown.extend_from_slice(&[0xffu8; 4096]);
    let mut pdf = b"%PDF-1.4\n".to_vec();
    pdf.extend_from_slice(&[0u8; 64]);
    for (name, bytes) in [
        ("blob.bin", unknown),
        ("doc.pdf", pdf),
        ("broken.zip", b"PK\x03\x04truncated".to_vec()),
    ] {
        let p = write(&dir, name, &bytes);
        let r = show(&p, &ShowOptions::default()).unwrap_err();
        assert!(r.contains("could not scan"), "{name}: {r}");
    }
}

#[test]
fn binary_formats_get_a_summary_without_names() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(
        &dir,
        "model.safetensors",
        &synth::safetensors(&[("person_name_vector", "F32", &[1000, 512])]),
    );
    let Ok(Shown::Summary(s)) = show(&p, &ShowOptions::default()) else {
        panic!("expected a summary");
    };
    assert!(s.contains("format: safetensors tensor file"), "{s}");
    assert!(s.contains("F32 [1000, 512]"), "{s}");
    assert!(!s.contains("person_name_vector"));

    let p = write(&dir, "blob.bin", &[0u8, 1, 2, 3, 0, 0, 7, 9]);
    let r = show(&p, &ShowOptions::default()).unwrap_err();
    assert!(r.contains("binary file of unknown format"), "{r}");
}

#[test]
fn a_directory_or_missing_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert!(show(dir.path(), &ShowOptions::default()).is_err());
    assert!(show(&dir.path().join("nope"), &ShowOptions::default()).is_err());
    // A FIFO is refused without being opened (opening it would wait).
    let fifo = dir.path().join("pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let r = show(&fifo, &ShowOptions::default()).unwrap_err();
    assert!(r.contains("not a regular file"), "{r}");
}

#[test]
fn mask_replaces_only_the_spans() {
    let text = b"0123456789";
    let out = mask(
        text,
        vec![Span::new(0..2, "a"), Span::new(8..10, "b")],
        Marker::Fixed,
    );
    assert_eq!(out, b"<redacted>234567<redacted>");
    let out = mask(
        text,
        vec![Span::new(2..5, "a"), Span::new(4..7, "b")],
        Marker::Fixed,
    );
    assert_eq!(out, b"01<redacted>789");
    let out = mask(b"a\nb\nc", vec![Span::new(1..4, "a")], Marker::Fixed);
    assert_eq!(out, b"a<redacted>\n\nc");
    assert_eq!(mask(b"abc", Vec::new(), Marker::Fixed), b"abc");
}

#[test]
fn lines_parse_and_select() {
    assert_eq!(parse_lines("3:5"), Ok((3, 5)));
    assert_eq!(parse_lines("1:1"), Ok((1, 1)));
    for bad in ["0:1", "5:3", "3", ":4", "a:b", "+1:2", "1:2:3", " 1:2"] {
        assert!(parse_lines(bad).is_err(), "{bad}");
    }
    let t = b"l1\nl2\nl3\nl4";
    assert_eq!(select_lines(t, 2, 3), b"l2\nl3\n");
    assert_eq!(select_lines(t, 1, 1), b"l1\n");
    assert_eq!(select_lines(t, 4, 9), b"l4");
    assert_eq!(select_lines(t, 3, 9), b"l3\nl4");
    assert_eq!(select_lines(t, 7, 9), b"");
}

/// A ruleset directory adding three rules: one that matches plain content,
/// one that matches only next to a marker (so only a rescan finds it), and
/// one that matches the letter before a marker (so every rescan finds one
/// more).
fn extra_rules() -> TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("ruleset.toml"),
        "id = \"show_test\"\nversion = \"0.1.0\"\nlicence = \"MIT\"\n\
         description = \"test rules\"\ncategories = [\"secret\"]\n",
    )
    .unwrap();
    fs::write(
        d.path().join("rules.yar"),
        r#"rule added_word {
  meta:
    category = "secret"
    weight = 10
  strings:
    $re = "zebra-quokka"
  condition:
    $re
}
rule near_marker {
  meta:
    category = "secret"
    weight = 10
  strings:
    $re = "near <redacted>"
  condition:
    $re
}
rule content_flag {
  meta:
    category = "secret"
    weight = 10
  condition:
    filesize > 0 and uint8(0) == 0x51
}
rule creeping {
  meta:
    category = "secret"
    weight = 10
  strings:
    $re = /[a-z]<redacted>/
  condition:
    $re
}
"#,
    )
    .unwrap();
    d
}

fn show_with(rules: &Path, path: &Path) -> Result<Shown, String> {
    let cfg = ShowConfig {
        extra_ruleset_dirs: vec![rules.to_path_buf()],
        ..ShowConfig::default()
    };
    show_file(&cfg, path, &ShowOptions::default(), Some(cache())).map_err(|r| r.reason)
}

fn kind(cfg: &ShowConfig, path: &Path) -> RefusalKind {
    match show_file(cfg, path, &ShowOptions::default(), Some(cache())) {
        Ok(_) => panic!("{} was shown", path.display()),
        Err(r) => r.kind,
    }
}

#[test]
fn refusals_say_whether_only_the_file_and_rules_decide_them() {
    let dir = tempfile::tempdir().unwrap();
    let plain = ShowConfig::default();
    let fifo = dir.path().join("pipe");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let big = write(&dir, "big.txt", &vec![b'a'; 2048]);
    let small_cap = ShowConfig {
        max_bytes: 1024,
        ..ShowConfig::default()
    };
    assert_eq!(kind(&small_cap, &big), RefusalKind::File, "over the cap");
    for (what, p) in [
        ("missing", dir.path().join("nope")),
        ("directory", dir.path().to_path_buf()),
        ("fifo", fifo.clone()),
        ("no match", write(&dir, "clean.txt", b"hello\n")),
        (
            "name only",
            write(&dir, "speaker_embedding.txt", b"notes\n"),
        ),
    ] {
        assert_eq!(kind(&plain, &p), RefusalKind::File, "{what}");
    }
    let rules = extra_rules();
    let with_rules = ShowConfig {
        extra_ruleset_dirs: vec![rules.path().to_path_buf()],
        ..ShowConfig::default()
    };
    let key = synth::fake_secret("github_pat", 23);
    let creep = write(&dir, "creep.txt", format!("abcdefgh{key}\n").as_bytes());
    assert_eq!(kind(&with_rules, &creep), RefusalKind::File, "rounds");
    let flag = write(&dir, "flag.txt", b"Q starts this file\n");
    assert_eq!(kind(&with_rules, &flag), RefusalKind::File, "no location");

    // A scan that did not read the content whole, or a scanner that could
    // not start, may have a cause outside the file.
    let names: Vec<String> = (0..1001).map(|i| format!("{i}.txt")).collect();
    let members: Vec<(&str, Vec<u8>)> = names
        .iter()
        .map(|n| (n.as_str(), b"plain\n".to_vec()))
        .collect();
    let many = write(&dir, "many.zip", &synth::npz(&members));
    assert_eq!(kind(&plain, &many), RefusalKind::Other, "read in part");
    let broken = tempfile::tempdir().unwrap();
    fs::write(
        broken.path().join("ruleset.toml"),
        "id = \"show_broken\"\nversion = \"0.1.0\"\nlicence = \"MIT\"\n\
         description = \"broken rules\"\ncategories = [\"secret\"]\n",
    )
    .unwrap();
    fs::write(broken.path().join("rules.yar"), "rule broken { condition: ").unwrap();
    let broken_cfg = ShowConfig {
        extra_ruleset_dirs: vec![broken.path().to_path_buf()],
        ..ShowConfig::default()
    };
    let other = write(&dir, "other.txt", b"hello again\n");
    assert_eq!(kind(&broken_cfg, &other), RefusalKind::Other, "no scanner");
}

#[test]
fn added_rules_mask_and_rescans_mask_what_masking_reveals() {
    let rules = extra_rules();
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 21);
    let p = write(
        &dir,
        "app.txt",
        format!("pet = zebra-quokka\nnear {key} tail\n").as_bytes(),
    );
    let Ok(Shown::Masked { text, masks, .. }) = show_with(rules.path(), &p) else {
        panic!("not masked");
    };
    assert!(!contains(&text, key.as_bytes()));
    assert_eq!(masks, 2);
    // `near ` joined the key's marker on the rescan.
    assert!(text == format!("pet = {FIXED_MARKER}\n{FIXED_MARKER} tail\n").into_bytes());
}

#[test]
fn matches_left_after_every_round_refuse_the_view() {
    let rules = extra_rules();
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 22);
    let p = write(&dir, "creep.txt", format!("abcdefgh{key}\n").as_bytes());
    let r = show_with(rules.path(), &p).unwrap_err();
    assert!(r.contains("rounds"), "{r}");
}

#[test]
fn markers_longer_than_their_matches_do_not_refuse_a_file_at_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let keys: Vec<String> = (0..20)
        .map(|i| synth::fake_secret("aws_access_key", 100 + i))
        .collect();
    let text = keys.join("\n") + "\n";
    let p = write(&dir, "keys.txt", text.as_bytes());
    let cfg = ShowConfig {
        max_bytes: text.len() as u64,
        ..ShowConfig::default()
    };
    let opts = ShowOptions {
        marker: Marker::RuleIds,
        lines: None,
    };
    let shown = show_file(&cfg, &p, &opts, Some(cache())).map_err(|r| r.reason);
    let Ok(Shown::Masked {
        text: out, masks, ..
    }) = shown
    else {
        panic!("not masked: {:?}", shown.err());
    };
    assert_eq!(masks, 20);
    assert!(out.len() > text.len(), "the markers are the longer text");
    assert!(keys.iter().all(|k| !contains(&out, k.as_bytes())));
}

#[test]
fn a_content_match_without_a_location_refuses_the_view() {
    let rules = extra_rules();
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "flag.txt", b"Q starts this file\n");
    let r = show_with(rules.path(), &p).unwrap_err();
    assert!(
        r.contains("content_flag matched the content without a location"),
        "{r}"
    );
}

#[test]
fn an_npz_read_as_a_zip_is_summarised_as_a_zip() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(
        &dir,
        "mixed.npz",
        &synth::npz(&[
            ("a.npy", synth::npy("<f4", &[4, 8])),
            ("notes.txt", b"plain\n".to_vec()),
        ]),
    );
    let Ok(Shown::Summary(s)) = show(&p, &ShowOptions::default()) else {
        panic!("expected a summary");
    };
    assert!(s.contains("format: zip container"), "{s}");
}

#[test]
fn the_masked_view_counts_its_lines() {
    let dir = tempfile::tempdir().unwrap();
    let key = synth::fake_secret("github_pat", 12);
    for (body, n) in [
        (format!("{key}\nb\n"), 2u64),
        (format!("{key}\nb"), 2),
        (key.clone(), 1),
        (format!("{key}\n"), 1),
    ] {
        let p = write(&dir, "n.txt", body.as_bytes());
        let Ok(Shown::Masked { lines, .. }) = show(&p, &ShowOptions::default()) else {
            panic!("not masked");
        };
        assert_eq!(lines, n, "expected {n} lines");
    }
}

#[test]
fn paths_the_allowlist_covers_are_masked_too() {
    // gitleaks' global path allowlist makes the converted rules skip
    // `node_modules/`; the masked view runs every rule on every path, as it
    // ignores thresholds, ignore entries, and baselines. Checked inside a
    // repository and outside any.
    for in_repo in [true, false] {
        let d = tempfile::tempdir().unwrap();
        if in_repo {
            fs::create_dir(d.path().join(".git")).unwrap();
        }
        let dir = d.path().join("node_modules/pkg");
        fs::create_dir_all(&dir).unwrap();
        let line = synth::fake_secret("generic_api_key_assignment", 13);
        let value = line.split('"').nth(1).unwrap().to_string();
        let p = dir.join("settings.ini");
        fs::write(&p, format!("{line}\n")).unwrap();

        // The scan with default settings applies the allowlist and finds
        // nothing there ...
        let mut rg = RiskGrep::with_cache_dir(Config::default(), None, Some(cache())).unwrap();
        let t = &rg.scan_paths(std::slice::from_ref(&p)).targets[0];
        assert!(t.path_allowlisted, "precondition (in_repo {in_repo})");
        assert!(t.evidence.is_empty(), "precondition (in_repo {in_repo})");

        // With the setting off, the scan finds the value: the fixture is one
        // the rules detect.
        let off = Config {
            path_allowlist: false,
            ..Config::default()
        };
        let mut rg = RiskGrep::with_cache_dir(off, None, Some(cache())).unwrap();
        let t = &rg.scan_paths(std::slice::from_ref(&p)).targets[0];
        assert!(!t.evidence.is_empty(), "fixture (in_repo {in_repo})");

        // ... and the masked view still masks the value.
        let (text, masks) = masked(&p);
        assert!(masks >= 1, "nothing masked (in_repo {in_repo})");
        assert!(
            !contains(&text, value.as_bytes()),
            "the value was shown (in_repo {in_repo})"
        );
    }
}

#[test]
fn rules_see_the_path_a_scan_gives_them() {
    // A rule conditioned on the path from the repository's root matches in
    // a scan from any working directory, so the masked view must give rules
    // the same path, or such a match is printed unmasked.
    let rules = tempfile::tempdir().unwrap();
    fs::write(
        rules.path().join("ruleset.toml"),
        "id = \"show_path\"\nversion = \"0.1.0\"\nlicence = \"MIT\"\n\
         description = \"test rules\"\ncategories = [\"secret\"]\n",
    )
    .unwrap();
    fs::write(
        rules.path().join("rules.yar"),
        r#"rule rooted_word {
  meta:
    category = "secret"
    weight = 10
  strings:
    $re = "pelican-marmot"
  condition:
    path matches /^conf\/app\.txt$/ and $re
}
"#,
    )
    .unwrap();
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join(".git")).unwrap();
    fs::create_dir(d.path().join("conf")).unwrap();
    let p = write(&d, "conf/app.txt", b"name = pelican-marmot\n");

    // The scan (working directory outside the repository) finds it ...
    let cfg = Config {
        extra_ruleset_dirs: vec![rules.path().to_path_buf()],
        ..Config::default()
    };
    let mut rg = RiskGrep::with_cache_dir(cfg, None, Some(cache())).unwrap();
    let t = &rg.scan_paths(std::slice::from_ref(&p)).targets[0];
    assert!(
        t.evidence.iter().any(|e| e.rule == "rooted_word"),
        "precondition"
    );

    // ... and the masked view masks it.
    match show_with(rules.path(), &p) {
        Ok(Shown::Masked { text, masks, .. }) => {
            assert_eq!(masks, 1);
            assert!(!contains(&text, b"pelican-marmot"), "the word was shown");
        }
        Ok(Shown::Summary(_)) => panic!("expected a masked view, got a summary"),
        Err(r) => panic!("refused: {r}"),
    }

    // Through a link outside the repository, the rules still see the
    // linked file's path from its repository's root.
    let out = tempfile::tempdir().unwrap();
    let link = out.path().join("link.txt");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    match show_with(rules.path(), &link) {
        Ok(Shown::Masked { text, masks, .. }) => {
            assert_eq!(masks, 1);
            assert!(!contains(&text, b"pelican-marmot"), "the word was shown");
        }
        Ok(Shown::Summary(_)) => panic!("expected a masked view, got a summary"),
        Err(r) => panic!("refused: {r}"),
    }
}
