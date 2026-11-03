//! Zip archives through the `RiskGrep` facade: member evidence, the member
//! table, the limits that stop decompression bombs, and caching. Archives
//! are built at run time from synthetic members; secrets are generated and
//! never printed.

use riskgrep_core::config::Config;
use riskgrep_core::model::{Category, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::{RiskGrep, AFTER_READ};
use riskgrep_core::synth;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn shared_cache() -> PathBuf {
    static D: OnceLock<TempDir> = OnceLock::new();
    D.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let mut g = RiskGrep::with_cache_dir(Config::default(), None, Some(d.path().into()))
            .expect("scanner builds");
        g.scan_bytes("warm", b"nothing here\n");
        d
    })
    .path()
    .to_path_buf()
}

fn scanner_with(cfg: Config) -> RiskGrep {
    RiskGrep::with_cache_dir(cfg, None, Some(shared_cache())).unwrap()
}

fn scanner() -> RiskGrep {
    scanner_with(Config::default())
}

fn secret() -> Category {
    Category("secret".into())
}

fn aws_file(seed: u64) -> Vec<u8> {
    format!(
        "# settings\nAPP=demo\nlet id = \"{}\";\n",
        synth::fake_secret("aws_access_key", seed)
    )
    .into_bytes()
}

fn text(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    age(&p);
    p
}

/// Set a file's mtime into the past so a fresh stat entry is not racy.
fn age(p: &Path) {
    let f = File::options().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
}

fn scan(g: &mut RiskGrep, p: &Path) -> Report {
    g.scan_paths(&[p.to_path_buf()])
}

fn only(r: &Report) -> &TargetReport {
    assert_eq!(r.targets.len(), 1);
    &r.targets[0]
}

fn partial(t: &TargetReport) -> &str {
    match &t.status {
        TargetStatus::Partial { not_read } => not_read,
        other => panic!("expected partial, got {other:?}"),
    }
}

/// Offsets of each zip header with `sig` (local `PK\x03\x04`, central
/// `PK\x01\x02`).
fn headers(zip: &[u8], sig: &[u8; 4]) -> Vec<usize> {
    zip.windows(4)
        .enumerate()
        .filter(|(_, w)| w == sig)
        .map(|(i, _)| i)
        .collect()
}

/// Mark member `i` encrypted in both its local and central headers.
fn mark_encrypted(zip: &mut [u8], i: usize) {
    let l = headers(zip, b"PK\x03\x04")[i];
    zip[l + 6] |= 1;
    let c = headers(zip, b"PK\x01\x02")[i];
    zip[c + 8] |= 1;
}

/// Declare member `i`'s uncompressed size as `size` in both headers.
fn declare_size(zip: &mut [u8], i: usize, size: u32) {
    let l = headers(zip, b"PK\x03\x04")[i];
    zip[l + 22..l + 26].copy_from_slice(&size.to_le_bytes());
    let c = headers(zip, b"PK\x01\x02")[i];
    zip[c + 24..c + 28].copy_from_slice(&size.to_le_bytes());
}

#[test]
fn findings_in_members_are_attributed_to_them() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[
        ("README.md", text("# Demo\n\nNothing to see.\n")),
        ("config/app.env", aws_file(1)),
        ("logo.png", PNG.to_vec()),
    ]);
    let p = write(d.path(), "backup.zip", &z);
    let r = scan(&mut scanner(), &p);
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(!t.text, "a member cannot be read by line ranges");
    let e = t
        .evidence
        .iter()
        .find(|e| e.rule == "aws_access_token")
        .expect("aws evidence");
    assert_eq!(e.member.as_deref(), Some("config/app.env"));
    // Offsets and lines are the member's own.
    assert_eq!(e.locations[0].line_start, 3);
    assert!(e.locations[0].start < 60);
    let c = t.container.as_ref().expect("container report");
    assert_eq!(c.format, "zip");
    assert_eq!((c.members, c.scanned, c.skipped, c.not_read), (3, 2, 1, 0));
    assert_eq!(c.listed.len(), 1);
    assert_eq!(c.listed[0].path, "config/app.env");
    assert_eq!(c.listed[0].scores[&secret()], 95.0);
    assert_eq!(r.summary.targets, 1);
}

#[test]
fn nested_archives_are_opened_and_named() {
    let d = tempfile::tempdir().unwrap();
    let inner = synth::zip(&[("config/app.env", aws_file(2))]);
    let outer = synth::zip(&[("notes.txt", text("hi\n")), ("inner.zip", inner)]);
    let p = write(d.path(), "outer.zip", &outer);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(t
        .evidence
        .iter()
        .any(|e| e.member.as_deref() == Some("inner.zip!/config/app.env")));
    assert_eq!(t.container.unwrap().members, 3);
}

#[test]
fn a_high_ratio_member_is_not_decompressed() {
    let d = tempfile::tempdir().unwrap();
    let bomb = vec![b'0'; 4 << 20];
    let z = synth::zip(&[("zeros.txt", bomb), ("config/app.env", aws_file(3))]);
    assert!(
        z.len() < 64 << 10,
        "the member compresses far past the ratio"
    );
    let p = write(d.path(), "bomb.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(partial(&t), "member 1 not read (limits.container_ratio)");
    // The rest of the archive is still scanned.
    assert_eq!(t.scores[&secret()], 95.0);
    let c = t.container.unwrap();
    assert_eq!(c.not_read, 1);
    assert!(c
        .listed
        .iter()
        .any(|m| m.path == "zeros.txt" && matches!(m.status, TargetStatus::Unscanned { .. })));
}

#[test]
fn a_member_lying_about_its_size_is_not_read_past_the_cap() {
    let d = tempfile::tempdir().unwrap();
    let body: Vec<u8> = (0..(3u32 << 20))
        .map(|i| b"abcdefghij"[(i % 10) as usize])
        .collect();
    let mut z = synth::npz(&[("big.txt", body), ("ok.txt", text("fine\n"))]);
    declare_size(&mut z, 0, 10);
    let p = write(d.path(), "liar.zip", &z);
    let mut cfg = Config::default();
    cfg.limits.member_bytes = 1 << 20;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    // The stored data runs past the declared size. The zip reader refuses
    // the mismatch, so the member is not read; whatever a reader does, no
    // more than the member cap is read and the archive is never whole.
    assert_eq!(partial(&t), "member 1 unreadable");
    let c = t.container.unwrap();
    assert_eq!((c.scanned, c.not_read), (1, 1));
    assert!(c
        .listed
        .iter()
        .any(|m| m.path == "big.txt" && matches!(m.status, TargetStatus::Unscanned { .. })));
}

#[test]
fn nesting_past_the_depth_limit_is_partial() {
    let d = tempfile::tempdir().unwrap();
    let mut z = synth::zip(&[("deep/app.env", aws_file(4))]);
    for i in 0..3 {
        z = synth::zip(&[(&format!("level{i}.zip"), z)]);
    }
    let p = write(d.path(), "nested.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    // Depth 1 is the file; level2.zip (2) and level1.zip (3) open, level0.zip
    // would be depth 4. Nothing in scope was read.
    assert_eq!(
        t.status,
        TargetStatus::Unscanned {
            reason: "member 3 not read (limits.container_depth)".into()
        }
    );
    let mut cfg = Config::default();
    cfg.limits.container_depth = 4;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
}

#[test]
fn members_over_the_count_limit_are_partial() {
    let d = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..8).map(|i| format!("f{i}.txt")).collect();
    let members: Vec<(&str, Vec<u8>)> = names.iter().map(|n| (n.as_str(), text("x\n"))).collect();
    let p = write(d.path(), "many.zip", &synth::zip(&members));
    let mut cfg = Config::default();
    cfg.limits.container_members = 5;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        partial(&t),
        "members 6..8 not read (limits.container_members)"
    );
    let c = t.container.unwrap();
    assert_eq!((c.members, c.scanned, c.not_read), (8, 5, 3));
}

#[test]
fn encrypted_members_are_partial_and_never_clean() {
    let d = tempfile::tempdir().unwrap();
    let mut z = synth::npz(&[("a.txt", text("plain\n")), ("private.txt", text("x\n"))]);
    mark_encrypted(&mut z, 1);
    let p = write(d.path(), "enc.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(partial(&t), "member 2 encrypted");
    assert!(!partial(&t).contains("private"), "reasons name no member");
    let mut all = synth::npz(&[("a.txt", text("x\n"))]);
    mark_encrypted(&mut all, 0);
    let p = write(d.path(), "all.zip", &all);
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Unscanned {
            reason: "member 1 encrypted".into()
        }
    );
}

#[test]
fn an_unreadable_archive_is_unscanned() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "broken.zip", b"PK\x03\x04rest of a zip");
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Unscanned {
            reason: "zip central directory unreadable".into()
        }
    );
}

#[test]
fn a_spent_time_budget_is_unscanned() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "t.zip", &synth::zip(&[("a.txt", text("a\n"))]));
    let mut cfg = Config::default();
    cfg.limits.time_budget = Duration::ZERO;
    assert_eq!(
        only(&scan(&mut scanner_with(cfg), &p)).status,
        TargetStatus::Unscanned {
            reason: "timeout".into()
        }
    );
}

#[test]
fn whole_archives_are_cached_and_partial_ones_are_not() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let mk = || RiskGrep::with_cache_dir(Config::default(), None, Some(cache.path().into()));
    let p = write(
        d.path(),
        "c.zip",
        &synth::zip(&[("config/app.env", aws_file(5)), ("logo.png", PNG.to_vec())]),
    );
    let first = scan(&mut mk().unwrap(), &p);
    let mut g = mk().unwrap();
    let second = scan(&mut g, &p);
    assert_eq!(first, second);
    assert!(
        !g.bundle_loaded(),
        "a cached archive must not load the bundle"
    );
    assert_eq!(only(&second).container.as_ref().unwrap().skipped, 1);

    let mut z = synth::npz(&[("a.txt", text("a\n")), ("b.txt", text("b\n"))]);
    mark_encrypted(&mut z, 1);
    let q = write(d.path(), "p.zip", &z);
    scan(&mut mk().unwrap(), &q);
    let mut g = mk().unwrap();
    scan(&mut g, &q);
    assert!(g.bundle_loaded(), "a partial archive is scanned again");
}

#[test]
fn staged_archives_are_scanned_whole() {
    let z = synth::zip(&[("config/app.env", aws_file(6))]);
    let mut g = scanner();
    let t = g.scan_blob(
        "fixtures/backup.zip",
        b"zip-blob-1",
        &z,
        Some(std::slice::from_ref(&(100..=200))),
    );
    // Diff lines do not apply to a member.
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(t.evidence[0].member.as_deref(), Some("config/app.env"));
    let again = g.scan_blob("fixtures/backup.zip", b"zip-blob-1", &z, None);
    assert_eq!(again.container, t.container);
}

#[test]
fn ignore_globs_match_container_and_member_paths() {
    use riskgrep_core::suppress::{IgnoreRules, IgnoreSpec};
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[
        ("config/app.env", aws_file(7)),
        ("other/app.env", aws_file(8)),
    ]);
    let p = write(d.path(), "g.zip", &z);
    let with = |glob: &str| {
        let cfg = Config {
            ignore: IgnoreRules::new(IgnoreSpec {
                paths: vec![glob.into()],
                rules: vec![],
            })
            .unwrap(),
            ..Config::default()
        };
        only(&scan(&mut scanner_with(cfg), &p)).clone()
    };
    let t = with("**/g.zip!/config/**");
    assert_eq!(t.suppressed, 1);
    assert!(t
        .evidence
        .iter()
        .all(|e| e.member.as_deref() == Some("other/app.env")));
    assert_eq!(t.scores[&secret()], 95.0);
    let t = with("**/g.zip");
    assert!(t.evidence.is_empty());
    assert_eq!(t.scores[&secret()], 0.0);
}

#[test]
fn reports_hold_member_names_but_no_member_content() {
    let d = tempfile::tempdir().unwrap();
    let value = synth::fake_secret("aws_access_key", 9);
    let z = synth::zip(&[("config/app.env", aws_file(9))]);
    let p = write(d.path(), "leak.zip", &z);
    let r = scan(&mut scanner(), &p);
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains(&value), "a matched value reached the report");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let t = &v["targets"][0];
    assert_eq!(t["evidence"][0]["member"], "config/app.env");
    assert_eq!(t["container"]["format"], "zip");
    assert_eq!(t["container"]["listed"][0]["path"], "config/app.env");
    assert_eq!(t["container"]["listed"][0]["status"], "scanned");
}

#[test]
fn other_container_formats_stay_unscanned() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "a.7z", b"7z\xBC\xAF\x27\x1C rest");
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Unscanned {
            reason: "7z not scanned in v1".into()
        }
    );
}

#[test]
fn a_1password_export_is_found_inside_its_1pux_archive() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[
        ("export.attributes", text("{\"version\":3}\n")),
        ("export.data", synth::credential_file("onepassword_json", 1)),
    ]);
    let p = write(d.path(), "vault.1pux", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(t
        .evidence
        .iter()
        .all(|e| e.member.as_deref() == Some("export.data")));
}

/// Rename member `i` to `name` (same length) in both headers.
fn rename(zip: &mut [u8], i: usize, name: &str) {
    let l = headers(zip, b"PK\x03\x04")[i];
    zip[l + 30..l + 30 + name.len()].copy_from_slice(name.as_bytes());
    let c = headers(zip, b"PK\x01\x02")[i];
    zip[c + 46..c + 46 + name.len()].copy_from_slice(name.as_bytes());
}

#[test]
fn a_member_hidden_behind_a_duplicate_name_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let mut z = synth::npz(&[("a.ini", aws_file(10)), ("b.ini", text("plain=1\n"))]);
    rename(&mut z, 1, "a.ini");
    let p = write(d.path(), "dup.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert!(
        matches!(t.status, TargetStatus::Partial { .. }),
        "{:?}",
        t.status
    );
    assert!(partial(&t).contains("bytes outside the listed members"));
}

#[test]
fn bytes_outside_the_members_make_it_partial() {
    use std::io::Write as _;
    let d = tempfile::tempdir().unwrap();
    // A comment after the central directory.
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("a.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"a\n").unwrap();
    w.set_comment("note").unwrap();
    let commented = w.finish().unwrap().into_inner();
    let p = write(d.path(), "comment.zip", &commented);
    // A comment is scanned as text, not counted as bytes outside.
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Scanned
    );
    // A local entry ahead of the archive that its directory does not list.
    let hidden = synth::npz(&[("hidden.ini", aws_file(12))]);
    let mut z = hidden[..headers(&hidden, b"PK\x01\x02")[0]].to_vec();
    z.extend(synth::zip(&[("a.txt", text("a\n"))]));
    let p = write(d.path(), "prefixed.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert!(partial(&t).contains("bytes outside"), "{:?}", t.status);
    assert_eq!(t.scores[&secret()], 0.0, "the unlisted entry is not read");
}

/// `zip` behind a local entry its directory does not list. With `absolute`,
/// the directory's offsets count from the start of the file (as `zip -A`
/// leaves them); without, from the start of `zip`.
fn behind_unlisted_entry(hidden: &[u8], zip: &[u8], absolute: bool) -> Vec<u8> {
    let mut z = synth::npz(&[("hidden.bin", hidden.to_vec())]);
    z.truncate(headers(&z, b"PK\x01\x02")[0]);
    let by = z.len() as u32;
    let mut zip = zip.to_vec();
    if absolute {
        let shift = |b: &mut [u8], at: usize| {
            let v = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            b[at..at + 4].copy_from_slice(&(v + by).to_le_bytes());
        };
        for c in headers(&zip, b"PK\x01\x02") {
            shift(&mut zip, c + 42);
        }
        let end = headers(&zip, b"PK\x05\x06")[0];
        shift(&mut zip, end + 16);
    }
    z.extend(zip);
    z
}

#[test]
fn an_archive_with_absolute_offsets_behind_other_bytes_is_partial() {
    let d = tempfile::tempdir().unwrap();
    let inner = synth::zip(&[("config.ini", aws_file(30))]);
    // More than the directory budget: opened at the offsets the end record
    // gives, without searching the bytes ahead of it.
    let z = behind_unlisted_entry(&vec![0u8; 9 << 20], &inner, true);
    let p = write(d.path(), "shifted.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert!(partial(&t).contains("bytes outside"), "{:?}", t.status);
    assert_eq!(t.scores[&secret()], 95.0, "the listed member is read");
}

#[test]
fn a_large_prefix_is_not_searched_past_the_directory_budget() {
    let d = tempfile::tempdir().unwrap();
    let inner = synth::zip(&[("config.ini", aws_file(31))]);
    let z = behind_unlisted_entry(&vec![0u8; 9 << 20], &inner, false);
    let p = write(d.path(), "padded.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(
        t.status,
        TargetStatus::Unscanned {
            reason: "zip central directory not read within 8388608 bytes".into()
        }
    );
}

#[test]
fn a_zip_behind_a_stub_is_skipped_as_an_unknown_binary() {
    let d = tempfile::tempdir().unwrap();
    let inner = synth::zip(&[("config.ini", aws_file(32))]);
    for stub in [&b"#!/bin/sh\nexit 0\n"[..], b"MZ\x90\0\0\0\0\0"] {
        let mut z = stub.to_vec();
        z.extend(&inner);
        let p = write(d.path(), "installer.zip", &z);
        let t = only(&scan(&mut scanner(), &p)).clone();
        assert!(
            matches!(t.status, TargetStatus::Skipped { .. }),
            "{:?}",
            t.status
        );
        assert!(t.evidence.is_empty());
    }
}

#[test]
fn data_descriptors_are_accounted_for() {
    use std::io::Write as _;
    let d = tempfile::tempdir().unwrap();
    let mut w = zip::ZipWriter::new_stream(Vec::new());
    for (name, body) in [("a.txt", text("a\n")), ("b.ini", aws_file(11))] {
        w.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(&body).unwrap();
    }
    let z = w.finish().unwrap().into_inner();
    let p = write(d.path(), "stream.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
}

fn commented_zip(comment: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("a.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"plain\n").unwrap();
    w.set_raw_comment(comment.to_vec().into_boxed_slice())
        .unwrap();
    w.finish().unwrap().into_inner()
}

#[test]
fn the_archive_comment_is_scanned_as_a_reserved_member() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "c.zip", &commented_zip(&aws_file(13)));
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    let e = &t.evidence[0];
    assert_eq!(e.member.as_deref(), Some("comment!"));
    assert_eq!(e.locations[0].line_start, 3);
    let c = t.container.unwrap();
    assert_eq!((c.members, c.scanned), (2, 2));
    assert_eq!(c.listed[0].path, "comment!");
    // A comment holding a NUL byte is still read as text.
    let mut nul = b"\0\n".to_vec();
    nul.extend(aws_file(14));
    let p = write(d.path(), "nul.zip", &commented_zip(&nul));
    assert_eq!(only(&scan(&mut scanner(), &p)).scores[&secret()], 95.0);
    // A nested archive's comment is named through its container.
    let outer = synth::zip(&[("inner.zip", commented_zip(&aws_file(16)))]);
    let p = write(d.path(), "outer.zip", &outer);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.evidence[0].member.as_deref(), Some("inner.zip!/comment!"));
}

#[test]
fn a_real_member_cannot_take_the_comment_name() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("comment!", aws_file(15))]);
    let p = write(d.path(), "named.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.evidence[0].member.as_deref(), Some("comment!!"));
}

#[test]
fn a_comment_over_the_member_cap_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "big.zip", &commented_zip(&vec![b'x'; 2000]));
    let mut cfg = Config::default();
    cfg.limits.member_bytes = 1000;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        partial(&t),
        "member 2 read only in part (limits.member_bytes)"
    );
}

#[test]
fn a_member_name_that_is_not_utf8_is_still_named_and_read() {
    let d = tempfile::tempdir().unwrap();
    let mut z = synth::npz(&[("aXX.ini", aws_file(17))]);
    // Flag the name UTF-8 (bit 11) and make it invalid UTF-8.
    let l = headers(&z, b"PK\x03\x04")[0];
    z[l + 7] |= 0x08;
    z[l + 31] = 0xFF;
    z[l + 32] = 0xFE;
    let c = headers(&z, b"PK\x01\x02")[0];
    z[c + 9] |= 0x08;
    z[c + 47] = 0xFF;
    z[c + 48] = 0xFE;
    let p = write(d.path(), "badname.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.scores[&secret()], 95.0, "{:?}", t.status);
    // The zip reader falls back to code page 437 for the bad name.
    assert_eq!(t.evidence[0].member.as_deref(), Some("a\u{a0}\u{25a0}.ini"));
}

#[test]
fn archives_over_the_hash_cap_are_walked_from_the_file_and_not_cached() {
    use std::io::Write as _;
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let p = d.path().join("large.zip");
    {
        // 65 MiB in all: over the 64 MiB cap on archives read into memory.
        let mut w = zip::ZipWriter::new(File::create(&p).unwrap());
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .large_file(true);
        w.start_file("config.ini", stored).unwrap();
        w.write_all(&aws_file(18)).unwrap();
        w.start_file("zeros.bin", stored).unwrap();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..65 {
            w.write_all(&chunk).unwrap();
        }
        w.finish().unwrap();
    }
    assert!(fs::metadata(&p).unwrap().len() > 64 << 20);
    age(&p);
    let mut cfg = Config::default();
    cfg.limits.member_bytes = 80 << 20;
    cfg.limits.container_bytes = 80 << 20;
    cfg.limits.time_budget = Duration::from_secs(60);
    let mk = || RiskGrep::with_cache_dir(cfg.clone(), None, Some(cache.path().into())).unwrap();
    let first = scan(&mut mk(), &p);
    let t = only(&first);
    // Read whole from the file (the zero-filled member is a skipped binary).
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(t.container.as_ref().unwrap().skipped, 1);
    // Not cached: the next scan walks and scans it again.
    let mut g = mk();
    assert_eq!(scan(&mut g, &p), first);
    assert!(g.bundle_loaded(), "an archive over the cap is not cached");
}

/// An unlisted local entry holding a secret.
fn unlisted_entry() -> Vec<u8> {
    let z = synth::npz(&[("hidden.ini", aws_file(40))]);
    z[..headers(&z, b"PK\x01\x02")[0]].to_vec()
}

#[test]
fn bytes_after_the_central_directory_make_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let base = synth::zip(&[("a.txt", text("a\n"))]);
    let end = headers(&base, b"PK\x05\x06")[0];
    let body = unlisted_entry();
    let between = [&base[..end], &body, &base[end..]].concat();
    let after = [&base[..], &body].concat();
    for (name, z) in [("between.zip", between), ("after.zip", after)] {
        let p = write(d.path(), name, &z);
        let t = only(&scan(&mut scanner(), &p)).clone();
        let not_read = partial(&t);
        assert_eq!(
            not_read,
            format!("{} bytes outside the listed members not read", body.len()),
            "{name}"
        );
    }
}

#[test]
fn a_directory_end_past_its_entries_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let base = synth::zip(&[("a.txt", text("a\n"))]);
    let end = headers(&base, b"PK\x05\x06")[0];
    let body = unlisted_entry();
    // The end record's directory size claims the hidden bytes as directory.
    let mut z = [&base[..end], &body, &base[end..]].concat();
    let at = headers(&z, b"PK\x05\x06")[0] + 12;
    let v = u32::from_le_bytes(z[at..at + 4].try_into().unwrap());
    z[at..at + 4].copy_from_slice(&(v + body.len() as u32).to_le_bytes());
    let p = write(d.path(), "claimed.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert!(partial(&t).contains("bytes outside"), "{:?}", t.status);
}

#[test]
fn zip64_end_records_are_accounted_for() {
    let d = tempfile::tempdir().unwrap();
    let base = synth::zip(&[("a.txt", text("a\n"))]);
    let start = headers(&base, b"PK\x01\x02")[0] as u64;
    let end = headers(&base, b"PK\x05\x06")[0];
    let mut record = b"PK\x06\x06".to_vec();
    record.extend(44u64.to_le_bytes());
    record.extend([45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    record.extend(1u64.to_le_bytes());
    record.extend(1u64.to_le_bytes());
    record.extend((end as u64 - start).to_le_bytes());
    record.extend(start.to_le_bytes());
    let mut locator = b"PK\x06\x07\0\0\0\0".to_vec();
    locator.extend((end as u64).to_le_bytes());
    locator.extend(1u32.to_le_bytes());
    let z = [&base[..end], &record, &locator, &base[end..]].concat();
    let p = write(d.path(), "zip64.zip", &z);
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Scanned
    );
}

#[test]
fn a_comment_holding_the_end_signature_is_not_counted_as_outside() {
    use std::io::Write as _;
    let d = tempfile::tempdir().unwrap();
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("a.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"a\n").unwrap();
    w.set_comment("PK\x05\x06 and more than twenty-two bytes after it")
        .unwrap();
    let z = w.finish().unwrap().into_inner();
    let p = write(d.path(), "signature.zip", &z);
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Scanned
    );
}

#[test]
fn a_central_header_past_the_listed_entries_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let base = synth::zip(&[("a.txt", text("a\n"))]);
    let end = headers(&base, b"PK\x05\x06")[0];
    let body = aws_file(41);
    let mut extra = b"PK\x01\x02".to_vec();
    extra.resize(46, 0);
    extra[28..30].copy_from_slice(&(body.len() as u16).to_le_bytes());
    extra.extend(&body);
    let z = [&base[..end], &extra, &base[end..]].concat();
    let p = write(d.path(), "extra-header.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert!(partial(&t).contains("bytes outside"), "{:?}", t.status);
}

#[test]
fn zip64_extensible_data_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let base = synth::zip(&[("a.txt", text("a\n"))]);
    let start = headers(&base, b"PK\x01\x02")[0] as u64;
    let end = headers(&base, b"PK\x05\x06")[0];
    let hidden = aws_file(42);
    let mut record = b"PK\x06\x06".to_vec();
    record.extend((44 + hidden.len() as u64).to_le_bytes());
    record.extend([45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    record.extend(1u64.to_le_bytes());
    record.extend(1u64.to_le_bytes());
    record.extend((end as u64 - start).to_le_bytes());
    record.extend(start.to_le_bytes());
    record.extend(&hidden);
    let mut locator = b"PK\x06\x07\0\0\0\0".to_vec();
    locator.extend((end as u64).to_le_bytes());
    locator.extend(1u32.to_le_bytes());
    let z = [&base[..end], &record, &locator, &base[end..]].concat();
    let p = write(d.path(), "extensible.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert!(partial(&t).contains("bytes outside"), "{:?}", t.status);
}

/// An archive of `n` small text members, under a time budget a slow build
/// cannot spend, so only the member limits decide what is read.
fn scan_many(n: usize) -> TargetReport {
    let d = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..n).map(|i| format!("dir/file_{i:05}.txt")).collect();
    let members: Vec<(&str, Vec<u8>)> = names.iter().map(|n| (n.as_str(), text("x\n"))).collect();
    let p = write(d.path(), "many.zip", &synth::zip(&members));
    let mut cfg = Config::default();
    cfg.limits.time_budget = Duration::from_secs(120);
    only(&scan(&mut scanner_with(cfg), &p)).clone()
}

#[test]
fn hundreds_of_members_fit_the_directory_budget() {
    let t = scan_many(999);
    assert_eq!(t.status, TargetStatus::Scanned);
    let c = t.container.unwrap();
    assert_eq!((c.members, c.scanned, c.not_read), (999, 999, 0));
}

#[test]
fn members_past_the_default_count_limit_are_partial() {
    let t = scan_many(1001);
    assert_eq!(
        partial(&t),
        "member 1001 not read (limits.container_members)"
    );
    let c = t.container.unwrap();
    assert_eq!((c.members, c.scanned, c.not_read), (1001, 1000, 1));
}

/// The local entry (with a data descriptor when `descriptor` is set) and
/// central header of an entry built by hand, its local header at offset 0.
fn raw_entry(name: &str, method: u16, data: &[u8], descriptor: bool) -> (Vec<u8>, Vec<u8>) {
    let le16 = |v: u16| v.to_le_bytes();
    let le32 = |v: u32| v.to_le_bytes();
    let flags: u16 = if descriptor { 0x0808 } else { 0x0800 };
    let compressed = data.len() as u32;
    let mut local = Vec::new();
    local.extend_from_slice(b"PK\x03\x04");
    local.extend_from_slice(&le16(20));
    local.extend_from_slice(&le16(flags));
    local.extend_from_slice(&le16(method));
    local.extend_from_slice(&[0; 4]); // time and date
    local.extend_from_slice(&le32(0)); // CRC-32 of nothing
    local.extend_from_slice(&le32(if descriptor { 0 } else { compressed }));
    local.extend_from_slice(&le32(0));
    local.extend_from_slice(&le16(name.len() as u16));
    local.extend_from_slice(&le16(0));
    local.extend_from_slice(name.as_bytes());
    local.extend_from_slice(data);
    if descriptor {
        local.extend_from_slice(b"PK\x07\x08");
        local.extend_from_slice(&le32(0));
        local.extend_from_slice(&le32(compressed));
        local.extend_from_slice(&le32(0));
    }
    let mut central = Vec::new();
    central.extend_from_slice(b"PK\x01\x02");
    central.extend_from_slice(&le16(20));
    central.extend_from_slice(&le16(20));
    central.extend_from_slice(&le16(flags));
    central.extend_from_slice(&le16(method));
    central.extend_from_slice(&[0; 4]);
    central.extend_from_slice(&le32(0));
    central.extend_from_slice(&le32(compressed));
    central.extend_from_slice(&le32(0));
    central.extend_from_slice(&le16(name.len() as u16));
    central.extend_from_slice(&[0; 8]); // extra, comment, disk, internal attributes
    central.extend_from_slice(&le32(0)); // external attributes
    central.extend_from_slice(&le32(0)); // local header offset
    central.extend_from_slice(name.as_bytes());
    (local, central)
}

/// An end record for `entries` entries.
fn end_record(entries: u16, directory_size: usize, directory_at: usize) -> Vec<u8> {
    let mut r = b"PK\x05\x06\0\0\0\0".to_vec();
    r.extend_from_slice(&entries.to_le_bytes());
    r.extend_from_slice(&entries.to_le_bytes());
    r.extend_from_slice(&(directory_size as u32).to_le_bytes());
    r.extend_from_slice(&(directory_at as u32).to_le_bytes());
    r.extend_from_slice(&[0; 2]);
    r
}

/// An entry built by hand ([`raw_entry`]) followed by `a.txt`'s from a writer.
fn with_entry(name: &str, method: u16, data: &[u8], descriptor: bool) -> Vec<u8> {
    let (local, central) = raw_entry(name, method, data, descriptor);
    let base = synth::zip(&[("a.txt", text("a\n"))]);
    let cd = headers(&base, b"PK\x01\x02")[0];
    let end = headers(&base, b"PK\x05\x06")[0];
    let mut second = base[cd..end].to_vec();
    second[42..46].copy_from_slice(&(local.len() as u32).to_le_bytes());
    let size = central.len() + second.len();
    let record = end_record(2, size, local.len() + cd);
    [&local[..], &base[..cd], &central, &second, &record].concat()
}

/// A deflate stream that inflates to `content`.
fn deflated(content: &str) -> Vec<u8> {
    let z = synth::zip(&[("b.txt", text(content))]);
    let start = 30 + "b.txt".len();
    let compressed = u32::from_le_bytes(z[18..22].try_into().unwrap()) as usize;
    z[start..start + compressed].to_vec()
}

#[test]
fn directory_entries_holding_nothing_stay_scanned() {
    let d = tempfile::tempdir().unwrap();
    let fixed = [0x03, 0x00];
    let empty_stored = [0x01, 0x00, 0x00, 0xff, 0xff];
    for (name, z) in [
        // `jar cf`: stored, no bytes at all.
        ("stored.jar", with_entry("pkg/", 0, &[], false)),
        // `JarOutputStream`: an empty deflate stream and a data descriptor.
        ("deflated.jar", with_entry("pkg/", 8, &fixed, true)),
        ("no_descriptor.jar", with_entry("pkg/", 8, &fixed, false)),
        (
            "empty_block.jar",
            with_entry("pkg/", 8, &empty_stored, false),
        ),
    ] {
        let p = write(d.path(), name, &z);
        let t = only(&scan(&mut scanner(), &p)).clone();
        assert_eq!(t.status, TargetStatus::Scanned, "{name}");
        let c = t.container.unwrap();
        assert_eq!((c.members, c.scanned), (1, 1), "{name}");
    }
}

#[test]
fn bytes_in_a_directory_entry_make_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let body = unlisted_entry();
    let trailing = [&[0x03, 0x00][..], &body].concat();
    for (name, z, bytes) in [
        (
            "stored.zip",
            with_entry("docs/", 0, &body, false),
            body.len(),
        ),
        (
            "trailing.zip",
            with_entry("docs/", 8, &trailing, false),
            trailing.len(),
        ),
        (
            "described.zip",
            with_entry("docs/", 8, &trailing, true),
            trailing.len(),
        ),
        (
            "not_empty.zip",
            with_entry("docs/", 8, &deflated("bb\n"), false),
            deflated("bb\n").len(),
        ),
        // A single byte fits the output the check inflates into.
        (
            "one_byte.zip",
            with_entry("docs/", 8, &deflated("b"), false),
            deflated("b").len(),
        ),
        // Under the longest stream that is inflated at all.
        (
            "short_trailing.zip",
            with_entry("docs/", 8, &[0x03, 0x00, 0x41, 0x41], false),
            4,
        ),
        ("cut_short.zip", with_entry("docs/", 8, &[0x03], false), 1),
    ] {
        let p = write(d.path(), name, &z);
        let t = only(&scan(&mut scanner(), &p)).clone();
        assert_eq!(
            partial(&t),
            format!("{bytes} bytes outside the listed members not read"),
            "{name}"
        );
    }
}

#[test]
fn an_archive_of_only_a_directory_entry_with_bytes_is_not_scanned() {
    let d = tempfile::tempdir().unwrap();
    let (local, central) = raw_entry("docs/", 0, &[0x41; 77], false);
    let z = [
        &local[..],
        &central,
        &end_record(1, central.len(), local.len()),
    ]
    .concat();
    let p = write(d.path(), "only_dir.zip", &z);
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Unscanned {
            reason: "77 bytes outside the listed members not read".into()
        }
    );
}

/// The path whose read [`slow_read_hook`] delays, and for how long.
static SLOW_READ: Mutex<Option<(PathBuf, Duration)>> = Mutex::new(None);

/// The one `AFTER_READ` hook of this test binary.
fn slow_read_hook(p: &Path) {
    let delay = SLOW_READ
        .lock()
        .unwrap()
        .as_ref()
        .filter(|(target, _)| target == p)
        .map(|(_, delay)| *delay);
    if let Some(delay) = delay {
        std::thread::sleep(delay);
    }
}

#[test]
fn a_member_reached_after_the_deadline_is_not_scanned() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("config.ini", aws_file(41))]);
    let p = write(d.path(), "late.zip", &z);
    let budget = Duration::from_millis(500);
    *SLOW_READ.lock().unwrap() = Some((
        fs::canonicalize(&p).unwrap(),
        budget + Duration::from_millis(100),
    ));
    let _ = AFTER_READ.set(slow_read_hook);
    let mut cfg = Config::default();
    cfg.limits.time_budget = budget;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        t.status,
        TargetStatus::Unscanned {
            reason: "member 1 not read (limits.time_budget_ms)".into()
        }
    );
}

#[test]
fn an_unreadable_npy_in_an_npz_member_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[
        ("a.txt", text("a\n")),
        ("m.npz", synth::npz_with_unreadable_member()),
    ]);
    let p = write(d.path(), "embeddings.zip", &z);
    // Separate scanners over one cache: a run must not read a row of the last.
    for run in 0..2 {
        let t = only(&scan(&mut scanner(), &p)).clone();
        assert_eq!(
            partial(&t),
            "member 2 read only in part (npz member 0 could not be read)",
            "run {run}"
        );
        assert!(t.unseen_part().is_some());
        let c = t.container.unwrap();
        assert_eq!(
            (c.members, c.scanned, c.read_in_part, c.not_read),
            (2, 1, 1, 0)
        );
    }
}

#[test]
fn an_npz_member_over_the_text_limit_keeps_its_reason() {
    let d = tempfile::tempdir().unwrap();
    let npz = synth::npz_with_unreadable_first(&[("zz_noise.npy", synth::npy("<i4", &[5000]))]);
    let p = write(d.path(), "big.zip", &synth::zip(&[("m.npz", npz)]));
    let mut cfg = Config::default();
    cfg.limits.text_max = 1024;
    cfg.limits.sample = 256;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        partial(&t),
        "member 1 read only in part (npz member 0 could not be read)"
    );
}

/// `z` with `comments[i]` as the comment of its central header `i`. The
/// archive must have no entry comments yet, and no archive comment.
fn with_entry_comments(z: &[u8], comments: &[&[u8]]) -> Vec<u8> {
    let mut cds = headers(z, b"PK\x01\x02");
    let end = headers(z, b"PK\x05\x06")[0];
    assert_eq!(cds.len(), comments.len());
    cds.push(end);
    let mut out = z[..cds[0]].to_vec();
    for (i, comment) in comments.iter().enumerate() {
        let at = out.len();
        out.extend_from_slice(&z[cds[i]..cds[i + 1]]);
        out[at + 32..at + 34].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
    }
    let directory = out.len() - cds[0];
    let mut record = z[end..].to_vec();
    record[12..16].copy_from_slice(&(directory as u32).to_le_bytes());
    [out, record].concat()
}

/// The members evidence names, in order, deduplicated.
fn members_with_evidence(t: &TargetReport) -> Vec<String> {
    let mut m: Vec<String> = t.evidence.iter().filter_map(|e| e.member.clone()).collect();
    m.sort();
    m.dedup();
    m
}

#[test]
fn an_entry_comment_is_scanned_under_a_reserved_name() {
    let d = tempfile::tempdir().unwrap();
    let z = with_entry_comments(
        &synth::zip(&[("readme.txt", text("plain\n"))]),
        &[&aws_file(42)],
    );
    let p = write(d.path(), "commented.zip", &z);
    let first = scan(&mut scanner(), &p);
    let t = only(&first).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(members_with_evidence(&t), ["readme.txt!comment!"]);
    let c = t.container.as_ref().unwrap();
    assert_eq!((c.members, c.scanned), (2, 2));
    // The comment's evidence comes back from the cache with its member.
    let mut g = scanner();
    assert_eq!(scan(&mut g, &p), first);
    assert!(!g.bundle_loaded(), "a whole archive is cached");
}

#[test]
fn an_entry_without_a_comment_adds_no_member() {
    let d = tempfile::tempdir().unwrap();
    let base = synth::zip(&[("a.txt", text("a\n")), ("b.txt", text("b\n"))]);
    let p = write(d.path(), "plain.zip", &base);
    let c = only(&scan(&mut scanner(), &p)).container.clone().unwrap();
    assert_eq!((c.members, c.scanned), (2, 2));
    let z = with_entry_comments(&base, &[b"note\n", b""]);
    let p = write(d.path(), "one.zip", &z);
    let c = only(&scan(&mut scanner(), &p)).container.clone().unwrap();
    assert_eq!((c.members, c.scanned), (3, 3));
}

#[test]
fn an_entry_comment_past_the_member_cap_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let z = with_entry_comments(&synth::zip(&[("a.txt", text("a\n"))]), &[&[b'x'; 64]]);
    let p = write(d.path(), "long.zip", &z);
    let mut cfg = Config::default();
    cfg.limits.member_bytes = 16;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        partial(&t),
        "member 2 read only in part (limits.member_bytes)"
    );
    assert_eq!(t.container.unwrap().listed[0].path, "a.txt!comment!");
}

#[test]
fn entry_comments_count_against_the_shared_limits() {
    let d = tempfile::tempdir().unwrap();
    let z = with_entry_comments(
        &synth::zip(&[("a.txt", text("a\n")), ("b.txt", text("b\n"))]),
        &[b"note a\n", b"note b\n"],
    );
    let p = write(d.path(), "counted.zip", &z);
    let mut cfg = Config::default();
    cfg.limits.container_members = 1;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        partial(&t),
        "members 2..4 not read (limits.container_members)"
    );
    let c = t.container.unwrap();
    assert_eq!((c.members, c.scanned, c.not_read), (4, 1, 3));
    let mut cfg = Config::default();
    cfg.limits.container_bytes = "a\n".len() as u64;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert!(
        partial(&t).contains("not read (limits.container_bytes)"),
        "{}",
        partial(&t)
    );
}

#[test]
fn reserved_comment_names_do_not_collide_with_stored_names() {
    let d = tempfile::tempdir().unwrap();
    // A stored member spelled like the comment of `a.txt`, and one like the
    // archive comment, each holding a key; `a.txt` and `b!` have comments
    // holding one too.
    let z = with_entry_comments(
        &synth::zip(&[
            ("a.txt", text("a\n")),
            ("a.txt!comment!", aws_file(43)),
            ("b!", text("b\n")),
            ("comment!", aws_file(44)),
        ]),
        &[&aws_file(45), b"", &aws_file(46), b""],
    );
    let p = write(d.path(), "names.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(
        members_with_evidence(&t),
        [
            "a.txt!comment!",
            "a.txt!comment!!",
            "b!!!comment!",
            "comment!!"
        ]
    );
}

#[test]
fn comments_of_directory_nested_and_encrypted_entries_are_scanned() {
    let d = tempfile::tempdir().unwrap();
    let dir = with_entry_comments(&with_entry("docs/", 0, &[], false), &[&aws_file(47), b""]);
    let p = write(d.path(), "dir.zip", &dir);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_with_evidence(&t), ["docs/!comment!"]);
    let inner = with_entry_comments(&synth::zip(&[("x.txt", text("x\n"))]), &[&aws_file(48)]);
    let p = write(d.path(), "nested.zip", &synth::zip(&[("inner.zip", inner)]));
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(members_with_evidence(&t), ["inner.zip!/x.txt!comment!"]);
    let mut locked = with_entry_comments(&synth::zip(&[("s.txt", text("s\n"))]), &[&aws_file(49)]);
    mark_encrypted(&mut locked, 0);
    let p = write(d.path(), "locked.zip", &locked);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(partial(&t), "member 1 encrypted");
    assert_eq!(members_with_evidence(&t), ["s.txt!comment!"]);
}

#[test]
fn an_entry_comment_is_read_as_the_bytes_stored() {
    let d = tempfile::tempdir().unwrap();
    // Bytes the zip library would decode to longer text, ahead of a key: the
    // evidence's offsets are into the comment as stored.
    let key = synth::fake_secret("aws_access_key", 50);
    let comment = [&b"\xe9\xe9\xe9\xe9\n"[..], key.as_bytes(), b"\n"].concat();
    let z = with_entry_comments(&synth::zip(&[("a.txt", text("a\n"))]), &[&comment]);
    let p = write(d.path(), "encoded.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(members_with_evidence(&t), ["a.txt!comment!"]);
    let at = &t.evidence[0].locations[0];
    assert_eq!(at.start, 5, "offset of the key in the stored comment");
    assert_eq!(at.end, 5 + key.len() as u64);
    // UTF-16 with a byte-order mark is found like any other member.
    let utf16: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(
            String::from_utf8(aws_file(51))
                .unwrap()
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    let z = with_entry_comments(&synth::zip(&[("a.txt", text("a\n"))]), &[&utf16]);
    let p = write(d.path(), "utf16.zip", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(members_with_evidence(&t), ["a.txt!comment!"]);
}

/// An entry built by hand, with its CRC-32 and sizes correct for `content`
/// and `data` as its stored bytes.
struct Hand<'a> {
    name: &'a str,
    /// The name in the local header, when it differs from `name`.
    local_name: Option<&'a [u8]>,
    method: u16,
    data: Vec<u8>,
    content: Vec<u8>,
    descriptor: bool,
}

impl<'a> Hand<'a> {
    fn stored(name: &'a str, content: &[u8]) -> Self {
        Hand {
            name,
            local_name: None,
            method: 0,
            data: content.to_vec(),
            content: content.to_vec(),
            descriptor: false,
        }
    }

    fn deflated(name: &'a str, content: &[u8]) -> Self {
        let mut encode = flate2::Compress::new(flate2::Compression::default(), false);
        let mut data = Vec::with_capacity(content.len() + 64);
        encode
            .compress_vec(content, &mut data, flate2::FlushCompress::Finish)
            .unwrap();
        Hand {
            data,
            method: 8,
            ..Hand::stored(name, content)
        }
    }

    fn then(mut self, trailing: &[u8]) -> Self {
        self.data.extend_from_slice(trailing);
        self
    }

    fn with_descriptor(mut self) -> Self {
        self.descriptor = true;
        self
    }

    fn named_locally(mut self, local_name: &'a [u8]) -> Self {
        self.local_name = Some(local_name);
        self
    }
}

fn hand_zip(entries: &[Hand]) -> Vec<u8> {
    let le16 = |v: usize| (v as u16).to_le_bytes();
    let le32 = |v: usize| (v as u32).to_le_bytes();
    let (mut out, mut directory) = (Vec::new(), Vec::new());
    for e in entries {
        let mut crc = flate2::Crc::new();
        crc.update(&e.content);
        let crc = crc.sum() as usize;
        let at = out.len();
        let flags: usize = if e.descriptor { 0x0808 } else { 0x0800 };
        let local_name = e.local_name.unwrap_or(e.name.as_bytes());
        let (local_crc, local_compressed, local_size) = if e.descriptor {
            (0, 0, 0)
        } else {
            (crc, e.data.len(), e.content.len())
        };
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&le16(20));
        out.extend_from_slice(&le16(flags));
        out.extend_from_slice(&le16(e.method.into()));
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&le32(local_crc));
        out.extend_from_slice(&le32(local_compressed));
        out.extend_from_slice(&le32(local_size));
        out.extend_from_slice(&le16(local_name.len()));
        out.extend_from_slice(&le16(0));
        out.extend_from_slice(local_name);
        out.extend_from_slice(&e.data);
        if e.descriptor {
            out.extend_from_slice(b"PK\x07\x08");
            out.extend_from_slice(&le32(crc));
            out.extend_from_slice(&le32(e.data.len()));
            out.extend_from_slice(&le32(e.content.len()));
        }
        directory.extend_from_slice(b"PK\x01\x02");
        directory.extend_from_slice(&le16(20));
        directory.extend_from_slice(&le16(20));
        directory.extend_from_slice(&le16(flags));
        directory.extend_from_slice(&le16(e.method.into()));
        directory.extend_from_slice(&[0; 4]);
        directory.extend_from_slice(&le32(crc));
        directory.extend_from_slice(&le32(e.data.len()));
        directory.extend_from_slice(&le32(e.content.len()));
        directory.extend_from_slice(&le16(e.name.len()));
        directory.extend_from_slice(&[0; 8]);
        directory.extend_from_slice(&le32(0));
        directory.extend_from_slice(&le32(at));
        directory.extend_from_slice(e.name.as_bytes());
    }
    let record = end_record(entries.len() as u16, directory.len(), out.len());
    [out, directory, record].concat()
}

/// (members, scanned, read in part, skipped, not read, opened), which must
/// add up.
fn buckets(t: &TargetReport) -> (u64, u64, u64, u64, u64, u64) {
    let c = t.container.as_ref().expect("a container");
    assert_eq!(
        c.members,
        c.scanned + c.read_in_part + c.skipped + c.not_read + c.opened,
        "{c:?}"
    );
    (
        c.members,
        c.scanned,
        c.read_in_part,
        c.skipped,
        c.not_read,
        c.opened,
    )
}

fn scan_zip(z: &[u8]) -> TargetReport {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "h.zip", z);
    only(&scan(&mut scanner(), &p)).clone()
}

#[test]
fn bytes_after_a_deflate_stream_make_it_partial() {
    let hidden = aws_file(31);
    let z = hand_zip(&[
        Hand::deflated("seen.ini", &aws_file(32)),
        Hand::deflated("private-name.txt", b"plain\n").then(&hidden),
    ]);
    let t = scan_zip(&z);
    assert_eq!(
        partial(&t),
        format!(
            "member 2 read only in part ({} bytes after its data not read)",
            hidden.len()
        )
    );
    assert!(t.unseen_part().is_some());
    assert_eq!(
        t.scores[&secret()],
        95.0,
        "the score of what was read stays"
    );
    assert_eq!(buckets(&t), (2, 1, 1, 0, 0, 0));
}

#[test]
fn one_byte_after_a_deflate_stream_makes_it_partial() {
    let t = scan_zip(&hand_zip(&[Hand::deflated("a.txt", b"plain\n").then(b"x")]));
    assert_eq!(
        partial(&t),
        "member 1 read only in part (1 byte after its data not read)"
    );
}

#[test]
fn bytes_after_an_empty_deflate_stream_make_it_partial() {
    let z = hand_zip(&[Hand::deflated("empty.txt", b"").then(&aws_file(33))]);
    assert!(partial(&scan_zip(&z)).starts_with("member 1 read only in part ("));
}

#[test]
fn a_stored_member_with_a_larger_compressed_size_is_not_read() {
    // The reader refuses it, so none of it is scanned and it never passes as
    // read.
    let hidden = aws_file(34);
    let z = hand_zip(&[Hand::stored("a.txt", b"plain\n").then(&hidden)]);
    assert_eq!(
        scan_zip(&z).status,
        TargetStatus::Unscanned {
            reason: "member 1 unreadable".into()
        }
    );
    let z = hand_zip(&[
        Hand::stored("seen.ini", &aws_file(43)),
        Hand::stored("private-name.txt", b"plain\n").then(&hidden),
    ]);
    let t = scan_zip(&z);
    assert_eq!(partial(&t), "member 2 unreadable");
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(buckets(&t), (2, 1, 0, 0, 1, 0));
}

#[test]
fn bytes_after_a_stream_in_a_nested_archive_name_the_nested_member() {
    let inner = hand_zip(&[Hand::deflated("x.txt", b"plain\n").then(b"hidden")]);
    let z = synth::zip(&[("a.txt", text("a\n")), ("inner.zip", inner)]);
    let t = scan_zip(&z);
    assert_eq!(
        partial(&t),
        "member 3 read only in part (6 bytes after its data not read)"
    );
    assert_eq!(buckets(&t), (3, 1, 1, 0, 0, 1));
}

#[test]
fn bytes_after_the_stream_of_a_nested_archive_or_skipped_member_count_it_as_partly_read() {
    let inner = synth::zip(&[("x.txt", text("x\n"))]);
    let t = scan_zip(&hand_zip(
        &[Hand::deflated("i.zip", &inner).then(b"hidden")],
    ));
    assert_eq!(
        partial(&t),
        "member 1 read only in part (6 bytes after its data not read)"
    );
    assert_eq!(buckets(&t), (2, 1, 1, 0, 0, 0));

    let t = scan_zip(&hand_zip(&[
        Hand::deflated("a.txt", b"a\n"),
        Hand::deflated("l.png", PNG).then(b"hidden"),
    ]));
    assert_eq!(buckets(&t), (2, 1, 1, 0, 0, 0));
    assert!(partial(&t).contains("6 bytes after its data"));
}

#[test]
fn a_member_cut_at_a_limit_keeps_that_reason_alone() {
    let z = hand_zip(&[Hand::deflated("a.txt", &vec![b'a'; 4096]).then(b"hidden")]);
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "h.zip", &z);
    let mut cfg = Config::default();
    cfg.limits.member_bytes = 1024;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(
        partial(&t),
        "member 1 read only in part (limits.member_bytes)"
    );
}

#[test]
fn an_archive_with_bytes_after_a_stream_is_not_cached() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let mk = || RiskGrep::with_cache_dir(Config::default(), None, Some(cache.path().into()));
    let z = hand_zip(&[Hand::deflated("a.txt", b"plain\n").then(b"hidden")]);
    let p = write(d.path(), "h.zip", &z);
    scan(&mut mk().unwrap(), &p);
    let mut g = mk().unwrap();
    assert!(partial(only(&scan(&mut g, &p))).contains("6 bytes after its data"));
    assert!(g.bundle_loaded(), "a partial archive is scanned again");
}

#[test]
fn ordinary_archive_shapes_stay_scanned() {
    let body = aws_file(35);
    let shapes: Vec<(&str, Vec<u8>)> = vec![
        ("writer", synth::zip(&[("a.txt", body.clone())])),
        ("stored", synth::npz(&[("a.txt", body.clone())])),
        (
            "deflate and descriptor",
            hand_zip(&[Hand::deflated("a.txt", &body).with_descriptor()]),
        ),
        (
            "stored and descriptor",
            hand_zip(&[Hand::stored("a.txt", &body).with_descriptor()]),
        ),
        (
            "empty members",
            hand_zip(&[
                Hand::deflated("empty.txt", b""),
                Hand::deflated("empty2.txt", b"").with_descriptor(),
                Hand::stored("empty3.txt", b""),
                Hand::stored("a.txt", &body),
            ]),
        ),
        (
            "jar",
            hand_zip(&[
                Hand::stored("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
                Hand::deflated("a.txt", &body).with_descriptor(),
            ]),
        ),
        (
            "wheel",
            hand_zip(&[
                Hand::deflated("pkg/a.txt", &body),
                Hand::deflated("pkg-1.dist-info/METADATA", b"Name: pkg\n"),
                Hand::deflated("pkg-1.dist-info/RECORD", b"pkg/a.txt,,\n"),
            ]),
        ),
        (
            "docx",
            hand_zip(&[
                Hand::deflated("[Content_Types].xml", b"<Types/>"),
                Hand::deflated("word/document.xml", &body),
            ]),
        ),
    ];
    for (shape, z) in shapes {
        let t = scan_zip(&z);
        assert_eq!(t.status, TargetStatus::Scanned, "{shape}");
        assert_eq!(t.scores[&secret()], 95.0, "{shape}");
    }
}

#[test]
fn a_local_name_differing_from_the_directory_makes_it_partial() {
    let body = aws_file(36);
    // Longer, shorter, and equally long; the local name is never reported.
    for local in [&b"a-much-longer-private-name.txt"[..], b"a", b"b.ini"] {
        let z = hand_zip(&[Hand::deflated("a.ini", &body).named_locally(local)]);
        let t = scan_zip(&z);
        assert_eq!(
            partial(&t),
            "member 1 read only in part (local header name differs from the directory)"
        );
        assert!(t.unseen_part().is_some());
        assert_eq!(t.scores[&secret()], 95.0, "the member was read");
        assert_eq!(buckets(&t), (1, 0, 1, 0, 0, 0));
        assert!(!format!("{t:?}").contains("private-name"));
    }
}

#[test]
fn a_directory_entry_whose_local_name_differs_makes_it_partial() {
    // Longer, shorter, equally long, and empty; the name is never reported.
    for local in [&b"secret-looking-name"[..], b"d", b"xxxx/", b""] {
        let z = hand_zip(&[
            Hand::stored("docs/", b"").named_locally(local),
            Hand::stored("a.ini", &aws_file(44)),
        ]);
        let t = scan_zip(&z);
        assert_eq!(
            partial(&t),
            "1 directory entry: local header name differs from the directory"
        );
        assert!(t.unseen_part().is_some());
        assert_eq!(t.scores[&secret()], 95.0, "the member was read");
        assert_eq!(buckets(&t), (1, 1, 0, 0, 0, 0));
        assert!(!format!("{t:?}").contains("secret-looking"));
    }
}

#[test]
fn directory_entries_whose_local_names_differ_are_counted_with_other_reasons() {
    let z = hand_zip(&[
        Hand::stored("docs/", b"").named_locally(b""),
        Hand::stored("more/", b"").named_locally(b"elsewhere/"),
        Hand::stored("full/", b"").then(b"held"),
        Hand::stored("a.txt", b"a\n"),
    ]);
    assert_eq!(
        partial(&scan_zip(&z)),
        "4 bytes outside the listed members not read; \
         2 directory entries: local header name differs from the directory"
    );
}

#[test]
fn a_directory_entry_whose_local_name_differs_in_a_nested_archive_counts() {
    let inner = hand_zip(&[
        Hand::stored("docs/", b"").named_locally(b""),
        Hand::stored("x.txt", b"x\n"),
    ]);
    let t = scan_zip(&synth::zip(&[("i.zip", inner)]));
    assert_eq!(
        partial(&t),
        "1 directory entry: local header name differs from the directory"
    );
}

#[test]
fn an_archive_of_one_directory_entry_whose_local_name_differs_is_partial() {
    let t = scan_zip(&hand_zip(&[Hand::stored("docs/", b"").named_locally(b"")]));
    assert_eq!(
        partial(&t),
        "1 directory entry: local header name differs from the directory"
    );
    assert_eq!(buckets(&t), (0, 0, 0, 0, 0, 0));
}

#[test]
fn a_directory_entry_matching_its_local_name_stays_scanned() {
    let z = hand_zip(&[
        Hand::stored("docs/", b""),
        Hand::deflated("empty/", b""),
        Hand::stored("a.txt", b"a\n"),
    ]);
    assert_eq!(scan_zip(&z).status, TargetStatus::Scanned);
    let lone = hand_zip(&[Hand::stored("docs/", b"")]);
    assert_eq!(scan_zip(&lone).status, TargetStatus::Scanned);
}

#[test]
fn an_archive_with_a_differing_directory_name_is_not_cached() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let mk = || RiskGrep::with_cache_dir(Config::default(), None, Some(cache.path().into()));
    let z = hand_zip(&[
        Hand::stored("docs/", b"").named_locally(b""),
        Hand::stored("a.txt", b"a\n"),
    ]);
    let p = write(d.path(), "h.zip", &z);
    scan(&mut mk().unwrap(), &p);
    let mut g = mk().unwrap();
    assert!(partial(only(&scan(&mut g, &p))).contains("1 directory entry"));
    assert!(g.bundle_loaded(), "a partial archive is scanned again");
}

#[test]
fn a_lone_skipped_member_with_hidden_bytes_is_partial_and_keeps_its_counts() {
    for (entry, reason) in [
        (
            Hand::deflated("l.png", PNG).then(b"hidden"),
            "member 1 read only in part (6 bytes after its data not read)",
        ),
        (
            Hand::deflated("l.png", PNG).named_locally(b"m.png"),
            "member 1 read only in part (local header name differs from the directory)",
        ),
        (
            Hand::deflated("blob", b"\x00\x01\x02\x03\xff\xfe").then(b"x"),
            "member 1 read only in part (1 byte after its data not read)",
        ),
    ] {
        let t = scan_zip(&hand_zip(&[entry]));
        assert_eq!(partial(&t), reason);
        assert!(t.unseen_part().is_some());
        assert_eq!(buckets(&t), (1, 0, 1, 0, 0, 0));
    }
}

#[test]
fn a_nested_archive_of_skipped_members_with_hidden_bytes_is_partial() {
    let inner = synth::zip(&[("l.png", PNG.to_vec())]);
    let t = scan_zip(&hand_zip(
        &[Hand::deflated("i.zip", &inner).then(b"hidden")],
    ));
    assert_eq!(
        partial(&t),
        "member 1 read only in part (6 bytes after its data not read)"
    );
    assert_eq!(buckets(&t), (2, 0, 1, 1, 0, 0));
}

#[test]
fn an_archive_with_nothing_read_stays_unscanned() {
    let mut z = synth::zip(&[("a.txt", text("a\n"))]);
    mark_encrypted(&mut z, 0);
    assert!(matches!(
        scan_zip(&z).status,
        TargetStatus::Unscanned { .. }
    ));
}

#[test]
fn every_member_is_in_exactly_one_count() {
    let d = tempfile::tempdir().unwrap();
    let nested = synth::zip(&[("x.txt", text("x\n"))]);
    let mut z = synth::zip(&[
        ("whole.txt", text("a\n")),
        ("logo.png", PNG.to_vec()),
        ("locked.txt", text("b\n")),
        ("long.txt", vec![b'c'; 4096]),
        ("inner.zip", nested),
    ]);
    mark_encrypted(&mut z, 2);
    let p = write(d.path(), "five.zip", &z);
    let mut cfg = Config::default();
    cfg.limits.text_max = 1024;
    cfg.limits.sample = 256;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    // whole.txt and x.txt; long.txt; logo.png; locked.txt; inner.zip.
    assert_eq!(buckets(&t), (6, 2, 1, 1, 1, 1));
}

#[test]
fn a_cached_archive_reports_the_same_counts() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let mk = || RiskGrep::with_cache_dir(Config::default(), None, Some(cache.path().into()));
    let z = synth::zip(&[
        ("a.txt", text("a\n")),
        ("l.png", PNG.to_vec()),
        ("i.zip", synth::zip(&[("x.txt", text("x\n"))])),
    ]);
    let p = write(d.path(), "c.zip", &z);
    let first = only(&scan(&mut mk().unwrap(), &p)).clone();
    let mut g = mk().unwrap();
    let second = only(&scan(&mut g, &p)).clone();
    assert!(!g.bundle_loaded());
    assert_eq!(buckets(&first), (4, 2, 0, 1, 0, 1));
    assert_eq!(buckets(&second), buckets(&first));
}

#[test]
fn a_member_read_in_part_is_not_also_not_read() {
    // Text over its limit: scanned, and sampled.
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("long.txt", vec![b'c'; 4096])]);
    let p = write(d.path(), "s.zip", &z);
    let mut cfg = Config::default();
    cfg.limits.text_max = 1024;
    cfg.limits.sample = 256;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(buckets(&t), (1, 0, 1, 0, 0, 0));
    assert_eq!(partial(&t), "member 1 sampled (bytes 256..3840 not read)");
    assert!(t.unseen_part().is_some(), "strict: on_partial applies");
}

#[test]
fn an_npz_with_another_member_goes_through_the_framework() {
    let d = tempfile::tempdir().unwrap();
    let npy = synth::npy("<f4", &[4, 256]);
    let z = synth::zip(&[("emb.npy", npy.clone()), ("notes.ini", aws_file(37))]);
    let p = write(d.path(), "renamed.npz", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(t.container.as_ref().unwrap().format, "zip");
    assert!(members_with_evidence(&t).contains(&"notes.ini".to_string()));

    // Only other members; stored as well as deflated.
    let z = synth::npz(&[("notes.ini", aws_file(38))]);
    let p = write(d.path(), "stored.NPZ", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.scores[&secret()], 95.0);

    // Over the text limit.
    let z = synth::zip(&[("emb.npy", npy), ("notes.ini", aws_file(39))]);
    let p = write(d.path(), "large.npz", &z);
    let mut cfg = Config::default();
    cfg.limits.text_max = 64;
    cfg.limits.sample = 16;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(t.container.as_ref().unwrap().format, "zip");
    assert!(members_with_evidence(&t).contains(&"notes.ini".to_string()));
}

#[test]
fn an_npz_inside_an_archive_or_staged_goes_through_the_framework() {
    let npz = synth::zip(&[("notes.ini", aws_file(40))]);
    let t = scan_zip(&synth::zip(&[("m.npz", npz.clone())]));
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(members_with_evidence(&t), vec!["m.npz!/notes.ini"]);

    let t = scanner().scan_blob("m.npz", b"blob-of-renamed-zip", &npz, None);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(t.container.as_ref().unwrap().format, "zip");
}

#[test]
fn a_real_npz_stays_on_the_tensor_path() {
    let d = tempfile::tempdir().unwrap();
    let biometric = Category("biometric".into());
    let z = synth::zip(&[("emb.npy", synth::npy("<f4", &[4, 256]))]);
    let p = write(d.path(), "real.npz", &z);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert!(t.container.is_none());
    assert_eq!(t.scores[&biometric], 70.0);
}

/// An `.npz` of one embedding with `comment` as its archive comment.
fn npz_with_archive_comment(comment: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    w.start_file("emb.npy", stored).unwrap();
    w.write_all(&synth::npy("<f4", &[4, 256])).unwrap();
    w.set_raw_comment(comment.to_vec().into_boxed_slice())
        .unwrap();
    w.finish().unwrap().into_inner()
}

#[test]
fn an_npz_with_a_comment_goes_through_the_framework() {
    let d = tempfile::tempdir().unwrap();
    let mut large = Config::default();
    large.limits.text_max = 64;
    large.limits.sample = 16;
    let archive = npz_with_archive_comment(&aws_file(43));
    let entry = with_entry_comments(
        &synth::npz(&[("emb.npy", synth::npy("<f4", &[4, 256]))]),
        &[&aws_file(44)],
    );
    for (name, bytes) in [("archive.npz", archive), ("entry.npz", entry)] {
        for cfg in [Config::default(), large.clone()] {
            let p = write(d.path(), name, &bytes);
            let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
            assert_eq!(t.container.as_ref().unwrap().format, "zip", "{name}");
            assert_eq!(t.scores[&secret()], 95.0, "{name}");
        }
    }
    // No comment: the tensor path, as before.
    let none = npz_with_archive_comment(b"");
    let t = only(&scan(&mut scanner(), &write(d.path(), "none.npz", &none))).clone();
    assert!(t.container.is_none());
}

#[test]
fn an_npz_that_is_no_zip_is_not_reported_scanned() {
    let d = tempfile::tempdir().unwrap();
    let mut bytes = b"PK\x03\x04 ".to_vec();
    bytes.extend_from_slice(&aws_file(41));
    let p = write(d.path(), "fake.npz", &bytes);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(
        t.status,
        TargetStatus::Unscanned {
            reason: "zip central directory unreadable".into()
        }
    );
}

#[test]
fn a_member_named_npy_without_the_magic_makes_it_partial() {
    let d = tempfile::tempdir().unwrap();
    let biometric = Category("biometric".into());
    let z = synth::zip(&[
        ("emb.npy", synth::npy("<f4", &[4, 256])),
        ("private-name.npy", aws_file(42)),
    ]);
    let p = write(d.path(), "m.npz", &z);
    let expect = "npz member 1 is not an npy file";
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(partial(&t), expect);
    assert!(t.unseen_part().is_some());
    assert_eq!(
        t.scores[&biometric], 70.0,
        "the real member keeps its score"
    );

    // Over the text limit, read through the member headers.
    let mut cfg = Config::default();
    cfg.limits.text_max = 64;
    cfg.limits.sample = 16;
    let t = only(&scan(&mut scanner_with(cfg), &p)).clone();
    assert_eq!(partial(&t), expect);
    assert_eq!(t.scores[&biometric], 70.0);
}

/// A version 1 `.npy` file whose header text is `header` (padded as numpy
/// does), followed by `data`.
fn npy_with_header(header: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = header.to_vec();
    while !(10 + h.len() + 1).is_multiple_of(64) {
        h.push(b' ');
    }
    h.push(b'\n');
    let mut out = b"\x93NUMPY\x01\x00".to_vec();
    out.extend_from_slice(&(h.len() as u16).to_le_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    out
}

/// What scanning an `.npz` of an embedding and `second` says, read whole and
/// over the text limit.
fn scan_npz_beside_an_embedding(second: Vec<u8>) -> Vec<TargetReport> {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[
        ("emb.npy", synth::npy("<f4", &[4, 256])),
        ("second.npy", second),
    ]);
    let p = write(d.path(), "m.npz", &z);
    let mut cfg = Config::default();
    cfg.limits.text_max = 64;
    cfg.limits.sample = 16;
    vec![
        only(&scan(&mut scanner(), &p)).clone(),
        only(&scan(&mut scanner_with(cfg), &p)).clone(),
    ]
}

#[test]
fn a_member_with_the_magic_but_no_npy_header_makes_it_partial() {
    let biometric = Category("biometric".into());
    let mut unsupported = npy_with_header(b"{'descr': '<i4', 'shape': (1,), }", &[0; 4]);
    unsupported[6] = 9;
    let members = [
        // Text after the magic.
        [b"\x93NUMPY".to_vec(), aws_file(45)].concat(),
        // Only the magic.
        b"\x93NUMPY".to_vec(),
        // A header that is not a dictionary of an array.
        npy_with_header(b"not a dictionary", &[0; 16]),
        // No shape, no descr, a shape that is not a tuple of integers.
        npy_with_header(b"{'descr': '<i4', 'fortran_order': False, }", &[0; 16]),
        npy_with_header(b"{'shape': (3,), 'fortran_order': False, }", &[0; 16]),
        npy_with_header(b"{'descr': '<i4', 'shape': (a, b), }", &[0; 16]),
        // A header longer than the member.
        b"\x93NUMPY\x01\x00\xff\x00{'descr'".to_vec(),
        // A version 2 header longer than the member.
        b"\x93NUMPY\x02\x00\x00\x01\x00\x00{'descr'".to_vec(),
        // A version that does not exist.
        unsupported,
    ];
    for (i, second) in members.into_iter().enumerate() {
        for t in scan_npz_beside_an_embedding(second) {
            assert_eq!(partial(&t), "npz member 1 is not an npy file", "case {i}");
            assert!(t.unseen_part().is_some(), "case {i}");
            assert_eq!(t.scores[&biometric], 70.0, "case {i}");
        }
    }
}

#[test]
fn valid_npy_members_that_are_not_float_arrays_stay_scanned() {
    let latin1 = {
        let mut h = b"{'descr': [('n".to_vec();
        h.push(0xe9);
        h.extend_from_slice(b"', '<i4')], 'fortran_order': False, 'shape': (2,), }");
        h
    };
    let members = [
        synth::npy("<i4", &[8]),
        synth::npy("|b1", &[8]),
        // Version 2, with a four-byte header length.
        {
            let v1 = npy_with_header(
                b"{'descr': '<i4', 'fortran_order': False, 'shape': (2,), }",
                &[0; 8],
            );
            let len = u16::from_le_bytes([v1[8], v1[9]]);
            let mut v2 = b"\x93NUMPY\x02\x00".to_vec();
            v2.extend_from_slice(&u32::from(len).to_le_bytes());
            v2.extend_from_slice(&v1[10..]);
            v2
        },
        // Structured, scalar shape, a header with a byte that is not UTF-8.
        npy_with_header(
            b"{'descr': [('a', '<i4'), ('b', '<f4')], 'fortran_order': False, 'shape': (3,), }",
            &[0; 24],
        ),
        npy_with_header(
            b"{'descr': '<f8', 'fortran_order': False, 'shape': (), }",
            &[0; 8],
        ),
        npy_with_header(&latin1, &[0; 8]),
        // A header longer than the 4,096 bytes read of the member.
        npy_with_header(
            &[
                b"{'descr': '<i4', 'fortran_order': False, 'shape': (1,), 'pad': '".to_vec(),
                vec![b'x'; 5000],
                b"', }".to_vec(),
            ]
            .concat(),
            &[0; 4],
        ),
    ];
    for (i, second) in members.into_iter().enumerate() {
        for t in scan_npz_beside_an_embedding(second) {
            assert_eq!(t.status, TargetStatus::Scanned, "case {i}");
        }
    }
}

#[test]
fn an_integer_npy_member_is_not_mistaken_for_one_without_the_magic() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("ids.npy", synth::npy("<i4", &[8]))]);
    let p = write(d.path(), "ints.npz", &z);
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Scanned
    );
}

const ALL_SKIPPED: &str =
    "every member is an image, a binary of unknown format, or an archive of them";

#[test]
fn a_container_of_only_skipped_members_is_skipped_and_keeps_its_counts() {
    let blob = vec![0u8, 1, 2, 3, 0xff, 0xfe];
    let d = tempfile::tempdir().unwrap();
    for (name, bytes, counts) in [
        (
            "image.zip",
            synth::zip(&[("logo.png", PNG.to_vec())]),
            (1, 0, 0, 1, 0, 0),
        ),
        (
            "two.zip",
            synth::zip(&[("logo.png", PNG.to_vec()), ("blob", blob.clone())]),
            (2, 0, 0, 2, 0, 0),
        ),
        (
            "blob.tar",
            synth::tar(&[("blob", blob.clone())]),
            (1, 0, 0, 1, 0, 0),
        ),
        ("blob.gz", synth::gzip(&blob), (1, 0, 0, 1, 0, 0)),
        (
            "nested.zip",
            synth::zip(&[("in.zip", synth::zip(&[("blob", blob.clone())]))]),
            (2, 0, 0, 1, 0, 1),
        ),
    ] {
        let p = write(d.path(), name, &bytes);
        let first = scan(&mut scanner(), &p);
        let t = only(&first);
        assert_eq!(
            t.status,
            TargetStatus::Skipped {
                reason: ALL_SKIPPED.into()
            },
            "{name}"
        );
        assert!(t.scores.is_empty(), "{name}");
        assert_eq!(buckets(t), counts, "{name}");
        assert_eq!(first.summary.skipped, 1, "{name}");
        assert_eq!(scan(&mut scanner(), &p), first, "{name}");
    }
}

#[test]
fn a_container_with_any_member_read_stays_scanned() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("logo.png", PNG.to_vec()), ("a.txt", text("plain\n"))]);
    let p = write(d.path(), "mixed.zip", &z);
    let r = scan(&mut scanner(), &p);
    assert_eq!(only(&r).status, TargetStatus::Scanned);
    assert_eq!(buckets(only(&r)), (2, 1, 0, 1, 0, 0));
}

#[test]
fn a_listed_member_has_only_its_path_status_and_scores() {
    let d = tempfile::tempdir().unwrap();
    let p = write(
        d.path(),
        "k.zip",
        &synth::zip(&[("config/app.env", aws_file(61))]),
    );
    let r = scan(&mut scanner(), &p);
    let c = only(&r).container.as_ref().unwrap();
    let v = serde_json::to_value(&c.listed[0]).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["path", "scores", "status"]);
}

#[test]
fn a_container_of_only_skipped_members_is_cached() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let mk = || RiskGrep::with_cache_dir(Config::default(), None, Some(cache.path().into()));
    let p = write(
        d.path(),
        "n.zip",
        &synth::zip(&[("in.zip", synth::zip(&[("logo.png", PNG.to_vec())]))]),
    );
    let first = scan(&mut mk().unwrap(), &p);
    let mut g = mk().unwrap();
    let second = scan(&mut g, &p);
    assert_eq!(first, second);
    assert!(
        !g.bundle_loaded(),
        "a cached archive must not load the bundle"
    );
    assert!(matches!(only(&second).status, TargetStatus::Skipped { .. }));
    assert_eq!(buckets(only(&second)), (2, 0, 0, 1, 0, 1));
}
