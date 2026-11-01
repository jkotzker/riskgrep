//! Zip archives through the `RiskGrep` facade: member evidence, the member
//! table, the limits that stop decompression bombs, and caching. Archives
//! are built at run time from synthetic members; secrets are generated and
//! never printed.

use riskgrep_core::config::Config;
use riskgrep_core::model::{Category, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::synth;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
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
        ("config/.env", aws_file(1)),
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
    assert_eq!(e.member.as_deref(), Some("config/.env"));
    // Offsets and lines are the member's own.
    assert_eq!(e.locations[0].line_start, 3);
    assert!(e.locations[0].start < 60);
    let c = t.container.as_ref().expect("container report");
    assert_eq!(c.format, "zip");
    assert_eq!((c.members, c.scanned, c.skipped, c.not_read), (3, 2, 1, 0));
    assert_eq!(c.listed.len(), 1);
    assert_eq!(c.listed[0].path, "config/.env");
    assert_eq!(c.listed[0].scores[&secret()], 95.0);
    assert_eq!(r.summary.targets, 1);
}

#[test]
fn nested_archives_are_opened_and_named() {
    let d = tempfile::tempdir().unwrap();
    let inner = synth::zip(&[("config/.env", aws_file(2))]);
    let outer = synth::zip(&[("notes.txt", text("hi\n")), ("inner.zip", inner)]);
    let p = write(d.path(), "outer.zip", &outer);
    let t = only(&scan(&mut scanner(), &p)).clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(t
        .evidence
        .iter()
        .any(|e| e.member.as_deref() == Some("inner.zip!/config/.env")));
    assert_eq!(t.container.unwrap().members, 3);
}

#[test]
fn a_high_ratio_member_is_not_decompressed() {
    let d = tempfile::tempdir().unwrap();
    let bomb = vec![b'0'; 4 << 20];
    let z = synth::zip(&[("zeros.txt", bomb), ("config/.env", aws_file(3))]);
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
    let mut z = synth::zip(&[("deep/.env", aws_file(4))]);
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
        &synth::zip(&[("config/.env", aws_file(5)), ("logo.png", PNG.to_vec())]),
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
    let z = synth::zip(&[("config/.env", aws_file(6))]);
    let mut g = scanner();
    let t = g.scan_blob(
        "fixtures/backup.zip",
        b"zip-blob-1",
        &z,
        Some(std::slice::from_ref(&(100..=200))),
    );
    // Diff lines do not apply to a member.
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(t.evidence[0].member.as_deref(), Some("config/.env"));
    let again = g.scan_blob("fixtures/backup.zip", b"zip-blob-1", &z, None);
    assert_eq!(again.container, t.container);
}

#[test]
fn ignore_globs_match_container_and_member_paths() {
    use riskgrep_core::suppress::{IgnoreRules, IgnoreSpec};
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("config/.env", aws_file(7)), ("other/.env", aws_file(8))]);
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
        .all(|e| e.member.as_deref() == Some("other/.env")));
    assert_eq!(t.scores[&secret()], 95.0);
    let t = with("**/g.zip");
    assert!(t.evidence.is_empty());
    assert_eq!(t.scores[&secret()], 0.0);
}

#[test]
fn reports_hold_member_names_but_no_member_content() {
    let d = tempfile::tempdir().unwrap();
    let value = synth::fake_secret("aws_access_key", 9);
    let z = synth::zip(&[("config/.env", aws_file(9))]);
    let p = write(d.path(), "leak.zip", &z);
    let r = scan(&mut scanner(), &p);
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains(&value), "a matched value reached the report");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let t = &v["targets"][0];
    assert_eq!(t["evidence"][0]["member"], "config/.env");
    assert_eq!(t["container"]["format"], "zip");
    assert_eq!(t["container"]["listed"][0]["path"], "config/.env");
    assert_eq!(t["container"]["listed"][0]["status"], "scanned");
    assert_eq!(t["container"]["listed"][0]["kind"], "file");
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
