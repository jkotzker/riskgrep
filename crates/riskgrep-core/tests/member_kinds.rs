//! A container's member counts by kind: `opened_formats` for the nested
//! containers opened and `skipped_kinds` for the members not scanned, counted
//! once per member at any nesting level, so they add up to `opened` and
//! `skipped`. They name no member. Inputs are generated at run time.

use riskgrep_core::config::Config;
use riskgrep_core::model::{ContainerReport, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::synth;
use rusqlite::Connection;
use std::collections::BTreeMap;
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

fn scanner() -> RiskGrep {
    RiskGrep::with_cache_dir(Config::default(), None, Some(shared_cache())).unwrap()
}

fn chunk(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(tag);
    crc.update(data);
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc.sum().to_be_bytes());
    out
}

/// A complete 1x1 greyscale PNG.
fn png() -> Vec<u8> {
    let mut ihdr = 1u32.to_be_bytes().to_vec();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    let mut idat = Vec::new();
    {
        use std::io::Write;
        let mut z = flate2::write::ZlibEncoder::new(&mut idat, flate2::Compression::default());
        z.write_all(&[0, 0]).unwrap();
        z.finish().unwrap();
    }
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &ihdr));
    out.extend(chunk(b"IDAT", &idat));
    out.extend(chunk(b"IEND", b""));
    out
}

/// Bytes of no known format, with NULs so they are not text.
fn unknown_binary() -> Vec<u8> {
    let mut b = vec![0u8, 1, 2, 3];
    b.extend((0..64u8).map(|i| i.wrapping_mul(37) ^ 0xA5));
    b
}

/// A one-table SQLite database's bytes.
fn database(dir: &Path) -> Vec<u8> {
    let p = dir.join("app.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE notes(body TEXT); INSERT INTO notes VALUES ('hello');")
        .unwrap();
    c.close().unwrap();
    let b = fs::read(&p).unwrap();
    fs::remove_file(&p).unwrap();
    b
}

fn age(p: &Path) {
    let f = File::options().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
}

fn scan_file(dir: &Path, name: &str, bytes: &[u8]) -> (TargetReport, TargetReport) {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    age(&p);
    let mut g = scanner();
    let first = only(&g.scan_paths(std::slice::from_ref(&p))).clone();
    // The second scan is answered from the cache.
    let second = only(&g.scan_paths(&[p])).clone();
    (first, second)
}

fn only(r: &Report) -> &TargetReport {
    assert_eq!(r.targets.len(), 1);
    &r.targets[0]
}

fn counts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, n)| (k.to_string(), *n)).collect()
}

/// The kinds add up to the totals.
fn consistent(c: &ContainerReport) {
    assert_eq!(c.opened_formats.values().sum::<u64>(), c.opened, "{c:?}");
    assert_eq!(c.skipped_kinds.values().sum::<u64>(), c.skipped, "{c:?}");
}

fn kinds(t: &TargetReport) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let c = t.container.as_ref().expect("container");
    consistent(c);
    (c.opened_formats.clone(), c.skipped_kinds.clone())
}

#[test]
fn nested_containers_are_counted_by_format() {
    let d = tempfile::tempdir().unwrap();
    let db = database(d.path());
    let tar = synth::tar(&[("x.txt", b"notes\n".to_vec())]);
    type Case<'a> = (&'a str, Vec<u8>, &'a [(&'a str, u64)]);
    let cases: Vec<Case> = vec![
        (
            "db.zip",
            synth::zip(&[("app.db", db.clone())]),
            &[("sqlite", 1)],
        ),
        (
            "tar.zip",
            synth::zip(&[("x.tar", tar.clone())]),
            &[("tar", 1)],
        ),
        (
            "zip.zip",
            synth::zip(&[("inner.zip", synth::zip(&[("a.txt", b"notes\n".to_vec())]))]),
            &[("zip", 1)],
        ),
        // A gzip stream holding a tar is one level: the database is the only
        // container opened inside it.
        (
            "db.tar.gz",
            synth::gzip(&synth::tar(&[("app.db", db.clone())])),
            &[("sqlite", 1)],
        ),
    ];
    for (name, bytes, want) in cases {
        for t in <[TargetReport; 2]>::from(scan_file(d.path(), name, &bytes)) {
            assert_eq!(t.status, TargetStatus::Scanned, "{name}");
            let (opened, skipped) = kinds(&t);
            assert_eq!(opened, counts(want), "{name}");
            assert!(skipped.is_empty(), "{name}: {skipped:?}");
        }
    }
}

#[test]
fn skipped_members_are_counted_by_kind_at_every_level() {
    let d = tempfile::tempdir().unwrap();
    let inner = synth::zip(&[("deep.png", png()), ("b.txt", b"notes\n".to_vec())]);
    let z = synth::zip(&[
        ("p.png", png()),
        ("blob", unknown_binary()),
        ("a.txt", b"notes\n".to_vec()),
        ("inner.zip", inner),
    ]);
    for t in <[TargetReport; 2]>::from(scan_file(d.path(), "mixed.zip", &z)) {
        assert_eq!(t.status, TargetStatus::Scanned);
        let (opened, skipped) = kinds(&t);
        assert_eq!(opened, counts(&[("zip", 1)]));
        // Counted once per member, whatever its level.
        assert_eq!(skipped, counts(&[("png", 2), ("unknown", 1)]));
        let j = serde_json::to_value(&t).unwrap();
        assert_eq!(j["container"]["skipped_kinds"]["png"], serde_json::json!(2));
        assert_eq!(
            j["container"]["opened_formats"]["zip"],
            serde_json::json!(1)
        );
        // No member is named: clean members are never listed.
        assert!(j["container"]["listed"].as_array().unwrap().is_empty());
        let text = j.to_string();
        for name in ["p.png", "blob", "deep.png", "inner.zip"] {
            assert!(!text.contains(name), "{name} named in {text}");
        }
    }
}

#[test]
fn a_container_of_only_skipped_members_keeps_its_kinds() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("p.png", png()), ("blob", unknown_binary())]);
    for t in <[TargetReport; 2]>::from(scan_file(d.path(), "media.zip", &z)) {
        assert!(
            matches!(t.status, TargetStatus::Skipped { .. }),
            "{:?}",
            t.status
        );
        let (_, skipped) = kinds(&t);
        assert_eq!(skipped, counts(&[("png", 1), ("unknown", 1)]));
    }
}

#[test]
fn links_and_images_in_database_cells_have_kinds_too() {
    let d = tempfile::tempdir().unwrap();
    let mut tar = synth::tar_entry("a.txt", b'0', b"notes\n");
    tar.extend(synth::tar_entry("link", b'2', b""));
    tar.extend([0u8; 1024]);
    let (t, _) = scan_file(d.path(), "links.tar", &tar);
    assert_eq!(kinds(&t).1, counts(&[("link_or_device", 1)]));

    let p = d.path().join("img.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE t(body TEXT, pic BLOB); INSERT INTO t VALUES ('hello', NULL);")
        .unwrap();
    c.execute("UPDATE t SET pic = ?1", [png()]).unwrap();
    c.close().unwrap();
    let bytes = fs::read(&p).unwrap();
    let (t, _) = scan_file(d.path(), "copy.db", &bytes);
    assert_eq!(kinds(&t).1, counts(&[("png", 1)]));
}

#[test]
fn a_container_without_nested_or_skipped_members_has_no_kind_fields() {
    let d = tempfile::tempdir().unwrap();
    let z = synth::zip(&[("a.txt", b"notes\n".to_vec())]);
    let (t, _) = scan_file(d.path(), "plain.zip", &z);
    let j = serde_json::to_value(&t).unwrap();
    assert!(j["container"].get("opened_formats").is_none(), "{j}");
    assert!(j["container"].get("skipped_kinds").is_none(), "{j}");
}
