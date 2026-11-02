//! SQLite databases through the `RiskGrep` facade and the extractor: what a
//! column's region holds, how a region is named, that a scan never touches
//! the database, and what a malformed one does. Databases are built at run
//! time with the bundled SQLite; secrets are generated and never printed.

use riskgrep_core::classify::Limits;
use riskgrep_core::config::Config;
use riskgrep_core::container::{self, sqlite::SQLITE, Extracted};
use riskgrep_core::model::{Category, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::synth;
use rusqlite::{params, Connection};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};
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

fn aws(seed: u64) -> String {
    synth::fake_secret("aws_access_key", seed)
}

/// Set a file's mtime into the past so a fresh stat entry is not racy.
fn age(p: &Path) {
    let f = File::options().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
}

/// A database at `dir/name` built by `sql`, closed, with its mtime aged.
fn db(dir: &Path, name: &str, sql: &str) -> PathBuf {
    let p = dir.join(name);
    let c = Connection::open(&p).unwrap();
    c.execute_batch(sql).unwrap();
    c.close().unwrap();
    age(&p);
    p
}

fn only(r: &Report) -> &TargetReport {
    assert_eq!(r.targets.len(), 1);
    &r.targets[0]
}

fn scan(g: &mut RiskGrep, p: &Path) -> Report {
    g.scan_paths(&[p.to_path_buf()])
}

fn partial(t: &TargetReport) -> &str {
    match &t.status {
        TargetStatus::Partial { not_read } => not_read,
        s => panic!("expected partial, got {s:?}"),
    }
}

fn unscanned(t: &TargetReport) -> &str {
    match &t.status {
        TargetStatus::Unscanned { reason } => reason,
        s => panic!("expected unscanned, got {s:?}"),
    }
}

fn extract(bytes: &[u8], limits: &Limits) -> Extracted {
    let deadline = Instant::now() + Duration::from_secs(30);
    container::extract(&SQLITE, &bytes, bytes.len() as u64, limits, deadline)
}

/// Each member's path and bytes.
fn regions(x: &Extracted) -> BTreeMap<String, Vec<u8>> {
    x.members
        .iter()
        .map(|m| (m.path.clone(), m.content.bytes.clone()))
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Every region's name and text, from a database built by `sql`.
fn read(sql: &str) -> Extracted {
    let d = tempfile::tempdir().unwrap();
    let p = db(d.path(), "t.db", sql);
    extract(&fs::read(p).unwrap(), &Limits::default())
}

// ---- Findings and names ----------------------------------------------------

#[test]
fn a_secret_in_a_text_column_is_found_and_named() {
    let d = tempfile::tempdir().unwrap();
    let key = aws(1);
    let p = db(
        d.path(),
        "app.db",
        &format!(
            "CREATE TABLE notes(id INTEGER PRIMARY KEY, title TEXT, body TEXT);
             INSERT INTO notes(title, body) VALUES ('first', 'nothing here');
             INSERT INTO notes(title, body) VALUES ('second', '{key}');"
        ),
    );
    let r = scan(&mut scanner(), &p);
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert!(t.scores[&secret()] >= 80.0, "{:?}", t.scores);
    let e = t
        .evidence
        .iter()
        .find(|e| e.rule == "aws_access_token")
        .expect("evidence");
    assert_eq!(e.member.as_deref(), Some("notes/body"));
    // The second row's cell, on the region's second line.
    assert_eq!(e.locations[0].line_start, 2);
    let c = t.container.as_ref().expect("container report");
    assert_eq!(c.format, "sqlite");
    assert_eq!(
        c.members,
        c.scanned + c.read_in_part + c.skipped + c.not_read + c.opened
    );
    assert!(!serde_json::to_string(&r).unwrap().contains(&key));
}

#[test]
fn reasons_name_no_table_and_names_are_escaped() {
    let x = read(
        "CREATE TABLE \"private diary\"(\"a/b\" TEXT, \"100%\" TEXT, \"x!/y\" TEXT, \"new\nline\" TEXT, \"end!\" TEXT);
         INSERT INTO \"private diary\" VALUES ('1','2','3','4','5');",
    );
    let names: Vec<String> = regions(&x).into_keys().collect();
    for want in [
        "private diary/a%2Fb",
        "private diary/100%25",
        "private diary/x!%2Fy",
        "private diary/new\\nline",
        "private diary/end!!",
    ] {
        assert!(names.iter().any(|n| n == want), "{want} not in {names:?}");
    }

    // Read in part: the reason counts and places members, and names nothing.
    let d = tempfile::tempdir().unwrap();
    let body = "x".repeat(4000);
    let mut sql = String::from("CREATE TABLE \"private diary\"(entry TEXT);");
    for _ in 0..50 {
        sql += &format!("INSERT INTO \"private diary\" VALUES ('{body}');");
    }
    let p = db(d.path(), "p.db", &sql);
    let mut cfg = Config::default();
    cfg.limits.container_bytes = 20_000;
    let r = scan(&mut scanner_with(cfg), &p);
    let reason = partial(only(&r));
    assert!(!reason.contains("private"), "{reason}");
    assert!(!reason.contains("entry"), "{reason}");
}

#[test]
fn a_database_in_an_archive_is_opened_and_named() {
    let d = tempfile::tempdir().unwrap();
    let key = aws(2);
    let p = db(
        d.path(),
        "inner.db",
        &format!("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('{key}');"),
    );
    let z = synth::zip(&[("data/app.db", fs::read(&p).unwrap())]);
    let zp = d.path().join("backup.zip");
    fs::write(&zp, z).unwrap();
    age(&zp);
    let r = scan(&mut scanner(), &zp);
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    let e = t
        .evidence
        .iter()
        .find(|e| e.rule == "aws_access_token")
        .expect("evidence");
    assert_eq!(e.member.as_deref(), Some("data/app.db!/t/v"));
}

#[test]
fn a_staged_database_is_scanned_from_its_bytes() {
    let d = tempfile::tempdir().unwrap();
    let key = aws(3);
    let p = db(
        d.path(),
        "app.db",
        &format!("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('{key}');"),
    );
    let t = scanner().scan_blob("app.db", b"blob-id-1", &fs::read(p).unwrap(), None);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert!(t.scores[&secret()] >= 80.0);
}

// ---- Never writing ---------------------------------------------------------

/// Every entry of `dir`: name, length, mtime, and content.
fn snapshot(dir: &Path) -> BTreeMap<String, (u64, SystemTime, Vec<u8>)> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let md = e.metadata().unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                (
                    md.len(),
                    md.modified().unwrap(),
                    fs::read(e.path()).unwrap(),
                ),
            )
        })
        .collect()
}

#[test]
fn a_scan_changes_nothing_in_a_rollback_database_or_its_directory() {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "app.db",
        &format!(
            "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('{}');",
            aws(4)
        ),
    );
    let before = snapshot(d.path());
    let r = scan(&mut scanner(), &p);
    assert_eq!(only(&r).status, TargetStatus::Scanned);
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn a_wal_is_never_checkpointed_and_its_unmerged_content_is_reported_unread() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("app.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
         CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('merged');
         PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .unwrap();
    let in_wal = aws(5);
    c.execute("INSERT INTO t VALUES (?1)", params![in_wal])
        .unwrap();
    // The connection stays open, as a running application's would, so the
    // `-wal` and `-shm` files stay on disk.
    assert!(fs::metadata(d.path().join("app.db-wal")).unwrap().len() > 0);
    let before = snapshot(d.path());

    let r = scan(&mut scanner(), &p);
    let t = only(&r);
    let reason = partial(t);
    assert!(reason.contains("write-ahead log"), "{reason}");
    assert_eq!(t.scores[&secret()], 0.0, "the log's content is not read");
    let c2 = t.container.as_ref().unwrap();
    assert!(c2.not_read >= 1);
    assert_eq!(
        c2.members,
        c2.scanned + c2.read_in_part + c2.skipped + c2.not_read + c2.opened
    );
    assert!(c2.listed.iter().any(|m| m.path == "wal!"));

    assert_eq!(snapshot(d.path()), before, "bytes and listing unchanged");
    let n: i64 = c
        .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2, "the database still reads");
    drop(c);
}

#[test]
fn a_wal_that_appears_after_a_clean_scan_is_not_hidden_by_the_cache() {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "app.db",
        "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('ok');",
    );
    let mut g = scanner();
    assert_eq!(only(&scan(&mut g, &p)).status, TargetStatus::Scanned);
    // A second scan is answered from the cache.
    assert_eq!(only(&scan(&mut g, &p)).status, TargetStatus::Scanned);

    let wal = d.path().join("app.db-wal");
    fs::write(&wal, b"\x37\x7f\x06\x82 not empty").unwrap();
    let r = scan(&mut g, &p);
    assert!(partial(only(&r)).contains("write-ahead log"));

    // Empty, as after a clean close of some builds: nothing unmerged.
    fs::write(&wal, b"").unwrap();
    assert_eq!(only(&scan(&mut g, &p)).status, TargetStatus::Scanned);
}

#[test]
fn a_rollback_journal_beside_it_is_reported_unread() {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "app.db",
        "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('ok');",
    );
    fs::write(d.path().join("app.db-journal"), b"\xd9\xd5\x05\xf9 pages").unwrap();
    let r = scan(&mut scanner(), &p);
    let t = only(&r);
    assert!(partial(t).contains("rollback journal"));
    let c = t.container.as_ref().unwrap();
    assert!(c.listed.iter().any(|m| m.path == "journal!"));
}

#[test]
fn a_log_file_scanned_by_itself_is_unscanned() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("app.db-wal");
    let mut bytes = b"\x37\x7f\x06\x82\x00\x2d\xe2\x18".to_vec();
    bytes.resize(4096, 0);
    fs::write(&p, &bytes).unwrap();
    let r = scan(&mut scanner(), &p);
    assert!(unscanned(only(&r)).contains("write-ahead log"));
}

// ---- What is read, compared with the engine --------------------------------

/// The values of `column`, in the engine's order, joined as a region is.
fn expected(c: &Connection, query: &str) -> Vec<u8> {
    let mut st = c.prepare(query).unwrap();
    let rows = st.query_map([], |r| r.get::<_, Option<String>>(0)).unwrap();
    let mut out = Vec::new();
    for v in rows {
        if let Some(v) = v.unwrap() {
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
    }
    out
}

/// Deterministic text: `n` characters drawn with a small generator.
fn text(seed: &mut u64, n: usize) -> String {
    (0..n)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            char::from(b'a' + (*seed % 26) as u8)
        })
        .collect()
}

#[test]
fn regions_hold_what_the_engine_reads_at_every_page_size_and_encoding() {
    for page in [512u32, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
            for vacuum in ["NONE", "FULL"] {
                let d = tempfile::tempdir().unwrap();
                let p = d.path().join("t.db");
                let c = Connection::open(&p).unwrap();
                c.execute_batch(&format!(
                    "PRAGMA page_size={page}; PRAGMA encoding='{encoding}';
                     PRAGMA auto_vacuum={vacuum}; PRAGMA synchronous=OFF;
                     PRAGMA journal_mode=MEMORY;
                     CREATE TABLE plain(a TEXT, b TEXT, n INTEGER);
                     CREATE TABLE nokey(b TEXT, a TEXT, c TEXT,
                                        PRIMARY KEY(a, b)) WITHOUT ROWID;
                     CREATE TABLE gen(a TEXT, g TEXT AS (a || 'x') VIRTUAL,
                                      s TEXT AS (a || 'y') STORED, z TEXT);
                     CREATE TABLE grown(a TEXT);
                     CREATE INDEX plain_a ON plain(a);"
                ))
                .unwrap();
                let mut seed = 0x9E37_79B9_7F4A_7C15u64 ^ u64::from(page);
                for i in 0..300 {
                    // Mostly short values, and some long enough to overflow.
                    let long = if i % 37 == 0 { 3 * page as usize } else { 40 };
                    let (a, b, z) = (
                        text(&mut seed, 20),
                        text(&mut seed, long),
                        text(&mut seed, 9),
                    );
                    c.execute(
                        "INSERT INTO plain VALUES (?1, ?2, ?3)",
                        params![a, if i % 5 == 0 { None } else { Some(b.clone()) }, i],
                    )
                    .unwrap();
                    c.execute(
                        "INSERT INTO nokey VALUES (?1, ?2, ?3)",
                        params![z, format!("{a}{i}"), b],
                    )
                    .unwrap();
                    c.execute("INSERT INTO gen(a, z) VALUES (?1, ?2)", params![a, z])
                        .unwrap();
                    if i == 150 {
                        c.execute_batch("ALTER TABLE grown ADD COLUMN later TEXT;")
                            .unwrap();
                    }
                    c.execute("INSERT INTO grown(a) VALUES (?1)", params![z])
                        .unwrap();
                }
                c.execute_batch("UPDATE grown SET later = a WHERE rowid % 2 = 0;")
                    .unwrap();

                let limits = Limits {
                    container_bytes: 1 << 28,
                    member_bytes: 1 << 28,
                    text_max: 1 << 28,
                    ..Limits::default()
                };
                let x = extract(&fs::read(&p).unwrap(), &limits);
                assert_eq!(
                    x.status(),
                    TargetStatus::Scanned,
                    "{page} {encoding} {vacuum}"
                );
                let got = regions(&x);
                for (name, query) in [
                    ("plain/a", "SELECT a FROM plain ORDER BY rowid"),
                    ("plain/b", "SELECT b FROM plain ORDER BY rowid"),
                    ("nokey/a", "SELECT a FROM nokey ORDER BY a, b"),
                    ("nokey/b", "SELECT b FROM nokey ORDER BY a, b"),
                    ("nokey/c", "SELECT c FROM nokey ORDER BY a, b"),
                    ("gen/a", "SELECT a FROM gen ORDER BY rowid"),
                    ("gen/s", "SELECT s FROM gen ORDER BY rowid"),
                    ("gen/z", "SELECT z FROM gen ORDER BY rowid"),
                    ("grown/a", "SELECT a FROM grown ORDER BY rowid"),
                    ("grown/later", "SELECT later FROM grown ORDER BY rowid"),
                ] {
                    let want = expected(&c, query);
                    let have = got
                        .get(name)
                        .unwrap_or_else(|| panic!("{name} missing at {page} {encoding} {vacuum}"));
                    assert!(
                        have == &want,
                        "{name} differs at {page} {encoding} {vacuum}"
                    );
                }
                assert!(!got.contains_key("plain/n"), "integers are not text");
                assert!(!got.keys().any(|k| k.starts_with("gen/g")), "not stored");
                assert!(!got.keys().any(|k| k.starts_with("plain_a")), "indexes");
            }
        }
    }
}

#[test]
fn the_schema_text_is_scanned_under_its_own_name() {
    let key = aws(6);
    let x = read(&format!(
        "CREATE TABLE t(v TEXT DEFAULT '{key}');
         CREATE VIEW w AS SELECT '{key}' AS k;
         CREATE TRIGGER tr AFTER INSERT ON t BEGIN SELECT '{key}'; END;"
    ));
    assert_eq!(x.status(), TargetStatus::Scanned);
    let got = regions(&x);
    let sql = got.get("sqlite_schema/sql").expect("schema region");
    assert!(contains(sql, b"CREATE TABLE t"));
    assert!(contains(sql, b"CREATE VIEW w"));
    assert!(contains(sql, b"CREATE TRIGGER tr"));
}

#[test]
fn a_view_has_no_region_of_its_own() {
    let x = read(
        "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('row');
         CREATE VIEW w AS SELECT v FROM t;",
    );
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert!(regions(&x).keys().all(|k| !k.starts_with("w/")));
}

#[test]
fn a_virtual_table_is_read_through_its_shadow_tables() {
    let key = aws(7);
    let x = read(&format!(
        "CREATE VIRTUAL TABLE docs USING fts5(body);
         INSERT INTO docs VALUES ('{key}');"
    ));
    assert_eq!(x.status(), TargetStatus::Scanned);
    let got = regions(&x);
    assert!(
        got.keys().all(|k| !k.starts_with("docs/")),
        "{:?}",
        got.keys()
    );
    assert!(contains(
        got.get("docs_content/c0").expect("shadow table"),
        key.as_bytes()
    ));
}

#[test]
fn deleted_rows_in_free_pages_and_unused_space_are_read() {
    let key = aws(8);
    let tail = aws(9);
    let long = "x".repeat(20_000);
    let x = read(&format!(
        "PRAGMA secure_delete=OFF;
         CREATE TABLE t(v TEXT);
         INSERT INTO t VALUES ('{key}{long}');
         INSERT INTO t VALUES ('kept');
         INSERT INTO t VALUES ('{tail}');
         DELETE FROM t WHERE v LIKE '%xxx%';
         DELETE FROM t WHERE v <> 'kept';"
    ));
    assert_eq!(x.status(), TargetStatus::Scanned);
    let got = regions(&x);
    assert!(!contains(got.get("t/v").unwrap(), key.as_bytes()));
    let unused = got.get("unused!").expect("unused-space region");
    assert!(
        contains(unused, tail.as_bytes()),
        "freeblock in a live page"
    );
}

// ---- Blobs -----------------------------------------------------------------

#[test]
fn blob_cells_are_scanned_as_bytes_or_opened_by_their_format() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("b.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE b(id INTEGER PRIMARY KEY, data BLOB, note TEXT);")
        .unwrap();
    let in_text_blob = aws(10);
    let in_zip = aws(11);
    let zip = synth::zip(&[("a.env", format!("K={in_zip}\n").into_bytes())]);
    let png: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    let random: Vec<u8> = (0u32..2000)
        .map(|i| (i.wrapping_mul(167) >> 2) as u8)
        .collect();
    for v in [
        in_text_blob.as_bytes(),
        zip.as_slice(),
        png,
        random.as_slice(),
    ] {
        c.execute("INSERT INTO b(data) VALUES (?1)", params![v])
            .unwrap();
    }
    c.close().unwrap();
    age(&p);

    let x = extract(&fs::read(&p).unwrap(), &Limits::default());
    assert_eq!(x.status(), TargetStatus::Scanned);
    let got = regions(&x);
    let bytes = got.get("b/data").expect("bytes region");
    assert!(contains(bytes, in_text_blob.as_bytes()));
    assert!(
        contains(bytes, &random[..64]),
        "unknown binary is read as bytes"
    );
    assert!(!contains(bytes, png), "an image is skipped");
    assert_eq!(x.skipped, 1, "the image");
    assert_eq!(x.opened, 1, "the zip");
    assert!(got.contains_key("b/data!blob!1!/a.env"), "{:?}", got.keys());

    let r = scan(&mut scanner(), &p);
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    let c = t.container.as_ref().unwrap();
    assert_eq!(
        c.members,
        c.scanned + c.read_in_part + c.skipped + c.not_read + c.opened
    );
}

#[test]
fn many_small_images_do_not_use_up_the_member_limit() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("b.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE b(data BLOB); CREATE TABLE later(v TEXT); BEGIN;")
        .unwrap();
    let png: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
    for _ in 0..1500 {
        c.execute("INSERT INTO b VALUES (?1)", params![png])
            .unwrap();
    }
    c.execute_batch("INSERT INTO later VALUES ('after'); COMMIT;")
        .unwrap();
    c.close().unwrap();
    let x = extract(&fs::read(&p).unwrap(), &Limits::default());
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert_eq!(x.skipped, 1500);
    assert!(regions(&x).contains_key("later/v"));
}

// ---- Limits ----------------------------------------------------------------

/// `rows` rows of about 1 KiB each, with `head` in the first row, `mid` in the
/// middle one, and `tail` in the last.
fn big_table(c: &Connection, table: &str, rows: usize, head: &str, mid: &str, tail: &str) {
    c.execute_batch(&format!("CREATE TABLE {table}(v TEXT); BEGIN;"))
        .unwrap();
    let mut seed = 77u64;
    for i in 0..rows {
        let v = match i {
            0 => head.to_string(),
            i if i == rows / 2 => mid.to_string(),
            i if i == rows - 1 => tail.to_string(),
            _ => text(&mut seed, 1000),
        };
        c.execute(&format!("INSERT INTO {table} VALUES (?1)"), params![v])
            .unwrap();
    }
    c.execute_batch("COMMIT;").unwrap();
}

#[test]
fn past_the_byte_budget_a_table_is_read_at_both_ends_and_partial() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("big.db");
    let c = Connection::open(&p).unwrap();
    let (head, mid, tail) = (aws(12), aws(13), aws(14));
    big_table(&c, "big", 2000, &head, &mid, &tail);
    c.close().unwrap();
    age(&p);

    let limits = Limits {
        container_bytes: 256 * 1024,
        ..Limits::default()
    };
    let x = extract(&fs::read(&p).unwrap(), &limits);
    let got = regions(&x);
    let v = got.get("big/v").expect("region");
    assert!(contains(v, head.as_bytes()), "oldest rows");
    assert!(contains(v, tail.as_bytes()), "newest rows");
    assert!(!contains(v, mid.as_bytes()), "the middle is not read");
    assert!(v.len() as u64 <= limits.container_bytes);
    assert!(matches!(x.status(), TargetStatus::Partial { .. }));

    let cfg = Config {
        limits,
        ..Config::default()
    };
    let r = scan(&mut scanner_with(cfg), &p);
    let t = only(&r);
    assert!(partial(t).contains("rows not read"), "{}", partial(t));
    assert!(t.container.as_ref().unwrap().read_in_part >= 1);
}

#[test]
fn a_large_table_does_not_starve_the_small_ones_after_it() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("big.db");
    let c = Connection::open(&p).unwrap();
    big_table(&c, "aaa_big", 4000, "h", "m", "t");
    let key = aws(15);
    c.execute_batch(&format!(
        "CREATE TABLE small1(v TEXT); INSERT INTO small1 VALUES ('{key}');
         CREATE TABLE small2(v TEXT); INSERT INTO small2 VALUES ('two');"
    ))
    .unwrap();
    c.close().unwrap();
    let limits = Limits {
        container_bytes: 512 * 1024,
        ..Limits::default()
    };
    let x = extract(&fs::read(&p).unwrap(), &limits);
    let got = regions(&x);
    assert!(contains(got.get("small1/v").unwrap(), key.as_bytes()));
    assert!(got.contains_key("small2/v"));
    // What the small tables leave goes to the large one.
    let big = got.get("aaa_big/v").unwrap().len() as u64;
    assert!(big > limits.container_bytes / 2, "{big}");
}

#[test]
fn a_database_that_fits_the_budget_is_read_whole() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("fits.db");
    let c = Connection::open(&p).unwrap();
    big_table(&c, "a", 1000, "h", "m", "t");
    big_table(&c, "b", 3000, "h", "m", "t");
    c.close().unwrap();
    let x = extract(&fs::read(&p).unwrap(), &Limits::default());
    assert_eq!(x.status(), TargetStatus::Scanned);
}

/// A region's cells, sorted: when the passes meet, what lies between them is
/// read exactly once.
fn sorted_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = bytes.split(|&b| b == b'\n').map(<[u8]>::to_vec).collect();
    v.sort();
    v
}

#[test]
fn when_both_passes_meet_every_row_is_read_exactly_once() {
    for (table, create, query) in [
        (
            "plain",
            "CREATE TABLE plain(k TEXT, v TEXT);",
            "SELECT v FROM plain",
        ),
        (
            "nokey",
            "CREATE TABLE nokey(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;",
            "SELECT v FROM nokey",
        ),
    ] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.db");
        let c = Connection::open(&p).unwrap();
        c.execute_batch(create).unwrap();
        c.execute_batch("BEGIN;").unwrap();
        let mut seed = 99u64;
        for i in 0..3000 {
            let v = text(&mut seed, 60);
            c.execute(
                &format!("INSERT INTO {table} VALUES (?1, ?2)"),
                params![format!("{i:05}"), v],
            )
            .unwrap();
        }
        c.execute_batch("COMMIT;").unwrap();
        let bytes = fs::read(&p).unwrap();
        // The table is over half of the budget, so the first pass stops short.
        let limits = Limits {
            container_bytes: bytes.len() as u64 + 16,
            ..Limits::default()
        };
        let x = extract(&bytes, &limits);
        assert_eq!(x.status(), TargetStatus::Scanned, "{table}");
        let got = regions(&x);
        let want = sorted_lines(&expected(&c, query));
        assert!(
            sorted_lines(got.get(&format!("{table}/v")).unwrap()) == want,
            "{table}"
        );
    }
}

#[test]
fn a_database_of_many_tiny_rows_that_fits_is_read_whole() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("tiny.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE t(v TEXT); BEGIN;").unwrap();
    for _ in 0..200_000 {
        c.execute("INSERT INTO t VALUES ('')", []).unwrap();
    }
    c.execute_batch("COMMIT;").unwrap();
    c.close().unwrap();
    let bytes = fs::read(&p).unwrap();
    assert!(bytes.len() < (1 << 23));
    assert_eq!(
        extract(&bytes, &Limits::default()).status(),
        TargetStatus::Scanned
    );
}

#[test]
fn a_very_wide_row_past_the_member_limit_is_partial_and_never_clean() {
    let cols: Vec<String> = (0..1500).map(|i| format!("c{i} TEXT")).collect();
    let vals: Vec<String> = (0..1500).map(|i| format!("'v{i}'")).collect();
    let x = read(&format!(
        "CREATE TABLE wide({}); INSERT INTO wide VALUES ({});",
        cols.join(","),
        vals.join(",")
    ));
    assert_eq!(x.members.len(), 1000);
    let TargetStatus::Partial { not_read } = x.status() else {
        panic!("{:?}", x.status())
    };
    assert!(not_read.contains("limits.container_members"), "{not_read}");
}

#[test]
fn a_cell_past_the_byte_budget_is_cut_and_partial() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("cell.db");
    let c = Connection::open(&p).unwrap();
    let head = aws(16);
    c.execute_batch("CREATE TABLE t(a TEXT, b TEXT);").unwrap();
    let body = format!("{head}{}", "y".repeat(3 << 20));
    c.execute("INSERT INTO t VALUES (?1, 'after')", params![body])
        .unwrap();
    c.close().unwrap();
    let limits = Limits {
        container_bytes: 1 << 20,
        ..Limits::default()
    };
    let x = extract(&fs::read(&p).unwrap(), &limits);
    let got = regions(&x);
    let a = got.get("t/a").unwrap();
    assert!(contains(a, head.as_bytes()));
    assert!(a.len() as u64 <= limits.container_bytes);
    assert!(matches!(x.status(), TargetStatus::Partial { .. }));
}

#[test]
fn a_cell_over_half_of_the_budget_is_read_whole() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("cell.db");
    let c = Connection::open(&p).unwrap();
    let tail = aws(21);
    // Free pages make the file larger than the budget, so that shares apply.
    c.execute_batch(
        "CREATE TABLE gone(a BLOB); INSERT INTO gone VALUES (zeroblob(1500000));
         CREATE TABLE t(a TEXT); DROP TABLE gone;",
    )
    .unwrap();
    let body = format!("{}{tail}", "y".repeat(700_000));
    c.execute("INSERT INTO t VALUES (?1)", params![body])
        .unwrap();
    c.close().unwrap();
    let bytes = fs::read(&p).unwrap();
    let limits = Limits {
        container_bytes: 1 << 20,
        ..Limits::default()
    };
    assert!(bytes.len() as u64 > limits.container_bytes);
    let x = extract(&bytes, &limits);
    assert!(contains(regions(&x).get("t/a").unwrap(), tail.as_bytes()));
}

#[test]
fn past_the_time_budget_it_is_never_clean() {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "t.db",
        "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('x');",
    );
    let bytes = fs::read(&p).unwrap();
    let past = Instant::now() - Duration::from_secs(1);
    let x = container::extract(
        &SQLITE,
        &bytes.as_slice(),
        bytes.len() as u64,
        &Limits::default(),
        past,
    );
    assert!(!matches!(x.status(), TargetStatus::Scanned));

    let mut cfg = Config::default();
    cfg.limits.time_budget = Duration::ZERO;
    let r = scan(&mut scanner_with(cfg), &p);
    assert!(!matches!(only(&r).status, TargetStatus::Scanned));
}

#[test]
fn whole_databases_are_cached_and_partial_ones_are_not() {
    let d = tempfile::tempdir().unwrap();
    let key = aws(17);
    let p = db(
        d.path(),
        "app.db",
        &format!("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('{key}');"),
    );
    let mut g = scanner();
    let first = scan(&mut g, &p);
    let again = {
        let mut g2 = scanner();
        let r = scan(&mut g2, &p);
        assert!(!g2.bundle_loaded(), "answered from the cache");
        r
    };
    assert_eq!(only(&first).scores, only(&again).scores);
    assert_eq!(only(&first).evidence.len(), only(&again).evidence.len());
    assert_eq!(
        only(&again).container.as_ref().unwrap().format,
        "sqlite",
        "the member table survives"
    );

    // No matched bytes reach the cache.
    g.close_cache();
    for e in fs::read_dir(shared_cache()).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            let bytes = fs::read(e.path()).unwrap();
            assert!(!contains(&bytes, key.as_bytes()), "{:?}", e.file_name());
        }
    }

    let p = db(
        d.path(),
        "other.db",
        "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('read in part');",
    );
    let mut cfg = Config::default();
    cfg.limits.container_bytes = 4;
    let r = scan(&mut scanner_with(cfg.clone()), &p);
    assert!(!matches!(only(&r).status, TargetStatus::Scanned));
    let mut g2 = scanner_with(cfg);
    scan(&mut g2, &p);
    assert!(g2.bundle_loaded(), "a partial database is scanned again");
}

// ---- Encrypted --------------------------------------------------------------

/// `n` bytes that look like ciphertext, from a fixed seed.
fn noise(n: usize) -> Vec<u8> {
    let mut x = 0x1234_5678_9ABC_DEF1u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect()
}

#[test]
fn an_encrypted_database_is_unscanned() {
    let d = tempfile::tempdir().unwrap();
    // SQLCipher's default layout: all of the file looks random, salt first.
    for name in [
        "vault.db",
        "vault.sqlite",
        "vault.sqlite3",
        "vault.db3",
        "vault.sqlcipher",
    ] {
        let p = d.path().join(name);
        fs::write(&p, noise(4096 * 4)).unwrap();
        let r = scan(&mut scanner(), &p);
        assert!(unscanned(only(&r)).contains("encrypted"), "{name}");
    }
    // A plaintext header (`cipher_plaintext_header_size`): the magic and the
    // first bytes are there, and the rest of page 1 is ciphertext.
    let p = d.path().join("header.db");
    let mut bytes = noise(4096 * 4);
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    bytes[16..18].copy_from_slice(&4096u16.to_be_bytes());
    bytes[18] = 1;
    bytes[19] = 1;
    bytes[20] = 80;
    bytes[21] = 64;
    bytes[22] = 32;
    bytes[23] = 32;
    // Not a b-tree page type, as about 98% of random bytes are not.
    bytes[100] = 0x55;
    fs::write(&p, &bytes).unwrap();
    let r = scan(&mut scanner(), &p);
    assert!(unscanned(only(&r)).contains("encrypted"), "{r:?}");

    // Inside an archive it makes the archive partial.
    let z = synth::zip(&[("vault.db", noise(4096)), ("a.txt", b"hello\n".to_vec())]);
    let zp = d.path().join("backup.zip");
    fs::write(&zp, z).unwrap();
    let r = scan(&mut scanner(), &zp);
    assert!(partial(only(&r)).contains("encrypted"));
}

#[test]
fn other_binaries_with_a_database_name_or_random_bytes_stay_skipped() {
    let d = tempfile::tempdir().unwrap();
    // Random bytes under a name that says nothing about a database.
    let p = d.path().join("blob.bin");
    fs::write(&p, noise(4096 * 4)).unwrap();
    assert!(matches!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Skipped { .. }
    ));
    // A database name, but structured bytes (other engines use `.db` too).
    let p = d.path().join("thumbs.db");
    let mut bytes = vec![0u8; 4096 * 4];
    bytes[0] = 0xD0;
    fs::write(&p, &bytes).unwrap();
    assert!(matches!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Skipped { .. }
    ));
    // Random bytes that are not whole pages of any size SQLite uses.
    let p = d.path().join("short.db");
    fs::write(&p, noise(4097)).unwrap();
    assert!(matches!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Skipped { .. }
    ));
}

// ---- Malformed and hostile --------------------------------------------------

/// A database with interior pages, overflow chains, a WITHOUT ROWID table, and
/// free pages, and its page size.
fn sample_db() -> (Vec<u8>, usize) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("s.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch(
        "PRAGMA page_size=512;
         CREATE TABLE t(a TEXT, b BLOB);
         CREATE TABLE k(a TEXT PRIMARY KEY, b TEXT) WITHOUT ROWID;
         CREATE TABLE doomed(a TEXT);
         BEGIN;",
    )
    .unwrap();
    let mut seed = 5u64;
    for i in 0..120 {
        let n = if i % 10 == 0 { 2000 } else { 30 };
        let v = text(&mut seed, n);
        c.execute("INSERT INTO t VALUES (?1, ?2)", params![v, v.as_bytes()])
            .unwrap();
        c.execute(
            "INSERT INTO k VALUES (?1, ?2)",
            params![format!("{i}{v}"), v],
        )
        .unwrap();
        c.execute("INSERT INTO doomed VALUES (?1)", params![v])
            .unwrap();
    }
    c.execute_batch("COMMIT; DROP TABLE doomed;").unwrap();
    c.close().unwrap();
    (fs::read(&p).unwrap(), 512)
}

/// The bytes of page `n` (1-based).
fn page_at(page: usize, n: u32) -> std::ops::Range<usize> {
    let at = (n as usize - 1) * page;
    at..at + page
}

/// The number of an interior table page, found by reading headers.
fn an_interior_page(bytes: &[u8], page: usize) -> u32 {
    (2..=(bytes.len() / page) as u32)
        .find(|&n| bytes[page_at(page, n).start] == 5)
        .expect("an interior table page")
}

fn check_terminates(bytes: &[u8], what: &str) {
    let start = Instant::now();
    let limits = Limits::default();
    let x = extract(bytes, &limits);
    // Whatever it says, it says it quickly and within the budgets.
    assert!(start.elapsed() < Duration::from_secs(5), "{what}");
    let held: u64 = x.members.iter().map(|m| m.content.bytes.len() as u64).sum();
    assert!(held <= limits.container_bytes, "{what}: {held}");
}

#[test]
fn every_truncation_terminates_and_never_reads_clean() {
    let (bytes, page) = sample_db();
    let mut n = bytes.len();
    while n > 0 {
        n = n.saturating_sub(page.max(bytes.len() / 64));
        let cut = &bytes[..n];
        check_terminates(cut, "truncated");
        if n > 0 && n + page / 2 < bytes.len() {
            let x = extract(cut, &Limits::default());
            assert_ne!(x.status(), TargetStatus::Scanned, "cut to {n}");
        }
    }
    // A cut inside a page leaves bytes no page holds.
    let cut = &bytes[..bytes.len() - page / 2];
    assert_ne!(
        extract(cut, &Limits::default()).status(),
        TargetStatus::Scanned
    );
}

#[test]
fn a_page_that_points_at_itself_terminates() {
    let (mut bytes, page) = sample_db();
    let n = an_interior_page(&bytes, page);
    let at = page_at(page, n).start;
    bytes[at + 8..at + 12].copy_from_slice(&n.to_be_bytes());
    check_terminates(&bytes, "self child");
    let x = extract(&bytes, &Limits::default());
    assert!(
        matches!(x.status(), TargetStatus::Partial { .. }),
        "{:?}",
        x.status()
    );
}

#[test]
fn an_overflow_chain_that_loops_terminates() {
    let (mut bytes, page) = sample_db();
    // Every overflow page: point each at itself, whatever it is.
    for n in 2..=(bytes.len() / page) as u32 {
        let r = page_at(page, n);
        if ![2, 5, 10, 13].contains(&bytes[r.start]) {
            bytes[r.start..r.start + 4].copy_from_slice(&n.to_be_bytes());
        }
    }
    check_terminates(&bytes, "overflow loop");
}

#[test]
fn cell_counts_and_pointers_past_the_page_terminate() {
    let (bytes, page) = sample_db();
    for n in 1..=(bytes.len() / page) as u32 {
        let mut b = bytes.clone();
        let at = page_at(page, n).start + if n == 1 { 100 } else { 0 };
        // Claims the most cells a page header can.
        b[at + 3] = 0xFF;
        b[at + 4] = 0xFF;
        check_terminates(&b, "cell count");
    }
    let mut b = bytes.clone();
    for byte in &mut b[100..page] {
        *byte = 0xFF;
    }
    check_terminates(&b, "page 1 all ones");
}

#[test]
fn a_varint_claiming_an_enormous_payload_terminates() {
    let (bytes, page) = sample_db();
    let mut hit = 0;
    for n in 2..=(bytes.len() / page) as u32 {
        let r = page_at(page, n);
        if bytes[r.start] != 13 {
            continue;
        }
        let ptr = u16::from_be_bytes([bytes[r.start + 8], bytes[r.start + 9]]) as usize;
        let mut b = bytes.clone();
        for i in 0..8 {
            b[r.start + ptr + i] = 0xFF;
        }
        check_terminates(&b, "huge varint");
        hit += 1;
    }
    assert!(hit > 0);
}

#[test]
fn random_damage_never_panics_or_hangs() {
    let (bytes, page) = sample_db();
    let mut x = 0xDEAD_BEEF_CAFE_F00Du64;
    let mut next = move |n: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % n as u64) as usize
    };
    for round in 0..3000 {
        let mut b = bytes.clone();
        match round % 3 {
            0 => {
                for _ in 0..1 + next(8) {
                    let at = next(b.len());
                    b[at] = next(256) as u8;
                }
            }
            1 => {
                // Damage only page headers and cell pointers.
                let n = next(b.len() / page);
                for _ in 0..4 {
                    let at = n * page + next(32);
                    b[at] = next(256) as u8;
                }
            }
            _ => {
                // One whole page of noise.
                let n = 1 + next(b.len() / page - 1);
                let start = n * page;
                for byte in &mut b[start..start + page] {
                    *byte = next(256) as u8;
                }
            }
        }
        check_terminates(&b, "random damage");
    }
}

#[test]
fn a_database_of_only_a_header_is_not_clean() {
    let (bytes, _) = sample_db();
    for n in [16usize, 99, 100, 101, 107] {
        let x = extract(&bytes[..n], &Limits::default());
        assert!(
            matches!(x.status(), TargetStatus::Unscanned { .. }),
            "{n}: {:?}",
            x.status()
        );
    }
}

#[test]
fn a_bad_page_in_a_table_makes_the_database_partial() {
    let (mut bytes, page) = sample_db();
    let n = (2..=(bytes.len() / page) as u32)
        .find(|&n| bytes[page_at(page, n).start] == 13)
        .unwrap();
    let r = page_at(page, n);
    bytes[r].fill(0xEE);
    let x = extract(&bytes, &Limits::default());
    let TargetStatus::Partial { not_read } = x.status() else {
        panic!("{:?}", x.status())
    };
    assert!(not_read.contains("unreadable"), "{not_read}");
}

#[test]
fn a_tree_that_leads_back_on_itself_does_not_read_as_whole() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("m.db");
    let c = Connection::open(&p).unwrap();
    big_table(&c, "big", 3000, "h", "m", "t");
    let root: u32 = c
        .query_row("SELECT rootpage FROM sqlite_master", [], |r| r.get(0))
        .unwrap();
    c.close().unwrap();
    let mut bytes = fs::read(&p).unwrap();
    let at = page_at(4096, root).start;
    assert_eq!(bytes[at], 5, "the root is an interior page");
    // The root's rightmost child is now its first, so the second pass reaches
    // what the first read while most of the table lies elsewhere.
    let first_cell = u16::from_be_bytes([bytes[at + 12], bytes[at + 13]]) as usize;
    let first_child: [u8; 4] = bytes[at + first_cell..at + first_cell + 4]
        .try_into()
        .unwrap();
    bytes[at + 8..at + 12].copy_from_slice(&first_child);
    let limits = Limits {
        container_bytes: 64 * 1024,
        ..Limits::default()
    };
    let x = extract(&bytes, &limits);
    assert!(
        matches!(x.status(), TargetStatus::Partial { .. }),
        "{:?}",
        x.status()
    );
}

#[test]
fn pages_nothing_reaches_make_a_database_partial() {
    let d = tempfile::tempdir().unwrap();
    let key = aws(18);
    let p = db(
        d.path(),
        "hidden.db",
        &format!("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('{key}');"),
    );
    let mut bytes = fs::read(&p).unwrap();
    // An emptied schema: the table's page is still in the file.
    bytes[103] = 0;
    bytes[104] = 0;
    let TargetStatus::Partial { not_read } = extract(&bytes, &Limits::default()).status() else {
        panic!("an emptied schema must not read as a clean database");
    };
    assert!(
        not_read.contains("outside the listed members"),
        "{not_read}"
    );
}

#[test]
fn indexes_overflow_chains_and_pointer_maps_count_as_reached() {
    let d = tempfile::tempdir().unwrap();
    let long = "z".repeat(9000);
    let p = db(
        d.path(),
        "reach.db",
        &format!(
            "PRAGMA auto_vacuum=FULL;
             CREATE TABLE t(a TEXT, b TEXT);
             CREATE INDEX t_a ON t(a);
             CREATE UNIQUE INDEX t_b ON t(b);
             INSERT INTO t VALUES ('{long}', 'one');
             INSERT INTO t VALUES ('{long}x', 'two');"
        ),
    );
    let x = extract(&fs::read(p).unwrap(), &Limits::default());
    assert_eq!(x.status(), TargetStatus::Scanned);
}

#[test]
fn a_table_read_to_its_end_is_whole_when_its_rows_use_up_the_share() {
    // Rows mostly of integers: the bytes read pass the share while the text
    // they yield fits it, and the only leaf is read in one pass.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("ints.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch(
        "PRAGMA page_size=65536;
         CREATE TABLE t(v TEXT, a, b, c, d, e, f, g, h);
         BEGIN;",
    )
    .unwrap();
    let big = 1i64 << 60;
    for _ in 0..100 {
        c.execute(
            "INSERT INTO t VALUES ('short', ?1, ?1, ?1, ?1, ?1, ?1, ?1, ?1)",
            params![big],
        )
        .unwrap();
    }
    c.execute_batch("COMMIT;").unwrap();
    c.close().unwrap();
    let limits = Limits {
        container_bytes: 3000,
        ..Limits::default()
    };
    let x = extract(&fs::read(&p).unwrap(), &limits);
    assert_eq!(x.status(), TargetStatus::Scanned);
}

#[test]
fn a_zeroed_persistent_journal_holds_nothing_unmerged() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("app.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode=PERSIST;
         CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('ok');",
    )
    .unwrap();
    c.close().unwrap();
    assert!(fs::metadata(d.path().join("app.db-journal")).unwrap().len() > 0);
    age(&p);
    assert_eq!(
        only(&scan(&mut scanner(), &p)).status,
        TargetStatus::Scanned
    );
}

#[test]
fn a_row_cut_inside_its_header_is_not_reported_as_damage() {
    let cols: Vec<String> = (0..500).map(|i| format!("c{i} TEXT")).collect();
    let cell = "w".repeat(100);
    let vals: Vec<String> = (0..500).map(|_| format!("'{cell}'")).collect();
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "wide.db",
        &format!(
            "PRAGMA page_size=512; CREATE TABLE wide({}); INSERT INTO wide VALUES ({});",
            cols.join(","),
            vals.join(",")
        ),
    );
    let bytes = fs::read(p).unwrap();
    // The schema statement is about 5 KiB, and rows get what it leaves. Some
    // budget in this range cuts the record inside a two-byte serial type.
    for extra in 0..64 {
        let limits = Limits {
            container_bytes: 6000 + extra,
            ..Limits::default()
        };
        let TargetStatus::Partial { not_read } = extract(&bytes, &limits).status() else {
            continue;
        };
        assert!(!not_read.contains("unreadable"), "{extra}: {not_read}");
    }
}

#[test]
fn free_pages_are_scanned_and_count_as_reached() {
    let key = aws(19);
    let fill = "f".repeat(30_000);
    let x = read(&format!(
        "PRAGMA secure_delete=OFF;
         CREATE TABLE gone(v TEXT);
         CREATE TABLE kept(v TEXT);
         INSERT INTO gone VALUES ('{fill}{key}{fill}');
         INSERT INTO kept VALUES ('here');
         DROP TABLE gone;"
    ));
    assert_eq!(x.status(), TargetStatus::Scanned);
    let got = regions(&x);
    assert!(!got.keys().any(|k| k.starts_with("gone/")));
    assert!(contains(
        got.get("unused!").expect("free pages"),
        key.as_bytes()
    ));
}

#[test]
fn a_database_in_a_blob_cell_is_opened() {
    let d = tempfile::tempdir().unwrap();
    let key = aws(20);
    let inner = db(
        d.path(),
        "inner.db",
        &format!("CREATE TABLE s(v TEXT); INSERT INTO s VALUES ('{key}');"),
    );
    let p = d.path().join("outer.db");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE files(name TEXT, data BLOB);")
        .unwrap();
    c.execute(
        "INSERT INTO files VALUES ('x', ?1)",
        params![fs::read(&inner).unwrap()],
    )
    .unwrap();
    c.close().unwrap();
    let x = extract(&fs::read(&p).unwrap(), &Limits::default());
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert_eq!(x.opened, 1);
    let got = regions(&x);
    assert!(contains(
        got.get("files/data!blob!1!/s/v").expect("nested region"),
        key.as_bytes()
    ));
}

/// A database of one short row, and the offset of its record in the file.
fn one_row_db() -> (Vec<u8>, usize) {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "r.db",
        "CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('a short text value');",
    );
    let bytes = fs::read(p).unwrap();
    let page = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    assert_eq!(bytes[page], 13, "page 2 is the table's leaf");
    let cell = u16::from_be_bytes([bytes[page + 8], bytes[page + 9]]) as usize;
    // One byte each for the payload size and the rowid.
    (bytes, page + cell + 2)
}

#[test]
fn a_record_whose_header_runs_past_its_payload_is_damage() {
    let (mut bytes, record) = one_row_db();
    bytes[record] = 0x7F;
    let TargetStatus::Partial { not_read } = extract(&bytes, &Limits::default()).status() else {
        panic!("a record that was not read must not read as clean");
    };
    assert!(not_read.contains("unreadable"), "{not_read}");
}

#[test]
fn a_value_that_runs_past_its_payload_is_damage() {
    let (mut bytes, record) = one_row_db();
    // The text's serial type: a value far longer than the payload.
    bytes[record + 1] = 0x7F;
    let TargetStatus::Partial { not_read } = extract(&bytes, &Limits::default()).status() else {
        panic!("a record that does not add up must not read as clean");
    };
    assert!(not_read.contains("unreadable"), "{not_read}");
}

#[test]
fn a_vast_sparse_file_stays_within_the_time_budget() {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "vast.db",
        "PRAGMA page_size=512; CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('x');",
    );
    // The change counter no longer matches, so the size comes from the file.
    let f = File::options().read(true).write(true).open(&p).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&f, &[0xAB], 27).unwrap();
    f.set_len(1 << 40).unwrap();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(2);
    let x = container::extract(&SQLITE, &f, 1 << 40, &Limits::default(), deadline);
    assert!(start.elapsed() < Duration::from_secs(4));
    assert!(matches!(x.status(), TargetStatus::Partial { .. }));
}

/// How much of a large database is read, and how long a scan takes. Run with
/// `--release`; generating the largest takes a minute or so.
#[test]
#[ignore]
fn how_much_of_a_large_database_is_read() {
    for mib in [32u64, 64, 256, 1024] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("large.db");
        let c = Connection::open(&p).unwrap();
        c.execute_batch(
            "PRAGMA synchronous=OFF; PRAGMA journal_mode=MEMORY;
             CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
             CREATE TABLE message(id INTEGER PRIMARY KEY, sent INTEGER, body TEXT);
             CREATE INDEX message_sent ON message(sent);
             INSERT INTO settings VALUES ('theme', 'dark');",
        )
        .unwrap();
        let mut seed = 31u64;
        let mut text_bytes = 0u64;
        let mut i = 0i64;
        while fs::metadata(&p).unwrap().len() < mib << 20 {
            c.execute_batch("BEGIN;").unwrap();
            for _ in 0..5000 {
                let v = text(&mut seed, 400);
                text_bytes += v.len() as u64 + 1;
                c.execute(
                    "INSERT INTO message(sent, body) VALUES (?1, ?2)",
                    params![i, v],
                )
                .unwrap();
                i += 1;
            }
            c.execute_batch("COMMIT;").unwrap();
        }
        c.close().unwrap();
        age(&p);
        let size = fs::metadata(&p).unwrap().len();
        let f = File::open(&p).unwrap();
        let x = container::extract(
            &SQLITE,
            &f,
            size,
            &Limits::default(),
            Instant::now() + Duration::from_secs(60),
        );
        let body = regions(&x)
            .get("message/body")
            .map_or(0, |b| b.len() as u64);
        let mut g = scanner_with(Config {
            no_cache: true,
            ..Config::default()
        });
        scan(&mut g, &p); // Rules loaded and file in the page cache.
        let start = Instant::now();
        let r = scan(&mut g, &p);
        println!(
            "{size} bytes: {:.1}% of the large table's text read, scan {:?}, {:?}",
            body as f64 * 100.0 / text_bytes as f64,
            start.elapsed(),
            only(&r).status
        );
    }
}

// ---- The column-name signal -------------------------------------------------

#[test]
fn a_credential_named_column_is_a_weak_signal() {
    let d = tempfile::tempdir().unwrap();
    let p = db(
        d.path(),
        "logins.db",
        "CREATE TABLE logins(origin TEXT, username TEXT, password_value BLOB);
         INSERT INTO logins VALUES ('https://example.test', 'someone', x'763130');",
    );
    let r = scan(&mut scanner(), &p);
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert!(t
        .evidence
        .iter()
        .any(|e| e.rule == "sqlite_credential_column"));
    let s = t.scores[&secret()];
    assert!(s > 0.0 && s < 50.0, "weak: {s}");

    // The same statement in an ordinary file means nothing.
    let sql = d.path().join("schema.sql");
    fs::write(&sql, "CREATE TABLE logins(password_value BLOB);\n").unwrap();
    let r = scan(&mut scanner(), &sql);
    assert!(only(&r)
        .evidence
        .iter()
        .all(|e| e.rule != "sqlite_credential_column"));

    // And a column named for something else does not fire.
    let p = db(
        d.path(),
        "plain.db",
        "CREATE TABLE t(title TEXT, passage TEXT);",
    );
    let r = scan(&mut scanner(), &p);
    assert!(only(&r)
        .evidence
        .iter()
        .all(|e| e.rule != "sqlite_credential_column"));
}
