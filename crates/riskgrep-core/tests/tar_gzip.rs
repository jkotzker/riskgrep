//! Tar and gzip through the `RiskGrep` facade: member names, the limits on
//! each layer, links, damage, and caching. Archives are built at run time from
//! synthetic members; secrets are generated and never printed.

use riskgrep_core::classify::{classify, FileClass, Limits};
use riskgrep_core::config::Config;
use riskgrep_core::container::gzip::GZIP;
use riskgrep_core::container::{self, ContainerKind, Extracted, Extractor};
use riskgrep_core::model::{Category, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::suppress::{IgnoreRules, IgnoreSpec};
use riskgrep_core::synth;
use std::fs::{self, File};
use std::io::Write;
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

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    let f = File::options().write(true).open(&p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(60))
        .unwrap();
    p
}

fn scan(g: &mut RiskGrep, p: &Path) -> Report {
    g.scan_paths(&[p.to_path_buf()])
}

/// The one target from scanning `bytes` as a file named `name` in a new
/// directory.
fn scan_named(name: &str, bytes: &[u8], cfg: Config) -> TargetReport {
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), name, bytes);
    let r = scan(&mut scanner_with(cfg), &p);
    assert_eq!(r.targets.len(), 1);
    r.targets[0].clone()
}

fn scan_default(name: &str, bytes: &[u8]) -> TargetReport {
    scan_named(name, bytes, Config::default())
}

fn partial(t: &TargetReport) -> &str {
    match &t.status {
        TargetStatus::Partial { not_read } => not_read,
        other => panic!("expected partial, got {other:?}"),
    }
}

fn unscanned(t: &TargetReport) -> &str {
    match &t.status {
        TargetStatus::Unscanned { reason } => reason,
        other => panic!("expected unscanned, got {other:?}"),
    }
}

fn members_of(t: &TargetReport, rule: &str) -> Vec<String> {
    t.evidence
        .iter()
        .filter(|e| e.rule == rule)
        .filter_map(|e| e.member.clone())
        .collect()
}

/// The stream of `data` with its header's flags set and `fields` after the
/// fixed header, as a gzip writer that stores them would write it.
fn gzip_with_fields(data: &[u8], flags: u8, fields: &[u8]) -> Vec<u8> {
    let plain = synth::gzip(data);
    let mut out = plain[..10].to_vec();
    out[3] = flags;
    out.extend_from_slice(fields);
    out.extend_from_slice(&plain[10..]);
    out
}

fn gzip_named(data: &[u8], name: &str) -> Vec<u8> {
    let mut fields = name.as_bytes().to_vec();
    fields.push(0);
    gzip_with_fields(data, 0x08, &fields)
}

/// A pattern of `n` bytes that deflate cannot shrink much.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut r = synth::Rng::new(seed);
    let mut v = vec![0u8; n];
    r.fill(&mut v);
    v
}

/// Printable text of `n` bytes that deflates to about half its size.
fn prose(n: usize, seed: u64) -> Vec<u8> {
    let mut r = synth::Rng::new(seed);
    (0..n)
        .map(|_| b"abcdefghijklmnop"[(r.next_u64() % 16) as usize])
        .collect()
}

fn extract_gzip(bytes: &[u8], limits: &Limits) -> Extracted {
    container::extract(
        &GZIP,
        &bytes,
        bytes.len() as u64,
        limits,
        Instant::now() + Duration::from_secs(30),
    )
}

// Naming.

#[test]
fn tar_members_are_named_by_their_path_inside() {
    let tar = synth::tar(&[
        ("README.md", text("# Demo\n")),
        ("config/app.ini", aws_file(1)),
    ]);
    let t = scan_default("backup.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(members_of(&t, "aws_access_token"), ["config/app.ini"]);
    assert!(!t.text, "a member cannot be read by line ranges");
    let e = t
        .evidence
        .iter()
        .find(|e| e.rule == "aws_access_token")
        .unwrap();
    assert_eq!(e.locations[0].line_start, 3, "lines are the member's own");
    let c = t.container.as_ref().unwrap();
    assert_eq!(c.format, "tar");
    assert_eq!((c.members, c.scanned, c.skipped, c.not_read), (2, 2, 0, 0));
    assert_eq!(c.listed[0].path, "config/app.ini");
}

#[test]
fn compressed_tar_members_are_named_as_if_the_gzip_were_not_there() {
    let gz = synth::gzip(&synth::tar(&[("config/app.ini", aws_file(2))]));
    for name in ["backup.tar.gz", "backup.tgz"] {
        let t = scan_default(name, &gz);
        assert_eq!(t.status, TargetStatus::Scanned, "{name}");
        assert_eq!(members_of(&t, "aws_access_token"), ["config/app.ini"]);
        let c = t.container.as_ref().unwrap();
        assert_eq!(c.format, "gzip");
        assert_eq!((c.members, c.scanned, c.opened), (1, 1, 0));
    }
}

#[test]
fn a_plain_gzip_is_one_member_named_after_the_file() {
    let t = scan_default("app.log.gz", &synth::gzip(&aws_file(3)));
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["app.log"]);
    assert_eq!(t.container.as_ref().unwrap().members, 1);
}

#[test]
fn a_stored_gzip_name_is_the_member_name() {
    let gz = gzip_named(&aws_file(4), "original.env");
    let t = scan_default("renamed.gz", &gz);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["original.env"]);
}

#[test]
fn a_gzip_without_the_suffix_keeps_the_file_name() {
    let t = scan_default("blob.dat", &synth::gzip(&aws_file(5)));
    assert_eq!(members_of(&t, "aws_access_token"), ["blob.dat"]);
    let t = scan_default(".gz", &synth::gzip(&aws_file(5)));
    assert_eq!(members_of(&t, "aws_access_token"), ["data"]);
}

#[test]
fn a_tgz_holding_no_tar_is_named_like_the_tar_it_claims() {
    let t = scan_default("x.tgz", &synth::gzip(&aws_file(6)));
    assert_eq!(members_of(&t, "aws_access_token"), ["x.tar"]);
}

#[test]
fn a_path_rule_sees_the_name_inside_a_gzip() {
    // `.pem` and friends match on the member's name, as for a loose file.
    let loose = scan_default(".env", &aws_file(7));
    let gz = scan_default(".env.gz", &synth::gzip(&aws_file(7)));
    let rules = |t: &TargetReport| {
        let mut r: Vec<String> = t.evidence.iter().map(|e| e.rule.clone()).collect();
        r.sort();
        r
    };
    assert_eq!(rules(&loose), rules(&gz));
}

#[test]
fn names_are_escaped_and_absolute_or_dotdot_names_are_only_names() {
    let tar = synth::tar(&[
        ("/etc/app.ini", aws_file(8)),
        ("../../up.ini", aws_file(9)),
        ("a\tb.ini", aws_file(10)),
        ("x!/y.ini", aws_file(11)),
    ]);
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "odd.tar", &tar);
    let t = scan(&mut scanner(), &p).targets[0].clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    let mut names = members_of(&t, "aws_access_token");
    names.sort();
    assert_eq!(
        names,
        ["../../up.ini", "/etc/app.ini", "a\\tb.ini", "x!!/y.ini"]
    );
    assert!(!d.path().parent().unwrap().join("up.ini").exists());
}

#[test]
fn gnu_long_names_are_read() {
    let long = format!("{}/app.ini", "d".repeat(180));
    let mut name = long.clone().into_bytes();
    name.push(0);
    let mut tar = synth::tar_entry("././@LongLink", b'L', &name);
    // The GNU magic is what makes the crate treat `L` as a long name.
    let mut gnu = synth::tar_header("short", b'0', aws_file(12).len() as u64);
    gnu[257..265].copy_from_slice(b"ustar  \0");
    synth::tar_seal(&mut gnu);
    tar[257..265].copy_from_slice(b"ustar  \0");
    let mut head = [0u8; 512];
    head.copy_from_slice(&tar[..512]);
    synth::tar_seal(&mut head);
    tar[..512].copy_from_slice(&head);
    tar.extend_from_slice(&gnu);
    let body = aws_file(12);
    tar.extend_from_slice(&body);
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    let t = scan_default("long.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), [long]);
}

/// One PAX record with its length prefix.
fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut len = body.len() + 1;
    while format!("{len}").len() + body.len() != len {
        len = format!("{len}").len() + body.len();
    }
    format!("{len}{body}").into_bytes()
}

#[test]
fn pax_names_and_sizes_are_read() {
    let long = format!("{}/app.ini", "p".repeat(300));
    let body = aws_file(13);
    let mut records = pax_record("path", &long);
    records.extend(pax_record("size", &body.len().to_string()));
    let mut tar = synth::tar_entry("PaxHeaders/x", b'x', &records);
    // The header's own size is zero: the record overrides it.
    tar.extend_from_slice(&synth::tar_header("short", b'0', 0));
    tar.extend_from_slice(&body);
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    let t = scan_default("pax.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), [long]);
    assert_eq!(t.container.as_ref().unwrap().members, 1);
}

#[test]
fn pax_comments_and_vendor_records_are_scanned_and_metadata_is_not() {
    let token = String::from_utf8(aws_file(14)).unwrap().replace('\n', " ");
    let mut records = pax_record("comment", &token);
    records.extend(pax_record("mtime", "1700000000.5"));
    let mut tar = synth::tar_entry("PaxHeaders/x", b'x', &records);
    tar.extend_from_slice(&synth::tar_entry("clean.txt", b'0', b"nothing\n"));
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("c.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["comment!"]);
    let c = t.container.as_ref().unwrap();
    assert_eq!((c.members, c.scanned), (2, 2));
    // Metadata alone adds no member.
    let mut tar = synth::tar_entry("PaxHeaders/x", b'x', &pax_record("mtime", "1.5"));
    tar.extend_from_slice(&synth::tar_entry("clean.txt", b'0', b"nothing\n"));
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("m.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.container.as_ref().unwrap().members, 1);
}

#[test]
fn a_global_pax_header_is_scanned_as_the_comment() {
    let token = String::from_utf8(aws_file(15)).unwrap().replace('\n', " ");
    let mut tar = synth::tar_entry("pax_global_header", b'g', &pax_record("comment", &token));
    tar.extend_from_slice(&synth::tar_entry("clean.txt", b'0', b"nothing\n"));
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("g.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["comment!"]);
}

#[test]
fn a_global_pax_header_is_read_within_its_budget() {
    // One line with no record syntax, so the 1 MiB read holds one bad record.
    let mut tar = synth::tar_entry("pax_global_header", b'g', &vec![b'a'; 3 << 20]);
    tar.extend_from_slice(&synth::tar_entry("a.ini", b'0', &aws_file(45)));
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("g.tar", &tar);
    assert_eq!(t.scores[&secret()], 95.0, "the walk goes on after it");
    let n = (2u64 << 20) + 1;
    assert_eq!(
        partial(&t),
        format!("{n} bytes outside the listed members not read")
    );
}

#[test]
fn an_extended_header_past_its_budget_stops_the_walk() {
    let mut tar = synth::tar_entry("ok.txt", b'0', &aws_file(16));
    let mut long = synth::tar_entry("././@LongLink", b'L', &noise(3 << 20, 1));
    long[257..265].copy_from_slice(b"ustar  \0");
    let mut head = [0u8; 512];
    head.copy_from_slice(&long[..512]);
    synth::tar_seal(&mut head);
    long[..512].copy_from_slice(&head);
    tar.extend_from_slice(&long);
    tar.extend_from_slice(&synth::tar_entry("after.txt", b'0', b"x\n"));
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("long.tar", &tar);
    assert_eq!(t.scores[&secret()], 95.0, "what was read keeps its score");
    assert!(partial(&t).contains("tar extended header over 1048576 bytes"));
}

// Links and devices.

#[test]
fn links_and_devices_are_counted_as_skipped_and_never_followed() {
    let d = tempfile::tempdir().unwrap();
    let target = write(d.path(), "real.txt", &aws_file(17));
    let mut link = synth::tar_header("sym.txt", b'2', 0);
    link[157..157 + target.to_str().unwrap().len()]
        .copy_from_slice(target.to_str().unwrap().as_bytes());
    synth::tar_seal(&mut link);
    let mut tar = link.to_vec();
    tar.extend_from_slice(&synth::tar_header("hard.txt", b'1', 0));
    tar.extend_from_slice(&synth::tar_header("char", b'3', 0));
    tar.extend_from_slice(&synth::tar_header("block", b'4', 0));
    tar.extend_from_slice(&synth::tar_header("fifo", b'6', 0));
    tar.extend_from_slice(&synth::tar_header("dir/", b'5', 0));
    tar.extend_from_slice(&synth::tar_entry("dir/a.txt", b'0', b"clean\n"));
    tar.resize(tar.len() + 1024, 0);
    let p = write(d.path(), "links.tar", &tar);
    let t = scan(&mut scanner(), &p).targets[0].clone();
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 0.0, "the link target was not read");
    let c = t.container.as_ref().unwrap();
    // A directory is not a member, as in a zip.
    assert_eq!((c.members, c.scanned, c.skipped), (6, 1, 5));
}

#[test]
fn links_count_toward_the_member_limit() {
    let mut tar = Vec::new();
    for i in 0..20 {
        tar.extend_from_slice(&synth::tar_header(&format!("l{i}"), b'2', 0));
    }
    tar.extend_from_slice(&synth::tar_entry("a.txt", b'0', &aws_file(18)));
    tar.resize(tar.len() + 1024, 0);
    let mut cfg = Config::default();
    cfg.limits.container_members = 5;
    let t = scan_named("many.tar", &tar, cfg);
    assert!(
        unscanned(&t).contains("member 6 not read (limits.container_members)"),
        "{t:?}"
    );
}

#[test]
fn data_held_by_a_link_or_directory_is_not_reported_as_read() {
    for kind in *b"25" {
        let mut tar = synth::tar_entry("x", kind, &aws_file(19));
        tar.extend_from_slice(&synth::tar_entry("a.txt", b'0', b"clean\n"));
        tar.resize(tar.len() + 1024, 0);
        let t = scan_default("held.tar", &tar);
        assert!(partial(&t).contains("bytes outside the listed members"));
    }
}

// Budgets.

#[test]
fn a_gzip_bomb_stops_at_the_ratio() {
    let gz = synth::gzip(&vec![0u8; 64 << 20]);
    assert!(gz.len() < 128 << 10);
    let x = extract_gzip(&gz, &Limits::default());
    assert!(x.members.is_empty());
    assert_eq!(
        x.status(),
        TargetStatus::Unscanned {
            reason: "member 1 not read (limits.container_ratio)".into()
        }
    );
    let t = scan_default("bomb.gz", &gz);
    assert_eq!(unscanned(&t), "member 1 not read (limits.container_ratio)");
}

#[test]
fn a_tar_bomb_in_gzip_stops_at_the_ratio_and_keeps_what_came_first() {
    let mut tar = synth::tar_entry("first.ini", b'0', &aws_file(20));
    tar.extend_from_slice(&synth::tar_entry("zeros", b'0', &vec![0u8; 64 << 20]));
    tar.extend_from_slice(&synth::tar_entry("last.ini", b'0', &aws_file(21)));
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("bomb.tar.gz", &synth::gzip(&tar));
    assert_eq!(members_of(&t, "aws_access_token"), ["first.ini"]);
    assert!(partial(&t).contains("gzip stream not read past limits.container_ratio"));
}

#[test]
fn the_gzip_layer_stops_at_the_byte_budget_with_the_ratio_out_of_the_way() {
    let mut limits = Limits {
        container_bytes: 1 << 20,
        member_bytes: 1 << 20,
        container_members: 4,
        container_ratio: u32::MAX,
        ..Limits::default()
    };
    let body = vec![b'a'; 32 << 20];
    let x = extract_gzip(&synth::gzip(&body), &limits);
    assert_eq!(x.members.len(), 1);
    assert_eq!(x.members[0].content.bytes.len(), 1 << 20);
    assert!(x.members[0].truncated.is_some());
    assert!(matches!(x.status(), TargetStatus::Partial { .. }));
    // A compressed tar reads at most the budget plus its framing, so the
    // members after the budget are not reached and nothing claims them read.
    let tar = synth::tar(&[("big", body), ("after.txt", text("x\n"))]);
    let x = extract_gzip(&synth::gzip(&tar), &limits);
    assert_eq!(x.members[0].content.bytes.len(), 1 << 20);
    let TargetStatus::Partial { not_read } = x.status() else {
        panic!("not partial");
    };
    assert!(not_read.contains("gzip stream not read past limits.container_bytes"));
    // A smaller member cap leaves room for what follows in the same stream.
    limits.member_bytes = 1 << 10;
    limits.container_bytes = 8 << 20;
    let body = vec![b'b'; 2 << 20];
    let tar = synth::tar(&[("big", body), ("after.txt", text("x\n"))]);
    let x = extract_gzip(&synth::gzip(&tar), &limits);
    assert_eq!(x.members.len(), 2);
    assert_eq!(x.members[0].content.bytes.len(), 1 << 10);
    assert_eq!(x.members[1].path, "after.txt");
}

#[test]
fn framing_does_not_use_up_the_byte_budget() {
    // 200 members whose content, not whose tar blocks, fits the budget.
    let members: Vec<(String, Vec<u8>)> = (0..200)
        .map(|i| (format!("m{i}.txt"), prose(100, i)))
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = members
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    let limits = Limits {
        container_bytes: 200 * 100,
        member_bytes: 200 * 100,
        ..Limits::default()
    };
    let x = extract_gzip(&synth::gzip(&synth::tar(&refs)), &limits);
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert_eq!(x.members.len(), 200);
}

#[test]
fn tar_declared_sizes_are_not_trusted() {
    // A member declares far more than the file holds.
    let body = aws_file(22);
    let mut tar = synth::tar_header("liar.ini", b'0', 1 << 32).to_vec();
    tar.extend_from_slice(&body);
    let t = scan_default("liar.tar", &tar);
    assert_eq!(t.scores[&secret()], 95.0, "what was read keeps its score");
    let why = partial(&t);
    assert!(why.contains("member 1 read only in part"), "{why}");
    assert!(why.contains("tar ended before its end marker"), "{why}");
    // A member declares less than it holds: the walk stops at the bad header.
    let body = prose(4096, 3);
    let mut tar = synth::tar_header("short.txt", b'0', 512).to_vec();
    tar.extend_from_slice(&body);
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("short.tar", &tar);
    assert!(partial(&t).contains("tar header unreadable"));
    // A member over the cap is read to the cap and the next one still read.
    let big = prose(3 << 20, 4);
    let tar = synth::tar(&[("big.txt", big), ("config/app.ini", aws_file(23))]);
    let mut cfg = Config::default();
    cfg.limits.member_bytes = 1 << 20;
    let t = scan_named("big.tar", &tar, cfg);
    assert_eq!(
        partial(&t),
        "member 1 read only in part (limits.member_bytes)"
    );
    assert_eq!(members_of(&t, "aws_access_token"), ["config/app.ini"]);
}

#[test]
fn tar_members_past_the_limit_are_never_reported_read() {
    let names: Vec<String> = (0..10).map(|i| format!("m{i}.txt")).collect();
    let members: Vec<(&str, Vec<u8>)> = names.iter().map(|n| (n.as_str(), text("x\n"))).collect();
    let tar = synth::tar(&members);
    let mut cfg = Config::default();
    cfg.limits.container_members = 3;
    let t = scan_named("many.tar", &tar, cfg);
    let why = partial(&t);
    assert!(
        why.contains("member 4 not read (limits.container_members)"),
        "{why}"
    );
    assert!(why.contains("bytes outside the listed members"), "{why}");
}

#[test]
fn nesting_counts_a_compressed_tar_as_one_level() {
    let inner = synth::tar(&[("deep/app.ini", aws_file(24))]);
    let outer = synth::gzip(&synth::tar(&[("inner.tar", inner)]));
    let mut cfg = Config::default();
    cfg.limits.container_depth = 1;
    let t = scan_named("outer.tar.gz", &outer, cfg);
    assert_eq!(unscanned(&t), "member 1 not read (limits.container_depth)");
    let mut cfg = Config::default();
    cfg.limits.container_depth = 2;
    let t = scan_named("outer.tar.gz", &outer, cfg);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(
        members_of(&t, "aws_access_token"),
        ["inner.tar!/deep/app.ini"]
    );
    let c = t.container.as_ref().unwrap();
    assert_eq!((c.members, c.scanned, c.opened), (2, 1, 1));
}

#[test]
fn formats_nest_in_each_other() {
    let gz = synth::gzip(&synth::tar(&[("a/app.ini", aws_file(25))]));
    let zip = synth::zip(&[("backup.tgz", gz)]);
    let t = scan_default("outer.zip", &zip);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(
        members_of(&t, "aws_access_token"),
        ["backup.tgz!/a/app.ini"]
    );
    let plain = synth::gzip(&aws_file(26));
    let tar = synth::tar(&[("logs/app.log.gz", plain)]);
    let t = scan_default("logs.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(
        members_of(&t, "aws_access_token"),
        ["logs/app.log.gz!/app.log"]
    );
    let zip = synth::zip(&[("a.ini", aws_file(27))]);
    let t = scan_default("a.zip.gz", &synth::gzip(&zip));
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["a.zip!/a.ini"]);
}

// Damage.

#[test]
fn a_cut_tar_is_partial_and_keeps_what_was_read() {
    let tar = synth::tar(&[
        ("config/app.ini", aws_file(28)),
        ("b.txt", prose(4096, 5)),
        ("c.txt", text("x\n")),
    ]);
    // Inside member 2.
    let t = scan_default("cut.tar", &tar[..512 * 4]);
    assert_eq!(t.scores[&secret()], 95.0);
    let why = partial(&t);
    assert!(
        why.contains("member 2 read only in part (its data ends early or is corrupt)"),
        "{why}"
    );
    assert!(why.contains("tar ended before its end marker"), "{why}");
    // Inside a header.
    let t = scan_default("cut.tar", &tar[..512 * 2 + 100]);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(partial(&t).contains("tar header unreadable"));
    // Between entries, with no end marker.
    let t = scan_default("cut.tar", &tar[..512 * 2]);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(
        partial(&t),
        "container structure: tar ended before its end marker"
    );
}

#[test]
fn a_corrupt_tar_header_is_partial_after_the_first_and_unscanned_at_the_first() {
    let mut tar = synth::tar(&[("a.ini", aws_file(29)), ("b.txt", text("x\n"))]);
    let t0 = tar.clone();
    tar[512 * 2 + 10] ^= 0xFF;
    let t = scan_default("bad.tar", &tar);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(partial(&t), "container structure: tar header unreadable");
    let mut tar = t0;
    tar[10] ^= 0xFF;
    let t = scan_default("bad.tar", &tar);
    assert_eq!(unscanned(&t), "tar header unreadable");
}

#[test]
fn bytes_after_the_end_of_a_tar_are_not_read_unless_zero() {
    let mut tar = synth::tar(&[("a.txt", text("x\n"))]);
    // Blocking-factor padding is standard.
    tar.resize(10240, 0);
    assert_eq!(scan_default("pad.tar", &tar).status, TargetStatus::Scanned);
    let size = tar.len() as u64;
    let mut after = tar.clone();
    after.extend_from_slice(&aws_file(30));
    let t = scan_default("after.tar", &after);
    let n = after.len() as u64 - 512 * 3;
    assert_eq!(
        partial(&t),
        format!("{n} bytes outside the listed members not read")
    );
    assert!(n > size - 512 * 3);
    // A second archive after the first's end marker is not read either.
    let mut two = synth::tar(&[("a.txt", text("x\n"))]);
    two.extend_from_slice(&synth::tar(&[("b.ini", aws_file(31))]));
    let t = scan_default("two.tar", &two);
    assert!(partial(&t).contains("bytes outside the listed members"));
    assert_eq!(t.scores[&secret()], 0.0);
}

#[test]
fn non_zero_padding_after_a_member_is_not_read() {
    let mut tar = synth::tar(&[("a.txt", text("x\n"))]);
    tar[512 + 100] = b'!';
    let t = scan_default("pad.tar", &tar);
    assert_eq!(
        partial(&t),
        "member 1 read only in part (510 bytes after its data not read)"
    );
}

#[test]
fn a_cut_gzip_is_partial_and_keeps_what_was_read() {
    let mut body = aws_file(32);
    body.extend_from_slice(&prose(256 << 10, 6));
    let gz = synth::gzip(&body);
    let t = scan_default("cut.log.gz", &gz[..gz.len() / 2]);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(
        partial(&t),
        "member 1 read only in part (its data ends early or is corrupt)"
    );
    // Only the trailer is missing.
    let t = scan_default("cut.log.gz", &gz[..gz.len() - 4]);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(partial(&t).contains("ends early or is corrupt"));
    // A cut tar in a cut gzip names the gzip, and keeps what was read.
    let tar = synth::tar(&[
        ("config/app.ini", aws_file(33)),
        ("b.bin", noise(64 << 10, 7)),
    ]);
    let gz = synth::gzip(&tar);
    let t = scan_default("cut.tar.gz", &gz[..gz.len() / 2]);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(partial(&t).contains("gzip stream ends early or is corrupt"));
}

#[test]
fn a_gzip_that_yields_nothing_is_unscanned() {
    let t = scan_default("a.gz", b"\x1f\x8b\x08\0rest of a gzip stream");
    assert_eq!(unscanned(&t), "gzip stream ends early or is corrupt");
    let t = scan_default("b.gz", b"\x1f\x8b\x07\0\0\0\0\0\0\0rest");
    assert_eq!(unscanned(&t), "gzip header unreadable");
    let t = scan_default("c.gz", b"\x1f\x8b\x08");
    assert_eq!(unscanned(&t), "gzip header unreadable");
}

#[test]
fn a_gzip_checksum_mismatch_is_partial() {
    let mut gz = synth::gzip(&aws_file(34));
    let at = gz.len() - 8;
    gz[at] ^= 0xFF;
    let t = scan_default("sum.gz", &gz);
    assert_eq!(t.scores[&secret()], 95.0);
    assert!(partial(&t).contains("ends early or is corrupt"));
    let mut gz = synth::gzip(&aws_file(34));
    let at = gz.len() - 4;
    gz[at] ^= 0xFF;
    let t = scan_default("size.gz", &gz);
    assert!(partial(&t).contains("ends early or is corrupt"));
}

#[test]
fn every_member_of_a_multi_member_gzip_is_read() {
    let mut gz = synth::gzip(b"first line\n");
    gz.extend_from_slice(&synth::gzip(&aws_file(35)));
    let t = scan_default("multi.log.gz", &gz);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.scores[&secret()], 95.0);
    let c = t.container.as_ref().unwrap();
    assert_eq!(c.members, 1, "one stream, one member");
    // A tar split across gzip members is walked whole.
    let tar = synth::tar(&[("a.txt", text("x\n")), ("b.ini", aws_file(36))]);
    let (a, b) = tar.split_at(512);
    let mut gz = synth::gzip(a);
    gz.extend_from_slice(&synth::gzip(b));
    let t = scan_default("multi.tgz", &gz);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["b.ini"]);
}

#[test]
fn bytes_after_a_gzip_stream_are_not_read_unless_zero() {
    let gz = synth::gzip(b"clean\n");
    let mut padded = gz.clone();
    padded.resize(gz.len() + 512, 0);
    assert_eq!(
        scan_default("pad.gz", &padded).status,
        TargetStatus::Scanned
    );
    let mut after = gz.clone();
    after.extend_from_slice(&aws_file(37));
    let n = aws_file(37).len();
    assert_eq!(
        partial(&scan_default("after.gz", &after)),
        format!("{n} bytes outside the listed members not read")
    );
    // A stream that starts like a gzip member and is not one is not read.
    let mut after = gz.clone();
    after.extend_from_slice(b"\x1f\x8b\x07garbage");
    assert_eq!(
        partial(&scan_default("after.gz", &after)),
        "10 bytes outside the listed members not read"
    );
    // Zeros then data.
    let mut after = gz;
    after.resize(after.len() + 100, 0);
    after.extend_from_slice(b"hidden");
    assert_eq!(
        partial(&scan_default("after.gz", &after)),
        "106 bytes outside the listed members not read"
    );
}

#[test]
fn gzip_comment_and_extra_fields_are_scanned() {
    let token = aws_file(38);
    let mut fields = token.clone();
    fields.push(0);
    let gz = gzip_with_fields(b"clean\n", 0x10, &fields);
    let t = scan_default("c.gz", &gz);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["comment!"]);
    let mut fields = (token.len() as u16).to_le_bytes().to_vec();
    fields.extend_from_slice(&token);
    let gz = gzip_with_fields(b"clean\n", 0x04, &fields);
    let t = scan_default("e.gz", &gz);
    assert_eq!(members_of(&t, "aws_access_token"), ["comment!"]);
    // A later member's stored name is not any member's name, so it is read too.
    let mut gz = gzip_named(b"clean\n", "first.txt");
    let mut name = token;
    name.retain(|&b| b != b'\n');
    gz.extend_from_slice(&gzip_named(b"clean\n", std::str::from_utf8(&name).unwrap()));
    let t = scan_default("n.gz", &gz);
    assert_eq!(members_of(&t, "aws_access_token"), ["comment!"]);
    // A stored name alone adds no member.
    let t = scan_default("n.gz", &gzip_named(b"clean\n", "n"));
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.container.as_ref().unwrap().members, 1);
    // Nor does repeating the same name, as `cat a.gz a.gz` does.
    let mut gz = gzip_named(b"clean\n", "n");
    gz.extend_from_slice(&gzip_named(b"clean\n", "n"));
    let t = scan_default("n.gz", &gz);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(t.container.as_ref().unwrap().members, 1);
}

#[test]
fn a_gzip_header_checksum_is_skipped_over() {
    // FHCRC with a name before it: the data starts after both.
    let gz = gzip_with_fields(&aws_file(46), 0x0A, b"app.ini\0\xAB\xCD");
    let t = scan_default("h.gz", &gz);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["app.ini"]);
}

#[test]
fn a_damaged_compressed_tar_inside_an_archive_counts_each_member_once() {
    let tar = synth::tar(&[
        ("a.ini", aws_file(47)),
        ("logo.png", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec()),
        ("noise.txt", prose(64 << 10, 8)),
    ]);
    let gz = synth::gzip(&tar);
    let outer = synth::tar(&[
        ("clean.txt", text("x\n")),
        ("inner.tgz", gz[..gz.len() - 4].to_vec()),
    ]);
    let t = scan_default("outer.tar", &outer);
    assert_eq!(t.scores[&secret()], 95.0, "what was read keeps its score");
    assert!(partial(&t).contains("gzip stream ends early or is corrupt"));
    let c = t.container.as_ref().unwrap();
    assert_eq!(
        c.members,
        c.scanned + c.read_in_part + c.skipped + c.not_read + c.opened,
        "{c:?}"
    );
    assert_eq!(c.members, 5);
}

#[test]
fn reasons_never_name_a_member() {
    let name = "private-person-name.txt";
    let mut tar = synth::tar_entry(name, b'0', b"x\n");
    tar[512 + 100] = b'!';
    tar.extend_from_slice(&synth::tar_header(name, b'0', 1 << 30));
    let t = scan_default("r.tar", &tar);
    assert!(!partial(&t).contains("private"));
    let gz = gzip_named(b"x\n", name);
    let t = scan_default("r.gz", &gz[..gz.len() - 3]);
    assert!(!partial(&t).contains("private"));
}

// Classification, caching, and targets.

#[test]
fn classification_recognises_old_style_tar_headers() {
    let mut h = synth::tar_header("a.txt", b'0', 0);
    h[257..265].fill(0);
    synth::tar_seal(&mut h);
    assert_eq!(
        classify("a.tar", &h),
        FileClass::Container(ContainerKind::Tar)
    );
    // Some writers pad the checksum with spaces instead of zeros.
    let digits = String::from_utf8(h[148..154].to_vec()).unwrap();
    let padded = format!("{:>6}\0 ", digits.trim_start_matches('0'));
    h[148..156].copy_from_slice(padded.as_bytes());
    assert_eq!(
        classify("a.tar", &h),
        FileClass::Container(ContainerKind::Tar)
    );
    synth::tar_seal(&mut h);
    h[148] = b'9';
    assert_ne!(
        classify("a.tar", &h),
        FileClass::Container(ContainerKind::Tar)
    );
    let mut tar = synth::tar_entry("a.ini", b'0', &aws_file(39));
    tar[257..265].fill(0);
    let mut head = [0u8; 512];
    head.copy_from_slice(&tar[..512]);
    synth::tar_seal(&mut head);
    tar[..512].copy_from_slice(&head);
    tar.resize(tar.len() + 1024, 0);
    let t = scan_default("old.tar", &tar);
    assert_eq!(t.status, TargetStatus::Scanned);
    assert_eq!(members_of(&t, "aws_access_token"), ["a.ini"]);
    let t = scan_default("old.tgz", &synth::gzip(&tar));
    assert_eq!(members_of(&t, "aws_access_token"), ["a.ini"]);
}

#[test]
fn fully_read_archives_are_cached_and_partial_ones_are_not() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let mk = || RiskGrep::with_cache_dir(Config::default(), None, Some(cache.path().into()));
    let tar = synth::tar(&[("config/app.ini", aws_file(40)), ("b.txt", text("x\n"))]);
    for (name, bytes) in [
        ("a.tar", tar.clone()),
        ("a.tar.gz", synth::gzip(&tar)),
        ("a.log.gz", synth::gzip(&aws_file(40))),
    ] {
        let p = write(d.path(), name, &bytes);
        let first = scan(&mut mk().unwrap(), &p);
        let mut g = mk().unwrap();
        let second = scan(&mut g, &p);
        assert_eq!(first, second, "{name}");
        assert!(!g.bundle_loaded(), "{name}: a whole archive is cached");
        assert_eq!(second.targets[0].scores[&secret()], 95.0);
    }
    let mut after = synth::gzip(&tar);
    after.extend_from_slice(b"trailing");
    let q = write(d.path(), "b.tar.gz", &after);
    scan(&mut mk().unwrap(), &q);
    let mut g = mk().unwrap();
    scan(&mut g, &q);
    assert!(g.bundle_loaded(), "a partial archive is scanned again");
}

#[test]
fn ignore_globs_match_tar_member_paths() {
    let d = tempfile::tempdir().unwrap();
    let tar = synth::tar(&[
        ("config/app.ini", aws_file(41)),
        ("vendor/x.ini", aws_file(42)),
    ]);
    let p = write(d.path(), "a.tar", &tar);
    let cfg = Config {
        ignore: IgnoreRules::new(IgnoreSpec {
            paths: vec!["**/a.tar!/vendor/**".into()],
            rules: vec![],
        })
        .unwrap(),
        ..Config::default()
    };
    let t = scan(&mut scanner_with(cfg), &p).targets[0].clone();
    assert_eq!(t.suppressed, 1);
    assert_eq!(members_of(&t, "aws_access_token"), ["config/app.ini"]);
}

#[test]
fn staged_tar_and_gzip_blobs_are_scanned_whole() {
    let mut g = scanner();
    let tgz = synth::gzip(&synth::tar(&[("config/app.ini", aws_file(43))]));
    let t = g.scan_blob("fixtures/backup.tar.gz", b"tgz-blob", &tgz, None);
    assert_eq!(t.scores[&secret()], 95.0);
    assert_eq!(members_of(&t, "aws_access_token"), ["config/app.ini"]);
    let gz = synth::gzip(&aws_file(44));
    let t = g.scan_blob("fixtures/app.log.gz", b"gz-blob", &gz, None);
    assert_eq!(members_of(&t, "aws_access_token"), ["app.log"]);
}

/// The first bytes of a stream of each compressed format with no reader, by
/// the name reasons give it: a documented magic, then synthetic bytes.
fn compressed_streams() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let body = noise(256, 9);
    let with = |magic: &[u8]| [magic, &body].concat();
    vec![
        ("bzip2", "a.tar.bz2", with(b"BZh91AY&SY")),
        ("bzip2", "empty.bz2", with(b"BZh9\x17\x72\x45\x38\x50\x90")),
        ("xz", "a.tar.xz", with(b"\xFD7zXZ\0")),
        ("zstd", "a.tar.zst", with(b"\x28\xB5\x2F\xFD")),
        ("lzip", "a.tar.lz", with(b"LZIP\x01")),
        ("lz4", "a.tar.lz4", with(b"\x04\x22\x4D\x18")),
        ("lz4", "legacy.lz4", with(b"\x02\x21\x4C\x18")),
        ("lzop", "a.tar.lzo", with(b"\x89LZO\0\r\n\x1A\n")),
        ("snappy", "a.sz", with(b"\xFF\x06\0\0sNaPpY")),
    ]
}

#[test]
fn compressed_streams_with_no_reader_are_unscanned_whatever_their_name() {
    for (format, name, bytes) in compressed_streams() {
        let reason = format!("{format} not scanned in v1");
        let t = scan_default(name, &bytes);
        assert_eq!(unscanned(&t), reason, "{name}");
        // By its bytes, not its name.
        let t = scan_default("renamed.dat", &bytes);
        assert_eq!(unscanned(&t), reason, "renamed {name}");
    }
}

#[test]
fn compressed_streams_with_no_reader_make_an_archive_partial() {
    for (format, name, bytes) in compressed_streams() {
        let why = format!("member 2 not opened ({format} not scanned in v1)");
        let members = [("clean.txt", text("x\n")), (name, bytes)];
        for (outer, archive) in [
            ("o.zip", synth::zip(&members)),
            ("o.tar", synth::tar(&members)),
            ("o.tgz", synth::gzip(&synth::tar(&members))),
        ] {
            let t = scan_default(outer, &archive);
            assert_eq!(partial(&t), why, "{name} in {outer}");
            let c = t.container.as_ref().unwrap();
            assert_eq!((c.scanned, c.not_read), (1, 1), "{name} in {outer}");
            assert!(
                c.listed.iter().any(|m| m.path == name),
                "{name} in {outer}: the member is listed"
            );
        }
    }
}

#[test]
fn text_that_starts_like_a_compressed_stream_stays_text() {
    let cases: [&[u8]; 8] = [
        b"BZh\n",
        b"BZh is the start of a bzip2 file.\n",
        b"BZh9 is the highest level.\n",
        b"BZh91AY&SX is one byte off.\n",
        b"BZh01AY&SY has level zero.\n",
        b"LZIP is a compressor.\n",
        b"LZ4 is a compressor.\n",
        b"sNaPpY is a compressor.\n",
    ];
    for bytes in cases {
        assert_eq!(classify("notes.txt", bytes), FileClass::Text);
        let t = scan_default("notes.txt", bytes);
        assert_eq!(t.status, TargetStatus::Scanned);
    }
    // A name alone is not a format.
    for name in [
        "notes.xz",
        "notes.bz2",
        "notes.zst",
        "notes.lz4",
        "notes.lz",
    ] {
        let t = scan_default(name, b"plain text\n");
        assert_eq!(t.status, TargetStatus::Scanned, "{name}");
    }
    // Magic bytes cut short are not a format either.
    assert_eq!(classify("a", b"\x28\xB5\x2F"), FileClass::Text);
    assert_eq!(classify("a", b"BZh91AY&S"), FileClass::Text);
}

#[test]
fn seven_zip_stays_unscanned() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4])
        .unwrap();
    let r = scanner().scan_paths(&[f.path().to_path_buf()]);
    assert_eq!(
        r.targets[0].status,
        TargetStatus::Unscanned {
            reason: container::not_scanned_reason(ContainerKind::SevenZ)
        }
    );
    assert!(container::extractor(ContainerKind::Tar).is_some());
    assert_eq!(
        container::extractor(ContainerKind::Gzip).map(Extractor::id),
        Some("gzip")
    );
}
