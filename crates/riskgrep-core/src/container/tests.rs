//! The framework against a test-only extractor whose containers are built
//! here from synthetic members, so every status path is covered without a
//! real archive format.

use super::*;
use std::time::Duration;

/// Test container: the zip magic (so nested ones classify as containers),
/// then entries of `kind`, name length (u16 LE), name, payload length (u32
/// LE), payload, declared compressed size (u64 LE, 0 for none).
const MAGIC: &[u8] = b"PK\x03\x04TEST";

enum Entry {
    Data(&'static str, Vec<u8>),
    /// Data whose declared compressed size is given.
    Packed(&'static str, Vec<u8>, u64),
    Encrypted(&'static str),
    Unsupported(&'static str),
    /// Data whose stream fails after its first bytes.
    Broken(&'static str),
    Nested(&'static str, Vec<Entry>),
}

fn build(entries: &[Entry]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    for e in entries {
        let (kind, name, payload, packed): (u8, &str, Vec<u8>, u64) = match e {
            Entry::Data(n, b) => (b'd', n, b.clone(), 0),
            Entry::Packed(n, b, c) => (b'd', n, b.clone(), *c),
            Entry::Encrypted(n) => (b'e', n, Vec::new(), 0),
            Entry::Unsupported(n) => (b'u', n, Vec::new(), 0),
            Entry::Broken(n) => (b'b', n, b"partial".to_vec(), 0),
            Entry::Nested(n, inner) => (b'd', n, build(inner), 0),
        };
        out.push(kind);
        out.extend((name.len() as u16).to_le_bytes());
        out.extend(name.as_bytes());
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend(&payload);
        out.extend(packed.to_le_bytes());
    }
    out
}

struct Test;

/// A stream that yields some bytes, then fails.
struct Failing(Vec<u8>);

impl Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.0.is_empty() {
            return Err(std::io::Error::other("bad data"));
        }
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0.drain(..n);
        Ok(n)
    }
}

impl Extractor for Test {
    fn id(&self) -> &'static str {
        "test"
    }

    fn version(&self) -> u32 {
        1
    }

    fn extract(
        &self,
        src: &dyn Source,
        size: u64,
        walk: &mut dyn Walk,
    ) -> Result<(), ContainerError> {
        let all = src
            .range(0, size)
            .map_err(|_| ContainerError("unreadable".into()))?;
        let mut b = all
            .strip_prefix(MAGIC)
            .ok_or_else(|| ContainerError("test directory unreadable".into()))?;
        let mut entries = Vec::new();
        while !b.is_empty() {
            let kind = b[0];
            let nl = u16::from_le_bytes([b[1], b[2]]) as usize;
            let name = String::from_utf8(b[3..3 + nl].to_vec()).unwrap();
            let at = 3 + nl;
            let pl = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
            let payload = b[at + 4..at + 4 + pl].to_vec();
            let at = at + 4 + pl;
            let packed = u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
            b = &b[at + 8..];
            entries.push((kind, name, payload, packed));
        }
        let n = entries.len() as u64;
        for (i, (kind, name, payload, packed)) in entries.into_iter().enumerate() {
            let meta = MemberMeta {
                name,
                declared_size: Some(payload.len() as u64),
                compressed_size: (packed > 0).then_some(packed),
            };
            let flow = match kind {
                b'e' => walk.not_read(meta, NotRead::Encrypted),
                b'u' => walk.not_read(meta, NotRead::Unsupported),
                b'b' => walk.member(meta, &mut Failing(payload)),
                _ => walk.member(meta, &mut &payload[..]),
            };
            if flow == Flow::Stop {
                walk.rest(n - i as u64 - 1);
                break;
            }
        }
        Ok(())
    }
}

fn lookup(kind: ContainerKind) -> Option<&'static dyn Extractor> {
    (kind == ContainerKind::Zip).then_some(&Test as &'static dyn Extractor)
}

fn run_with(entries: &[Entry], limits: &Limits, deadline: Instant) -> Extracted {
    let bytes = build(entries);
    extract_with(
        &Test,
        lookup,
        &&bytes[..],
        bytes.len() as u64,
        limits,
        deadline,
    )
}

fn run(entries: &[Entry], limits: &Limits) -> Extracted {
    run_with(entries, limits, Instant::now() + Duration::from_secs(60))
}

fn text(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn paths(x: &Extracted) -> Vec<&str> {
    x.members.iter().map(|m| m.path.as_str()).collect()
}

fn partial(x: &Extracted) -> String {
    match x.status() {
        TargetStatus::Partial { not_read } => not_read,
        other => panic!("expected partial, got {other:?}"),
    }
}

fn unscanned(x: &Extracted) -> String {
    match x.status() {
        TargetStatus::Unscanned { reason } => reason,
        other => panic!("expected unscanned, got {other:?}"),
    }
}

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0, 0, 0, 0];

#[test]
fn scanned_reads_every_member_and_skips_unscannable_ones() {
    let x = run(
        &[
            Entry::Data("config/.env", text("A=1\n")),
            Entry::Data("logo.png", PNG.to_vec()),
            Entry::Data("bin.dat", vec![0, 1, 2, 0]),
            Entry::Data("notes.txt", text("hello\n")),
        ],
        &Limits::default(),
    );
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert_eq!(paths(&x), ["config/.env", "notes.txt"]);
    assert_eq!((x.total, x.skipped), (4, 2));
    assert_eq!(x.format, "test");
    assert!(x.members.iter().all(|m| m.text && m.truncated.is_none()));
    assert_eq!(x.members[0].content.bytes, b"A=1\n");
    assert_eq!(x.members[1].seq, 4);
}

#[test]
fn an_empty_container_is_scanned() {
    let x = run(&[], &Limits::default());
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert_eq!(x.total, 0);
}

#[test]
fn members_past_the_count_limit_make_it_partial() {
    let limits = Limits {
        container_members: 3,
        ..Limits::default()
    };
    let entries: Vec<Entry> = (0..6).map(|_| Entry::Data("a.txt", text("x\n"))).collect();
    let x = run(&entries, &limits);
    assert_eq!(x.members.len(), 3);
    assert_eq!(x.total, 6);
    assert_eq!(
        partial(&x),
        "members 4..6 not read (limits.container_members)"
    );
    assert_eq!(unread_count(&x.unread), 3);
    assert!(x.unread.iter().all(|u| u.path.is_none()));
}

#[test]
fn the_container_byte_budget_is_shared() {
    let limits = Limits {
        container_bytes: 25,
        ..Limits::default()
    };
    let ten = || Entry::Data("a.txt", text("0123456789"));
    let x = run(&[ten(), ten(), ten(), ten()], &limits);
    assert_eq!(x.members.len(), 3);
    assert_eq!(x.members[2].content.bytes.len(), 5);
    assert_eq!(
        x.members[2].truncated,
        Some(Cause::Limit("limits.container_bytes".into()))
    );
    assert_eq!(
        partial(&x),
        "member 3 read only in part (limits.container_bytes); \
         member 4 not read (limits.container_bytes)"
    );
}

#[test]
fn a_member_over_the_member_cap_is_read_in_part() {
    let limits = Limits {
        member_bytes: 40,
        ..Limits::default()
    };
    let x = run(&[Entry::Data("big.txt", vec![b'a'; 100])], &limits);
    assert_eq!(x.members.len(), 1);
    assert_eq!(x.members[0].content.bytes.len(), 40);
    assert_eq!(
        partial(&x),
        "member 1 read only in part (limits.member_bytes)"
    );
    let u = &x.unread[0];
    assert!(u.partly);
    assert_eq!(u.path.as_deref(), Some("big.txt"));
}

#[test]
fn a_high_ratio_member_is_not_read() {
    let bomb = vec![0u8; (RATIO_FLOOR + 1) as usize];
    let x = run(
        &[
            Entry::Packed("bomb.txt", bomb, 1000),
            Entry::Data("ok.txt", text("fine\n")),
        ],
        &Limits::default(),
    );
    assert_eq!(paths(&x), ["ok.txt"]);
    assert_eq!(partial(&x), "member 1 not read (limits.container_ratio)");
    // Below the floor, any ratio is allowed.
    let small = run(
        &[Entry::Packed("zeros.txt", vec![b'0'; 4096], 1)],
        &Limits::default(),
    );
    assert_eq!(small.status(), TargetStatus::Scanned);
}

#[test]
fn encrypted_unsupported_and_broken_members_make_it_partial() {
    let x = run(
        &[
            Entry::Data("a.txt", text("a\n")),
            Entry::Encrypted("secret.txt"),
            Entry::Unsupported("packed.txt"),
            Entry::Broken("broken.txt"),
            Entry::Encrypted("more.txt"),
        ],
        &Limits::default(),
    );
    assert_eq!(paths(&x), ["a.txt"]);
    assert_eq!(
        partial(&x),
        "members 2, 5 encrypted; member 3 stored with an unsupported method; \
         member 4 unreadable"
    );
    assert_eq!(
        x.unread[0].path.as_deref(),
        Some("secret.txt"),
        "unread members keep their path for the member table"
    );
}

#[test]
fn members_needing_no_bytes_keep_their_own_cause() {
    let limits = Limits {
        container_bytes: 4,
        ..Limits::default()
    };
    let x = run(
        &[
            Entry::Data("a.txt", text("abcd")),
            Entry::Encrypted("b.txt"),
            Entry::Data("c.txt", text("c\n")),
        ],
        &limits,
    );
    assert_eq!(
        partial(&x),
        "member 2 encrypted; member 3 not read (limits.container_bytes)"
    );
}

#[test]
fn nothing_read_is_unscanned() {
    let x = run(
        &[Entry::Encrypted("a.txt"), Entry::Encrypted("b.txt")],
        &Limits::default(),
    );
    assert_eq!(unscanned(&x), "members 1..2 encrypted");
}

#[test]
fn an_unreadable_structure_is_unscanned() {
    let bytes = b"PK\x03\x04 not a test container".to_vec();
    let x = extract_with(
        &Test,
        lookup,
        &&bytes[..],
        bytes.len() as u64,
        &Limits::default(),
        Instant::now() + Duration::from_secs(60),
    );
    assert_eq!(unscanned(&x), "test directory unreadable");
}

#[test]
fn a_spent_deadline_is_unscanned() {
    let x = run_with(
        &[Entry::Data("a.txt", text("a\n"))],
        &Limits::default(),
        Instant::now() - Duration::from_millis(1),
    );
    assert_eq!(unscanned(&x), "timeout");
}

#[test]
fn nested_members_are_named_through_their_containers() {
    let x = run(
        &[
            Entry::Data("top.txt", text("t\n")),
            Entry::Nested(
                "inner.zip",
                vec![
                    Entry::Data("x/.env", text("A=1\n")),
                    Entry::Nested("deep.zip", vec![Entry::Data("y.txt", text("y\n"))]),
                ],
            ),
        ],
        &Limits::default(),
    );
    assert_eq!(x.status(), TargetStatus::Scanned);
    assert_eq!(
        paths(&x),
        ["top.txt", "inner.zip!/x/.env", "inner.zip!/deep.zip!/y.txt"]
    );
    // Nested containers and their members are all counted.
    assert_eq!(x.total, 5);
}

#[test]
fn nesting_past_the_depth_limit_makes_it_partial() {
    let limits = Limits {
        container_depth: 2,
        ..Limits::default()
    };
    let x = run(
        &[Entry::Nested(
            "a.zip",
            vec![
                Entry::Data("in-a.txt", text("a\n")),
                Entry::Nested("b.zip", vec![Entry::Data("in-b.txt", text("b\n"))]),
            ],
        )],
        &limits,
    );
    assert_eq!(paths(&x), ["a.zip!/in-a.txt"]);
    assert_eq!(partial(&x), "member 3 not read (limits.container_depth)");
    assert_eq!(x.unread[0].path.as_deref(), Some("a.zip!/b.zip"));
}

#[test]
fn the_member_count_covers_nested_members() {
    let limits = Limits {
        container_members: 2,
        ..Limits::default()
    };
    let x = run(
        &[
            Entry::Nested(
                "a.zip",
                vec![
                    Entry::Data("1.txt", text("1\n")),
                    Entry::Data("2.txt", text("2\n")),
                ],
            ),
            Entry::Data("3.txt", text("3\n")),
        ],
        &limits,
    );
    assert_eq!(paths(&x), ["a.zip!/1.txt"]);
    assert_eq!(
        partial(&x),
        "members 3..4 not read (limits.container_members)"
    );
}

#[test]
fn a_nested_format_without_an_extractor_makes_it_partial() {
    let gz = vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0];
    let x = run(
        &[Entry::Data("a.txt", text("a\n")), Entry::Data("b.gz", gz)],
        &Limits::default(),
    );
    assert_eq!(partial(&x), "member 2 not opened (gzip not scanned in v1)");
}

#[test]
fn reasons_never_name_members() {
    let x = run(
        &[
            Entry::Data("a.txt", text("a\n")),
            Entry::Encrypted("private-name.txt"),
        ],
        &Limits::default(),
    );
    assert!(!partial(&x).contains("private-name"));
}

#[test]
fn names_are_escaped_and_capped() {
    assert_eq!(escape_name("a\nb\tc", 1), "a\\nb\\tc");
    assert_eq!(escape_name("odd!/name", 1), "odd!!/name");
    // A trailing `!` is escaped too, so `a!` joined to `x` is `a!!!/x`,
    // never the escaped single name `a!/x`.
    assert_eq!(escape_name("a!", 1), "a!!");
    assert_ne!(
        format!("{}!/x", escape_name("a!", 1)),
        escape_name("a!/x", 2)
    );
    let long = "é".repeat(800);
    let e = escape_name(&long, 42);
    assert!(e.len() <= NAME_MAX);
    assert!(e.ends_with("…#42"));
}

#[test]
fn describe_merges_positions_into_ranges() {
    let u = |seq, cause: Cause| Unread {
        seq,
        last: seq,
        path: None,
        cause,
        partly: false,
    };
    let unread: Vec<Unread> = (1..=30)
        .filter(|s| s % 2 == 0)
        .map(|s| u(s, Cause::Encrypted))
        .chain([u(40, Cause::Corrupt), u(41, Cause::Corrupt)])
        .collect();
    assert_eq!(
        describe(&unread, 0, Some("truncated")),
        "members 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, … encrypted; \
         members 40..41 unreadable; container structure: truncated"
    );
}
