//! UTF-16 and UTF-32 text: detection, scoring like UTF-8, and evidence
//! offsets and lines in the original file. Secrets are generated at run
//! time and never printed; assertions use statuses, scores, and offsets.

use riskgrep_core::classify::{classify, classify_sized, FileClass};
use riskgrep_core::config::Config;
use riskgrep_core::encoding::{Encoding, Utf};
use riskgrep_core::model::{Category, Location, Report, TargetReport, TargetStatus};
use riskgrep_core::scanner::RiskGrep;
use riskgrep_core::synth;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tempfile::TempDir;

fn shared_cache() -> PathBuf {
    static D: OnceLock<TempDir> = OnceLock::new();
    D.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        let mut g = RiskGrep::with_cache_dir(Config::default(), None, Some(d.path().into()))
            .expect("scanner builds");
        let r = g.scan_bytes("warm", b"nothing here\n");
        assert_eq!(r.targets[0].status, TargetStatus::Scanned);
        d
    })
    .path()
    .to_path_buf()
}

fn scanner_with(cfg: Config, cache: &Path) -> RiskGrep {
    RiskGrep::with_cache_dir(cfg, None, Some(cache.into())).unwrap()
}

fn scanner() -> RiskGrep {
    scanner_with(Config::default(), &shared_cache())
}

fn secret() -> Category {
    Category("secret".into())
}

fn only(r: &Report) -> &TargetReport {
    assert_eq!(r.targets.len(), 1, "one target");
    &r.targets[0]
}

/// Every encoding variant: (utf, with a byte-order mark).
const VARIANTS: [(Utf, bool); 8] = [
    (Utf::Utf16Le, true),
    (Utf::Utf16Be, true),
    (Utf::Utf16Le, false),
    (Utf::Utf16Be, false),
    (Utf::Utf32Le, true),
    (Utf::Utf32Be, true),
    (Utf::Utf32Le, false),
    (Utf::Utf32Be, false),
];

/// `text` in `utf`, by the standard library rather than the code under test.
fn encode(text: &str, utf: Utf, bom: bool) -> Vec<u8> {
    let mut s = String::new();
    if bom {
        s.push('\u{feff}');
    }
    s.push_str(text);
    match utf {
        Utf::Utf16Le => s.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        Utf::Utf16Be => s.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        Utf::Utf32Le => s.chars().flat_map(|c| (c as u32).to_le_bytes()).collect(),
        Utf::Utf32Be => s.chars().flat_map(|c| (c as u32).to_be_bytes()).collect(),
    }
}

/// Encoded length of `text` (no byte-order mark).
fn enc_len(text: &str, utf: Utf) -> u64 {
    encode(text, utf, false).len() as u64
}

fn bom_len(utf: Utf, bom: bool) -> u64 {
    match (bom, utf) {
        (false, _) => 0,
        (true, Utf::Utf16Le | Utf::Utf16Be) => 2,
        (true, _) => 4,
    }
}

fn aws(seed: u64) -> String {
    synth::fake_secret("aws_access_key", seed)
}

/// A file whose third line, after CRLF line endings, two-byte, three-byte,
/// and supplementary-plane characters, holds an AWS key.
fn mixed_text(seed: u64) -> String {
    format!(
        "caf\u{e9} \u{20ac}12 \u{1f600} ok\r\nna\u{ef}ve \u{65e5}\u{672c} \u{1d11e}\r\n    id = \"{}\" # \u{e9}\r\nend\r\n",
        aws(seed)
    )
}

fn aws_locations(t: &TargetReport) -> Vec<Location> {
    t.evidence
        .iter()
        .filter(|e| e.rule == "aws_access_token")
        .flat_map(|e| e.locations.clone())
        .collect()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn byte_order_marks_and_patterns_classify_as_encoded_text() {
    let text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software]\r\n";
    for (utf, bom) in VARIANTS {
        let bytes = encode(text, utf, bom);
        let want = Encoding {
            utf,
            bom: bom_len(utf, bom) as u8,
        };
        assert_eq!(
            classify("a.reg", &bytes),
            FileClass::EncodedText(want),
            "{utf:?} bom={bom}"
        );
    }
}

#[test]
fn utf8_and_binaries_are_not_encoded_text() {
    // Plain text and UTF-8 with its byte-order mark stay text.
    assert_eq!(classify("a.txt", b"hello world\n"), FileClass::Text);
    assert_eq!(
        classify("a.txt", "\u{feff}h\u{e9}\n".as_bytes()),
        FileClass::Text
    );
    // A NUL inside ASCII text, and runs of NULs between bytes, are binary.
    assert_eq!(classify("a.txt", b"hello\0world"), FileClass::UnknownBinary);
    assert_eq!(
        classify("a.bin", b"AB\0\0\0\0CD\0\0\0\0EF\0\0"),
        FileClass::UnknownBinary
    );
    // Alternating NULs that hold control characters are not text.
    let ctl: Vec<u8> = (1u8..30).flat_map(|b| [b, 0]).collect();
    assert_eq!(classify("a.bin", &ctl), FileClass::UnknownBinary);
    // Little-endian integers whose high bytes are mostly non-zero.
    let ints: Vec<u8> = (0u32..2000)
        .flat_map(|i| (i.wrapping_mul(2_654_435_761)).to_le_bytes())
        .collect();
    assert_eq!(classify("a.bin", &ints), FileClass::UnknownBinary);
    // A byte-order mark followed by a NUL character is binary.
    let mut nul = encode("ab", Utf::Utf16Le, true);
    nul.extend([0, 0]);
    nul.extend(encode("cd", Utf::Utf16Le, false));
    assert_eq!(classify("a.txt", &nul), FileClass::UnknownBinary);
    // A UTF-32 mark followed by values beyond Unicode is binary.
    let mut big = vec![0xFF, 0xFE, 0, 0];
    for _ in 0..16 {
        big.extend(0xFFFF_FFF0u32.to_le_bytes());
    }
    assert_eq!(classify("a.bin", &big), FileClass::UnknownBinary);
    // One code unit is too little to tell.
    assert_eq!(classify("a.txt", b"A\0"), FileClass::UnknownBinary);
}

#[test]
fn a_surrogate_pair_cut_by_the_sniff_window_is_still_text() {
    let mut text = "a".repeat(4095);
    text.push('\u{1f600}');
    let bytes = encode(&text, Utf::Utf16Le, false);
    assert_eq!(
        classify_sized("a.txt", &bytes[..8192], bytes.len() as u64),
        FileClass::EncodedText(Encoding {
            utf: Utf::Utf16Le,
            bom: 0
        })
    );
}

#[test]
fn encoded_text_scores_like_utf8() {
    let d = tempfile::tempdir().unwrap();
    let text = format!("[settings]\r\nid = \"{}\"\r\n", aws(1));
    let mut g = scanner();
    let base = g.scan_paths(&[write(d.path(), "plain.ini", text.as_bytes())]);
    let want = only(&base).scores[&secret()];
    assert!(want >= 95.0, "{want}");
    for (i, (utf, bom)) in VARIANTS.into_iter().enumerate() {
        let p = write(d.path(), &format!("f{i}.ini"), &encode(&text, utf, bom));
        let r = g.scan_paths(&[p]);
        let t = only(&r);
        assert_eq!(t.status, TargetStatus::Scanned, "{utf:?} bom={bom}");
        // Only UTF-16 LE with a mark is decoded by Claude Code's `Read`.
        assert_eq!(t.text, utf == Utf::Utf16Le && bom, "{utf:?} bom={bom}");
        assert_eq!(t.scores[&secret()], want, "{utf:?} bom={bom}");
    }
}

/// The location of the key in the UTF-8 text, moved to the encoded file.
fn expected(text: &str, utf8: &Location, utf: Utf, bom: bool) -> (u64, u64) {
    let b = bom_len(utf, bom);
    let start = b + enc_len(&text[..utf8.start as usize], utf);
    let end = b + enc_len(&text[..utf8.end as usize], utf);
    (start, end)
}

#[test]
fn offsets_and_lines_point_into_the_original_file() {
    let d = tempfile::tempdir().unwrap();
    let text = mixed_text(2);
    let mut g = scanner();
    let base = g.scan_paths(&[write(d.path(), "plain.txt", text.as_bytes())]);
    let utf8 = aws_locations(only(&base));
    assert_eq!(utf8.len(), 1);
    assert_eq!((utf8[0].line_start, utf8[0].line_end), (3, 3));
    for (i, (utf, bom)) in VARIANTS.into_iter().enumerate() {
        let bytes = encode(&text, utf, bom);
        let p = write(d.path(), &format!("m{i}.txt"), &bytes);
        let r = g.scan_paths(&[p]);
        let locs = aws_locations(only(&r));
        assert_eq!(locs.len(), 1, "{utf:?} bom={bom}");
        let (start, end) = expected(&text, &utf8[0], utf, bom);
        assert_eq!(
            (
                locs[0].start,
                locs[0].end,
                locs[0].line_start,
                locs[0].line_end
            ),
            (start, end, 3, 3),
            "{utf:?} bom={bom}"
        );
        // The located bytes are the key itself, in the file's encoding.
        let key = aws(2);
        let found = &bytes[start as usize..end as usize];
        let at = enc_len(&text[..utf8[0].start as usize], utf);
        assert_eq!(
            found,
            &encode(&text, utf, false)[at as usize..][..found.len()]
        );
        assert!(
            found.len() as u64 >= enc_len(&key, utf),
            "{utf:?} bom={bom}"
        );
    }
}

#[test]
fn cached_evidence_keeps_original_offsets() {
    let d = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let text = mixed_text(3);
    let utf8 = write(d.path(), "plain.txt", text.as_bytes());
    let utf16 = write(d.path(), "wide.txt", &encode(&text, Utf::Utf16Le, true));
    let scan = |p: &Path| {
        let mut g = scanner_with(Config::default(), cache.path());
        aws_locations(only(&g.scan_paths(&[p.to_path_buf()])))
    };
    let (a, b) = (scan(&utf8), scan(&utf16));
    assert_ne!(a[0].start, b[0].start);
    // Second scans come from the cache and must agree with the first.
    assert_eq!(scan(&utf8), a);
    assert_eq!(scan(&utf16), b);
}

#[test]
fn invalid_code_units_decode_lossily() {
    let d = tempfile::tempdir().unwrap();
    let text = format!("x\nid = \"{}\"\n", aws(4));
    let mut g = scanner();
    let base = g.scan_paths(&[write(d.path(), "plain.txt", text.as_bytes())]);
    let utf8 = aws_locations(only(&base));
    // An unpaired high surrogate after the BOM, then the text.
    let mut bytes = vec![0xFF, 0xFE, 0x00, 0xD8];
    bytes.extend(encode(&text, Utf::Utf16Le, false));
    // A trailing odd byte.
    bytes.push(b'z');
    let r = g.scan_paths(&[write(d.path(), "lossy.txt", &bytes)]);
    let t = only(&r);
    assert_eq!(t.status, TargetStatus::Scanned);
    let locs = aws_locations(t);
    assert_eq!(locs.len(), 1);
    let (start, end) = expected(&text, &utf8[0], Utf::Utf16Le, false);
    assert_eq!(
        (locs[0].start, locs[0].end, locs[0].line_start),
        (start + 4, end + 4, 2)
    );
}

#[test]
fn sampled_encoded_file_maps_head_and_tail() {
    let d = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.limits.text_max = 4096;
    cfg.limits.sample = 1000;
    let mut g = scanner_with(cfg, &shared_cache());
    let head = format!("\u{e9}t\u{e9}\nid = \"{}\"\n", aws(5));
    let filler = "line of filler text\n".repeat(400);
    let tail_line = format!("key = \"{}\"\n", aws(6));
    for (utf, bom) in VARIANTS {
        let text = format!("{head}{filler}{tail_line}");
        let bytes = encode(&text, utf, bom);
        let size = bytes.len() as u64;
        let unit = match utf {
            Utf::Utf16Le | Utf::Utf16Be => 2,
            _ => 4,
        };
        let s = 1000 / unit * unit;
        let tail_start = (size - s).div_ceil(unit) * unit;
        let r = g.scan_paths(&[write(d.path(), "big.txt", &bytes)]);
        let t = only(&r);
        assert_eq!(
            t.status,
            TargetStatus::Partial {
                not_read: format!("bytes {s}..{tail_start} not read")
            },
            "{utf:?} bom={bom}"
        );
        let mut locs = aws_locations(t);
        locs.sort_by_key(|l| l.start);
        assert_eq!(locs.len(), 2, "{utf:?} bom={bom}");
        let b = bom_len(utf, bom);
        let k1 = b + enc_len(&head[..head.find("AKIA").unwrap()], utf);
        assert_eq!(
            (locs[0].start, locs[0].line_start),
            (k1, 2),
            "{utf:?} bom={bom}"
        );
        let before_k2 = format!("{head}{filler}key = \"");
        let k2 = b + enc_len(&before_k2, utf);
        assert_eq!(
            (
                locs[1].start,
                locs[1].end,
                locs[1].line_start,
                locs[1].line_end
            ),
            (k2, k2 + enc_len(&aws(6), utf), 0, 0),
            "{utf:?} bom={bom}"
        );
    }
}

#[test]
fn blob_line_filter_uses_lines_of_the_encoded_file() {
    let mut g = scanner();
    let text = format!("one\ntwo\nid = \"{}\"\nfour\n", aws(7));
    let bytes = encode(&text, Utf::Utf16Le, true);
    let hit = g.scan_blob(
        "a.txt",
        b"blob-a",
        &bytes,
        Some(std::slice::from_ref(&(3..=3))),
    );
    assert!(hit.scores[&secret()] >= 95.0);
    let miss = g.scan_blob(
        "a.txt",
        b"blob-a",
        &bytes,
        Some(std::slice::from_ref(&(1..=2))),
    );
    assert_eq!(miss.scores[&secret()], 0.0);
}

fn located(start: u64, end: u64) -> riskgrep_core::model::Evidence {
    riskgrep_core::model::Evidence {
        rule: "r".into(),
        category: secret(),
        weight: 1.0,
        count: 1,
        locations: vec![Location {
            start,
            end,
            line_start: 1,
            line_end: 1,
        }],
        shape: Vec::new(),
        fingerprints: Vec::new(),
        line_complete: false,
    }
}

#[test]
fn ends_are_exclusive_and_cover_whole_source_characters() {
    use riskgrep_core::encoding::Decoded;
    // "a", U+1F600 (a surrogate pair), an unpaired high surrogate, "b".
    let text_units: [u16; 5] = [0x61, 0xD83D, 0xDE00, 0xD800, 0x62];
    // Transcoded: a 0..1, U+1F600 1..5, U+FFFD 5..8, b 8..9.
    // UTF-16 LE with a mark: a 2..4, pair 4..8, lone surrogate 8..10, b 10..12.
    let cases: [((u64, u64), (u64, u64)); 7] = [
        ((0, 1), (2, 4)),
        ((1, 5), (4, 8)),
        ((2, 3), (4, 8)),
        ((0, 2), (2, 8)),
        ((5, 8), (8, 10)),
        ((6, 9), (8, 12)),
        ((9, 9), (12, 12)),
    ];
    let mut src = vec![0xFF, 0xFE];
    src.extend(text_units.iter().flat_map(|u| u.to_le_bytes()));
    let enc = Encoding {
        utf: Utf::Utf16Le,
        bom: 2,
    };
    let (d, bytes) = Decoded::new(enc, src, None);
    assert_eq!(bytes.len(), 9);
    for ((s, e), want) in cases {
        let mut ev = [located(s, e)];
        d.place(&mut ev);
        let l = &ev[0].locations[0];
        assert_eq!((l.start, l.end), want, "{s}..{e}");
    }
    // In UTF-32 the same pair is one 4-byte code unit.
    let src: Vec<u8> = ['a', '\u{1f600}', 'b']
        .iter()
        .flat_map(|&c| (c as u32).to_be_bytes())
        .collect();
    let enc = Encoding {
        utf: Utf::Utf32Be,
        bom: 0,
    };
    let (d, _) = Decoded::new(enc, src, None);
    let mut ev = [located(1, 5), located(3, 6)];
    d.place(&mut ev);
    let got: Vec<(u64, u64)> = ev
        .iter()
        .map(|e| (e.locations[0].start, e.locations[0].end))
        .collect();
    assert_eq!(got, [(4, 8), (4, 12)]);
}

#[test]
fn tail_sample_starts_on_a_code_unit_boundary() {
    let d = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.limits.text_max = 4096;
    cfg.limits.sample = 1001;
    let mut g = scanner_with(cfg, &shared_cache());
    let filler = "line of filler text\n".repeat(400);
    let tail_line = format!("key = \"{}\"\n", aws(8));
    let text = format!("{filler}{tail_line}");
    for (utf, bom) in [(Utf::Utf16Le, true), (Utf::Utf32Be, false)] {
        let mut bytes = encode(&text, utf, bom);
        // A stray final byte makes the size no multiple of the code unit.
        bytes.push(b'z');
        let size = bytes.len() as u64;
        let unit = if utf == Utf::Utf16Le { 2 } else { 4 };
        let s = 1001 / unit * unit;
        let tail_start = (size - s).div_ceil(unit) * unit;
        assert_ne!((size - s) % unit, 0, "the unaligned case is exercised");
        let r = g.scan_paths(&[write(d.path(), "odd.txt", &bytes)]);
        let t = only(&r);
        assert_eq!(
            t.status,
            TargetStatus::Partial {
                not_read: format!("bytes {s}..{tail_start} not read")
            },
            "{utf:?}"
        );
        let locs = aws_locations(t);
        assert_eq!(locs.len(), 1, "{utf:?}");
        let k = bom_len(utf, bom) + enc_len(&format!("{filler}key = \""), utf);
        assert_eq!(
            (locs[0].start, locs[0].end, locs[0].line_start),
            (k, k + enc_len(&aws(8), utf), 0),
            "{utf:?}"
        );
    }
}
