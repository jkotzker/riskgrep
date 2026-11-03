use riskgrep_core::classify::{
    classify, classify_sized, read_for_scan, safetensors_header_fits, slice_for_scan, FileClass,
    Known, Limits, Tail, KEY_STORE_MAX,
};
use riskgrep_core::container::ContainerKind;
use riskgrep_core::synth;
use std::fs::File;
use std::io::Write;

fn pad(mut v: Vec<u8>, to: usize) -> Vec<u8> {
    v.resize(to, b'a');
    v
}

fn safetensors_head(n: u64) -> Vec<u8> {
    let mut v = n.to_le_bytes().to_vec();
    v.push(b'{');
    pad(v, 64)
}

#[test]
fn defaults_match_constraints() {
    let l = Limits::default();
    assert_eq!(l.text_max, 8_388_608);
    assert_eq!(l.sample, 1_048_576);
    assert_eq!(l.sniff, 8192);
    assert_eq!(l.walk_files, 10_000);
    assert_eq!(l.time_budget, std::time::Duration::from_secs(2));
}

#[test]
fn npy_magic() {
    let mut h = vec![0x93, b'N', b'U', b'M', b'P', b'Y', 1, 0];
    h.extend_from_slice(&[0; 16]);
    assert_eq!(classify("a.npy", &h), FileClass::KnownBinary(Known::Npy));
    assert_eq!(classify("noext", &h), FileClass::KnownBinary(Known::Npy));
}

#[test]
fn zip_and_npz() {
    let h = pad(b"PK\x03\x04".to_vec(), 32);
    assert_eq!(
        classify("a.zip", &h),
        FileClass::Container(ContainerKind::Zip)
    );
    assert_eq!(classify("a.npz", &h), FileClass::KnownBinary(Known::Npz));
    assert_eq!(classify("A.NPZ", &h), FileClass::KnownBinary(Known::Npz));
}

#[test]
fn safetensors_magic() {
    assert_eq!(
        classify("m.safetensors", &safetensors_head(100)),
        FileClass::KnownBinary(Known::Safetensors)
    );
    // n <= 1 is not safetensors
    assert_ne!(
        classify("m.bin", &safetensors_head(1)),
        FileClass::KnownBinary(Known::Safetensors)
    );
    // implausibly large n (upper bytes set)
    assert_ne!(
        classify("m.bin", &safetensors_head(1 << 40)),
        FileClass::KnownBinary(Known::Safetensors)
    );
    // byte 8 must be '{'
    let mut h = safetensors_head(100);
    h[8] = b'[';
    assert_ne!(
        classify("m.bin", &h),
        FileClass::KnownBinary(Known::Safetensors)
    );
}

#[test]
fn safetensors_header_fit_check() {
    let h = safetensors_head(100);
    assert!(safetensors_header_fits(&h, 108));
    assert!(safetensors_header_fits(&h, 5000));
    assert!(!safetensors_header_fits(&h, 107));
    assert!(!safetensors_header_fits(&h[..4], 5000));
    let huge = u64::MAX.to_le_bytes();
    assert!(!safetensors_header_fits(&huge, u64::MAX));
}

#[test]
fn key_stores() {
    let h = pad(vec![0x30, 0x82, 0x01, 0x00], 32);
    for name in ["a.p12", "a.pfx", "a.der", "a.key", "A.P12"] {
        assert_eq!(
            classify(name, &h),
            FileClass::KnownBinary(Known::KeyStore),
            "{name}"
        );
    }
    // wrong extension: not a key store (NUL bytes make it unknown binary)
    assert_eq!(classify("a.bin", &h), FileClass::UnknownBinary);
    // SEC1 EC private keys: one-byte (`30 77`) and long-form (`30 81 ..`)
    // lengths, recognised for .der/.key only.
    for prefix in [
        vec![0x30, 0x77, 0x02, 0x01, 0x01],
        vec![0x30, 0x81, 0x87, 0x02, 0x01, 0x01],
    ] {
        let h = pad(prefix, 32);
        for name in ["a.der", "a.key", "A.KEY"] {
            assert_eq!(
                classify(name, &h),
                FileClass::KnownBinary(Known::KeyStore),
                "{name}"
            );
        }
        for name in ["a.p12", "a.pfx", "a.bin"] {
            assert_ne!(
                classify(name, &h),
                FileClass::KnownBinary(Known::KeyStore),
                "{name}"
            );
        }
    }
    // Any DER SEQUENCE header for .der/.key: short-form lengths (PKCS#8
    // Ed25519/X25519 `30 2e`, Ed448 `30 47`, SEC1 P-256 without public key
    // `30 31`, P-224 `30 68`, secp256k1 `30 74`, brainpoolP256r1 `30 78`) and
    // long forms `81` and `82`. `.p12`/`.pfx` keep `30 82` only.
    for prefix in [
        vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30],
        vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04],
        vec![0x30, 0x47, 0x02, 0x01, 0x00, 0x30],
        vec![0x30, 0x68, 0x02, 0x01, 0x01, 0x04],
        vec![0x30, 0x74, 0x02, 0x01, 0x01, 0x04],
        vec![0x30, 0x78, 0x02, 0x01, 0x01, 0x04],
    ] {
        let h = pad(prefix.clone(), 32);
        for name in ["a.der", "a.key", "A.KEY"] {
            assert_eq!(
                classify(name, &h),
                FileClass::KnownBinary(Known::KeyStore),
                "{name} {:02x}",
                prefix[1]
            );
        }
        for name in ["a.p12", "a.pfx", "a.bin"] {
            assert_ne!(
                classify(name, &h),
                FileClass::KnownBinary(Known::KeyStore),
                "{name} {:02x}",
                prefix[1]
            );
        }
    }
    // Not a recognised length byte: indefinite (`80`), or a length of 3+ bytes
    // (`83` is a valid DER length that no key-store rule matches).
    for second in [0x80u8, 0x83, 0x84, 0xff] {
        let h = pad(vec![0x30, second, 0x02, 0x01, 0x00], 32);
        assert_ne!(
            classify("a.key", &h),
            FileClass::KnownBinary(Known::KeyStore),
            "{second:02x}"
        );
    }
    assert_ne!(
        classify("a.key", &[0x30]),
        FileClass::KnownBinary(Known::KeyStore)
    );
    // Larger than 1 MiB: not a key store, so a text file whose first bytes
    // look like a header takes the text path (and its tail is scanned).
    let h = pad(vec![0x30, 0x78, 0x02, 0x01, 0x01, 0x04], 32);
    for name in ["a.der", "a.key"] {
        assert_eq!(
            classify_sized(name, &h, KEY_STORE_MAX),
            FileClass::KnownBinary(Known::KeyStore)
        );
        assert_eq!(
            classify_sized(name, &h, KEY_STORE_MAX + 1),
            FileClass::Text,
            "{name}"
        );
    }
    let h = pad(b"0x big text\n".to_vec(), 32);
    assert_eq!(classify_sized("a.key", &h, 9 << 20), FileClass::Text);
    // PEM .key stays text
    let pem = pad(b"-----BEGIN PRIVATE KEY-----\n".to_vec(), 64);
    assert_eq!(classify("a.key", &pem), FileClass::Text);
}

#[test]
fn archives_by_magic() {
    assert_eq!(
        classify("x", &pad(b"%PDF-1.7".to_vec(), 64)),
        FileClass::Container(ContainerKind::Pdf)
    );
    assert_eq!(
        classify("x", &pad(b"SQLite format 3\0".to_vec(), 64)),
        FileClass::Container(ContainerKind::Sqlite)
    );
    assert_eq!(
        classify("x", &pad(vec![0x1F, 0x8B, 8, 0], 64)),
        FileClass::Container(ContainerKind::Gzip)
    );
    assert_eq!(
        classify("x", &pad(vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], 64)),
        FileClass::Container(ContainerKind::SevenZ)
    );
    let mut tar = vec![b'a'; 512];
    tar[257..262].copy_from_slice(b"ustar");
    assert_eq!(
        classify("x", &tar),
        FileClass::Container(ContainerKind::Tar)
    );
}

#[test]
fn images_by_magic() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("png", vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]),
        ("jpeg", vec![0xFF, 0xD8, 0xFF, 0xE0]),
        ("gif", b"GIF89a".to_vec()),
        ("webp", b"RIFF\x10\x00\x00\x00WEBPVP8 ".to_vec()),
        ("heic", b"\0\0\0\x18ftypheic".to_vec()),
        ("heic", b"\0\0\0\x18ftypheix".to_vec()),
        ("heic", b"\0\0\0\x18ftypmif1".to_vec()),
        ("tiff", b"II*\0\x08\0\0\0".to_vec()),
        ("tiff", b"MM\0*\0\0\0\x08".to_vec()),
    ];
    for (kind, head) in cases {
        assert_eq!(
            classify("img", &pad(head, 64)),
            FileClass::Image(kind),
            "{kind}"
        );
    }
}

#[test]
fn nul_means_binary() {
    assert_eq!(classify("a.txt", b"hello\0world"), FileClass::UnknownBinary);
    assert_eq!(classify("a.txt", b"hello world\n"), FileClass::Text);
    assert_eq!(classify("a.txt", b""), FileClass::Text);
}

fn temp_with(bytes: &[u8]) -> (tempfile::NamedTempFile, File) {
    let mut t = tempfile::NamedTempFile::new().unwrap();
    t.write_all(bytes).unwrap();
    t.flush().unwrap();
    let f = File::open(t.path()).unwrap();
    (t, f)
}

#[test]
fn small_text_read_whole() {
    let (_t, f) = temp_with(b"hello\nworld\n");
    let c = read_for_scan(&f, 12, &FileClass::Text, &Limits::default()).unwrap();
    assert_eq!(c.bytes, b"hello\nworld\n");
    assert!(c.partial.is_none());
}

#[test]
fn text_at_cap_is_whole() {
    let size = 8 * 1024 * 1024;
    let (_t, f) = temp_with(&vec![b'x'; size]);
    let c = read_for_scan(&f, size as u64, &FileClass::Text, &Limits::default()).unwrap();
    assert_eq!(c.bytes.len(), size);
    assert!(c.partial.is_none());
}

#[test]
fn text_over_cap_is_sampled() {
    let mib = 1024 * 1024usize;
    let size = 9 * mib;
    let mut data = vec![b'm'; size];
    data[..mib].fill(b'h');
    data[size - mib..].fill(b't');
    let (_t, f) = temp_with(&data);
    let c = read_for_scan(&f, size as u64, &FileClass::Text, &Limits::default()).unwrap();
    assert_eq!(c.bytes.len(), 2 * mib + 1);
    assert_eq!(c.bytes[0], b'h');
    assert_eq!(c.bytes[mib], b'\n');
    assert_eq!(*c.bytes.last().unwrap(), b't');
    assert!(!c.bytes.contains(&b'm'));
    assert_eq!(
        c.partial.as_deref(),
        Some("bytes 1048576..8388608 not read")
    );
    // Content from `at` onward is the file's last MiB.
    assert_eq!(
        c.tail,
        Some(Tail {
            at: mib as u64 + 1,
            file_offset: (size - mib) as u64,
        })
    );
}

#[test]
fn whole_text_has_no_tail() {
    let (_t, f) = temp_with(b"hello\n");
    let c = read_for_scan(&f, 6, &FileClass::Text, &Limits::default()).unwrap();
    assert_eq!(c.tail, None);
    assert_eq!(c.unscanned, None);
}

#[test]
fn read_position_is_irrelevant() {
    use std::io::{Seek, SeekFrom};
    let (_t, mut f) = temp_with(b"abcdef");
    f.seek(SeekFrom::End(0)).unwrap();
    let c = read_for_scan(&f, 6, &FileClass::Text, &Limits::default()).unwrap();
    assert_eq!(c.bytes, b"abcdef");
}

fn npy_bytes(version: u8, hdr_len: usize) -> Vec<u8> {
    let mut v = vec![0x93, b'N', b'U', b'M', b'P', b'Y', version, 0];
    if version == 1 {
        v.extend_from_slice(&(hdr_len as u16).to_le_bytes());
    } else {
        v.extend_from_slice(&(hdr_len as u32).to_le_bytes());
    }
    v.extend(std::iter::repeat_n(b' ', hdr_len));
    v
}

#[test]
fn npy_header_only() {
    let mut data = npy_bytes(1, 118);
    let header_end = data.len();
    assert_eq!(header_end, 10 + 118);
    let size = 50 * 1024 * 1024u64;
    let mut t = tempfile::NamedTempFile::new().unwrap();
    t.write_all(&data).unwrap();
    t.as_file().set_len(size).unwrap();
    data.clear();
    let f = File::open(t.path()).unwrap();
    let c = read_for_scan(
        &f,
        size,
        &FileClass::KnownBinary(Known::Npy),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.bytes.len(), header_end);
    assert!(c.bytes.len() < 1024);
}

#[test]
fn npy_v2_header_length_is_u32() {
    let data = npy_bytes(2, 300);
    let (_t, f) = temp_with(&data);
    let size = data.len() as u64;
    let c = read_for_scan(
        &f,
        size,
        &FileClass::KnownBinary(Known::Npy),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.bytes.len(), 12 + 300);
}

#[test]
fn safetensors_reads_header() {
    let mut data = safetensors_head(200);
    data.resize(8 + 200, b'x');
    data.resize(10_000, 0);
    let (_t, f) = temp_with(&data);
    let c = read_for_scan(
        &f,
        data.len() as u64,
        &FileClass::KnownBinary(Known::Safetensors),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.bytes.len(), 208);
    assert!(c.partial.is_none());
}

#[test]
fn safetensors_header_capped_at_100_mib() {
    let n: u64 = 200 * 1024 * 1024;
    let mut t = tempfile::NamedTempFile::new().unwrap();
    t.write_all(&safetensors_head(n)).unwrap();
    let size = n + 8 + 10;
    t.as_file().set_len(size).unwrap();
    let f = File::open(t.path()).unwrap();
    let c = read_for_scan(
        &f,
        size,
        &FileClass::KnownBinary(Known::Safetensors),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.bytes.len(), 104_857_600);
    assert_eq!(
        c.partial.as_deref(),
        Some(format!("bytes 104857600..{} not read", n + 8).as_str())
    );
}

#[test]
fn npz_and_keystore_read_whole_up_to_cap() {
    let data = pad(vec![0x30, 0x82], 5000);
    let (_t, f) = temp_with(&data);
    for k in [Known::Npz, Known::KeyStore] {
        let c = read_for_scan(&f, 5000, &FileClass::KnownBinary(k), &Limits::default()).unwrap();
        assert_eq!(c.bytes.len(), 5000);
        assert!(c.partial.is_none());
    }
    let cap = 8 * 1024 * 1024u64;
    let size = cap + 100;
    let t = tempfile::NamedTempFile::new().unwrap();
    t.as_file().set_len(size).unwrap();
    let f = File::open(t.path()).unwrap();
    let c = read_for_scan(
        &f,
        size,
        &FileClass::KnownBinary(Known::KeyStore),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.bytes.len() as u64, cap);
    assert_eq!(
        c.partial.as_deref(),
        Some("bytes 8388608..8388708 not read")
    );
    drop(t);
}

/// An `.npz` over the text limit: one member of `big` floats (so the file
/// is large) placed after `members`.
fn big_npz(members: &[(&str, Vec<u8>)], big: u64) -> Vec<u8> {
    let mut all: Vec<(&str, Vec<u8>)> = members.to_vec();
    all.push(("zz_noise.npy", synth::npy("<f4", &[big])));
    synth::npz(&all)
}

#[test]
fn npz_over_limit_reads_member_headers_only() {
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    let small = vec![
        ("alice.npy", synth::npy("<f4", &[192])),
        ("notes.txt", b"not an array".to_vec()),
    ];
    let data = big_npz(&small, 4096);
    assert!(data.len() > 4096 * 4);
    let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert_eq!(c.partial, None);
    assert_eq!(c.unscanned, None);
    assert!(c.bytes.len() < data.len() / 2, "{}", c.bytes.len());
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(&c.bytes)).unwrap();
    let names: Vec<String> = (0..z.len())
        .map(|i| z.by_index(i).unwrap().name().unwrap().to_string())
        .collect();
    assert_eq!(names, ["alice.npy", "zz_noise.npy"]);
    // Each member keeps the first bytes of its array: the whole small one,
    // and the header (plus a little data) of the large one.
    let mut head = Vec::new();
    std::io::Read::read_to_end(&mut z.by_index(0).unwrap(), &mut head).unwrap();
    assert_eq!(head, small[0].1);
    let mut head = Vec::new();
    std::io::Read::read_to_end(&mut z.by_index(1).unwrap(), &mut head).unwrap();
    assert_eq!(head.len(), 4096);
    assert_eq!(head[..6], *b"\x93NUMPY");
    // The same input gives the same bytes (the result is cached by hash).
    let again = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert_eq!(again, c);
}

#[test]
fn npz_over_limit_reads_compressed_members() {
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let emb = synth::npy("<f4", &[3, 256]);
    for (name, bytes) in [
        ("emb.npy", emb.clone()),
        ("noise.npy", synth::npy("<f4", &[20_000])),
    ] {
        w.start_file(name, opts).unwrap();
        std::io::Write::write_all(&mut w, &bytes).unwrap();
    }
    let data = w.finish().unwrap().into_inner();
    assert!(data.len() > 4096);
    let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert_eq!(c.unscanned, None);
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(&c.bytes)).unwrap();
    let mut head = Vec::new();
    std::io::Read::read_to_end(&mut z.by_index(0).unwrap(), &mut head).unwrap();
    assert_eq!(head, emb[..4096.min(emb.len())]);
}

#[test]
fn npz_over_limit_without_directory_is_unscanned() {
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    let mut data = synth::npz(&[("a.npy", synth::npy("<f4", &[4096]))]);
    // Cut the central directory and end record off.
    let cut = data.len() - 100;
    data.truncate(cut);
    let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert!(c.bytes.is_empty());
    assert_eq!(c.partial, None);
    assert_eq!(
        c.unscanned.as_deref(),
        Some("npz central directory unreadable")
    );
    // A file of zeros: no end record anywhere.
    let zeros = vec![0u8; 64 * 1024];
    let c = slice_for_scan(&zeros, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert!(c.unscanned.is_some());
}

#[test]
fn npz_over_limit_with_prepended_bytes_is_unscanned() {
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    let members = [("alice.npy", synth::npy("<f4", &[192]))];
    let mut data = b"prepended bytes".to_vec();
    data.extend(big_npz(&members, 4096));
    assert!(data.len() > 4096 * 4);
    let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert!(c.bytes.is_empty());
    assert_eq!(
        c.unscanned.as_deref(),
        Some("npz central directory unreadable")
    );
}

#[test]
fn npz_directory_search_is_bounded() {
    // A large file with no end record: the backward search stops at the
    // directory budget instead of reading the whole file.
    let size = 64 * 1024 * 1024u64;
    let t = tempfile::NamedTempFile::new().unwrap();
    t.as_file().set_len(size).unwrap();
    let f = File::open(t.path()).unwrap();
    let c = read_for_scan(
        &f,
        size,
        &FileClass::KnownBinary(Known::Npz),
        &Limits::default(),
    )
    .unwrap();
    // zip 9.0.5 limits its end-record search to the last 64 KiB, so a file
    // with no end record is rejected before the directory budget is reached.
    assert_eq!(
        c.unscanned.as_deref(),
        Some("npz central directory unreadable")
    );
}

/// A zip with `entries` central directory records and no members, each record
/// carrying a `comment` of that many bytes, then a valid end record.
fn hostile_directory(entries: usize, comment: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..entries {
        let name = format!("m{i:05}.npy");
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 20, 0]);
        out.extend_from_slice(&[0; 4 + 4 + 4 + 4 + 4]);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(comment as u16).to_le_bytes());
        out.extend_from_slice(&[0; 2 + 2 + 4 + 4]);
        out.extend_from_slice(name.as_bytes());
        out.resize(out.len() + comment, b'x');
    }
    let directory = out.len() as u32;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries as u16).to_le_bytes());
    out.extend_from_slice(&(entries as u16).to_le_bytes());
    out.extend_from_slice(&directory.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn npz_directory_over_budget_is_unscanned() {
    // A central directory over 8 MiB with a valid end record at the end of the
    // file: the end record is found, and the directory itself runs past the
    // budget.
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    let data = hostile_directory(200, 65_535);
    assert!(data.len() > 8_388_608 + 4096, "{}", data.len());
    let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert!(c.bytes.is_empty());
    assert_eq!(
        c.unscanned.as_deref(),
        Some("npz central directory not read within 8388608 bytes")
    );
    // The same records with short comments fit the budget: the directory
    // parses, and the first member (which has no data) is the first not read.
    let small = hostile_directory(200, 10);
    let c = slice_for_scan(&small, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert_eq!(c.unscanned, None);
    assert_eq!(c.partial.as_deref(), Some("npz member 0 could not be read"));
}

/// Offsets of the central and local headers of the member called `name`.
fn member_headers(data: &[u8], name: &str) -> (usize, usize) {
    let sig = b"PK\x01\x02";
    let mut at = 0;
    while let Some(i) = data[at..].windows(4).position(|w| w == sig) {
        let cd = at + i;
        let len = u16::from_le_bytes([data[cd + 28], data[cd + 29]]) as usize;
        if &data[cd + 46..cd + 46 + len] == name.as_bytes() {
            let local = u32::from_le_bytes(data[cd + 42..cd + 46].try_into().unwrap());
            return (cd, local as usize);
        }
        at = cd + 4;
    }
    panic!("no member {name}");
}

fn put_u32(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// An over-limit `.npz` whose member `name` has had `damage(data, central,
/// local)` applied to its headers.
fn damaged_npz(name: &str, damage: fn(&mut [u8], usize, usize)) -> Vec<u8> {
    let members = [
        (name, synth::npy("<f4", &[192])),
        ("alice.npy", synth::npy("<f4", &[192])),
    ];
    let mut data = big_npz(&members, 4096);
    let (cd, local) = member_headers(&data, name);
    damage(&mut data, cd, local);
    data
}

fn wrong_crc(data: &mut [u8], cd: usize, local: usize) {
    put_u32(data, cd + 16, 0);
    put_u32(data, local + 14, 0);
}

fn understated_size(data: &mut [u8], cd: usize, local: usize) {
    put_u32(data, cd + 24, 64);
    put_u32(data, local + 22, 64);
}

#[test]
fn npz_over_limit_unreadable_npy_member_is_partial() {
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    for damage in [wrong_crc as fn(&mut [u8], usize, usize), understated_size] {
        let data = damaged_npz("bad.npy", damage);
        let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
        assert_eq!(c.unscanned, None);
        // The member's name is never put in the note.
        assert_eq!(c.partial.as_deref(), Some("npz member 0 could not be read"));
        // The readable members are still handed on.
        let z = zip::ZipArchive::new(std::io::Cursor::new(&c.bytes)).unwrap();
        let names: Vec<String> = z.file_names().map(|n| n.unwrap().into_owned()).collect();
        assert_eq!(names, ["alice.npy", "zz_noise.npy"]);
    }
}

#[test]
fn npz_over_limit_unreadable_other_member_is_ignored() {
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    for damage in [wrong_crc as fn(&mut [u8], usize, usize), understated_size] {
        let data = damaged_npz("bad.txt", damage);
        let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
        assert_eq!(c.unscanned, None);
        let z = zip::ZipArchive::new(std::io::Cursor::new(&c.bytes)).unwrap();
        let names: Vec<String> = z.file_names().map(|n| n.unwrap().into_owned()).collect();
        assert_eq!(names, ["alice.npy", "zz_noise.npy"]);
    }
}

#[test]
fn npz_over_limit_with_many_members_reads_them_all() {
    // The directory budget counts bytes fetched, not buffer refills: a
    // directory of a thousand short records is far under 8 MiB.
    let limits = Limits {
        text_max: 4096,
        ..Limits::default()
    };
    let names: Vec<String> = (0..1000).map(|i| format!("m{i:05}.npy")).collect();
    let members: Vec<(&str, Vec<u8>)> = names
        .iter()
        .map(|n| (n.as_str(), synth::npy("<f4", &[8])))
        .collect();
    let data = big_npz(&members, 4096);
    let c = slice_for_scan(&data, &FileClass::KnownBinary(Known::Npz), &limits).unwrap();
    assert_eq!(c.unscanned, None);
    let z = zip::ZipArchive::new(std::io::Cursor::new(&c.bytes)).unwrap();
    assert_eq!(z.len(), 1001);
}

#[test]
fn other_classes_read_nothing() {
    let (_t, f) = temp_with(b"PK\x03\x04abcd");
    for class in [
        FileClass::Container(ContainerKind::Zip),
        FileClass::Image("png"),
        FileClass::UnknownBinary,
    ] {
        let c = read_for_scan(&f, 8, &class, &Limits::default()).unwrap();
        assert!(c.bytes.is_empty());
        assert!(c.partial.is_none());
    }
}

#[test]
fn password_vaults_are_recognised_by_magic() {
    let kdbx = pad(vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5], 64);
    let kdb1 = pad(vec![0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5], 64);
    let kych = pad(b"kych\0\x01\0\0".to_vec(), 64);
    let pws3 = pad(b"PWS3".to_vec(), 64);
    for (name, head) in [
        ("Passwords.kdbx", &kdbx),
        ("renamed.dat", &kdbx),
        ("old.kdb", &kdb1),
        ("login.keychain-db", &kych),
        ("noext", &kych),
        ("vault.psafe3", &pws3),
        ("VAULT.PSAFE3", &pws3),
    ] {
        assert_eq!(
            classify(name, head),
            FileClass::KnownBinary(Known::Vault),
            "{name}"
        );
    }
    // PWS3 needs the extension; other KeePass-like signatures are not vaults.
    let mut pws3_bin = pws3.clone();
    pws3_bin[8] = 0;
    assert_eq!(classify("vault.dat", &pws3_bin), FileClass::UnknownBinary);
    let other = pad(vec![0x03, 0xD9, 0xA2, 0x9A, 0x00, 0xFB, 0x4B, 0xB5], 64);
    assert_eq!(classify("a.kdbx", &other), FileClass::UnknownBinary);
    // The word `kych` at the start of ordinary text is text.
    assert_eq!(classify("notes.txt", b"kych is a word\n"), FileClass::Text);
}

/// A Password Safe v3 header: the tag, a 32-byte salt, and the iteration
/// count, then filler up to 64 bytes.
fn pws3_header(iterations: u32) -> Vec<u8> {
    let mut head = b"PWS3".to_vec();
    head.extend([0x90; 32]);
    head.extend(iterations.to_le_bytes());
    pad(head, 64)
}

#[test]
fn password_safe_layout_is_recognised_without_the_extension() {
    let vault = Known::Vault;
    // 200 bytes plus whole 16-byte blocks, and an iteration count of at least
    // the original minimum of 2,048.
    for (size, iterations) in [(200, 2048), (216, 262_144), (100_008, 5_000_000)] {
        assert_eq!(
            classify_sized("backup", &pws3_header(iterations), size),
            FileClass::KnownBinary(vault),
            "{size} bytes, {iterations} iterations"
        );
    }
    for (size, iterations) in [
        (199, 262_144),
        (208, 262_144),
        (216, 2047),
        (216, 0),
        // At or above 2^28: a larger value is not a plausible iteration count.
        (216, 1 << 28),
    ] {
        assert_eq!(
            classify_sized("backup", &pws3_header(iterations), size),
            FileClass::UnknownBinary,
            "{size} bytes, {iterations} iterations"
        );
    }
    // Text whose bytes 36 to 40 read as a plausible iteration count (a line
    // feed at offset 39) is still text: the salt must hold a byte that is not
    // printable text.
    let mut text = b"PWS3".to_vec();
    text.extend([b'x'; 35]);
    text.push(b'\n');
    text.extend(b"more notes, a text file\n");
    assert_eq!(classify_sized("notes.txt", &text, 216), FileClass::Text);
    // A text file that starts with the letters is text.
    assert_eq!(
        classify_sized(
            "notes.txt",
            b"PWS3 build notes, a text file that only starts with them\n",
            216
        ),
        FileClass::Text
    );
}

#[test]
fn password_vaults_read_the_header_only() {
    let data = pad(
        vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5],
        100_000,
    );
    let (_t, f) = temp_with(&data);
    let c = read_for_scan(
        &f,
        100_000,
        &FileClass::KnownBinary(Known::Vault),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(c.bytes, &data[..64]);
    assert!(c.partial.is_none());
}
