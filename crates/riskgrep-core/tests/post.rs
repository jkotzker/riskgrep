use regex::bytes::Regex;
use riskgrep_core::lines::LineIndex;
use riskgrep_core::model::ShapeFacts;
use riskgrep_core::post::{
    compile_regex, float_arrays, AllowRegex, Entropy, FloatArray, NpyHeader, NpzMembers, Post,
    PostResult, SafetensorsHeader, Span, Stopwords,
};
use std::io::Write;

fn re(s: &str) -> Regex {
    compile_regex(s).unwrap()
}

/// Deterministic pseudo-random base62 text, generated at run time.
fn random_base62(n: usize, seed: u64) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed.to_le_bytes());
    let mut out = Vec::new();
    let mut xof = hasher.finalize_xof();
    let mut buf = vec![0u8; n * 4];
    xof.fill(&mut buf);
    for b in buf {
        if out.len() == n {
            break;
        }
        if (b as usize) < 62 * 4 {
            out.push(A[b as usize % 62]);
        }
    }
    out
}

fn npy(descr: &str, shape: &str) -> Vec<u8> {
    let mut h = format!("{{'descr': '{descr}', 'fortran_order': False, 'shape': {shape}, }}");
    while (10 + h.len() + 1) % 64 != 0 {
        h.push(' ');
    }
    h.push('\n');
    let mut v = b"\x93NUMPY\x01\x00".to_vec();
    v.extend((h.len() as u16).to_le_bytes());
    v.extend(h.as_bytes());
    v.extend([0u8; 16]);
    v
}

fn safetensors(json: &str) -> Vec<u8> {
    let mut v = (json.len() as u64).to_le_bytes().to_vec();
    v.extend(json.as_bytes());
    v
}

fn tensor(r: &PostResult) -> (&str, &[u64], Option<&str>) {
    match r {
        PostResult::KeepWithShape(_, ShapeFacts::Tensor { dtype, shape, name }) => {
            (dtype.as_str(), shape.as_slice(), name.as_deref())
        }
        other => panic!("expected KeepWithShape, got {other:?}"),
    }
}

#[test]
fn span_narrows_to_group() {
    let content = b"key = \"abcdef123456\" ;";
    let span = Span::new(re(r#"= "([a-z0-9]+)""#), 1);
    let r = span.apply(content, 0..content.len());
    let PostResult::Keep(range) = r else { panic!() };
    assert_eq!(&content[range], b"abcdef123456");
    assert_eq!(
        Span::new(re("zzz"), 0).apply(content, 0..content.len()),
        PostResult::Drop
    );
    assert_eq!(
        Span::new(re("(a)"), 3).apply(content, 0..content.len()),
        PostResult::Drop
    );
}

#[test]
fn allow_regex_drops_on_match() {
    let content = b"EXAMPLEKEY123";
    let allow = AllowRegex::new(re("EXAMPLE"));
    assert_eq!(allow.apply(content, 0..content.len()), PostResult::Drop);
    assert_eq!(allow.apply(b"realkey", 0..7), PostResult::Keep(0..7));
}

#[test]
fn entropy_drops_low() {
    let e = Entropy { min: 3.0 };
    let low = b"aaaaaaaaaaaaaaaa";
    assert_eq!(e.apply(low, 0..low.len()), PostResult::Drop);
    let high = random_base62(32, 7);
    assert_eq!(e.apply(&high, 0..32), PostResult::Keep(0..32));
}

#[test]
fn stopwords_drop() {
    let sw = Stopwords::new(&["Example".to_string(), "".to_string()]);
    let content = b"my-eXaMpLe-token";
    assert_eq!(sw.apply(content, 0..content.len()), PostResult::Drop);
    assert_eq!(sw.apply(content, 0..3), PostResult::Keep(0..3));
}

#[test]
fn npy_float_kept_int_dropped() {
    let p = NpyHeader {
        min_dim: 192,
        embedding_dims: None,
    };
    let f = npy("<f4", "(10, 192)");
    let r = p.apply(&f, 0..f.len());
    assert_eq!(tensor(&r), ("<f4", &[10, 192][..], None));
    let i = npy("<i8", "(500,)");
    assert_eq!(p.apply(&i, 0..i.len()), PostResult::Drop);
    let small = npy("<f4", "(10, 20)");
    assert_eq!(p.apply(&small, 0..small.len()), PostResult::Drop);
}

#[test]
fn safetensors_name_rule() {
    let json = r#"{"__metadata__":{"format":"pt"},"speaker_embedding":{"dtype":"F32","shape":[1,256],"data_offsets":[0,1024]},"layer.0.weight":{"dtype":"F32","shape":[768,768],"data_offsets":[1024,9999]}}"#;
    let data = safetensors(json);
    let named = SafetensorsHeader {
        min_dim: 192,
        name_regex: Some(re("embedding")),
        embedding_dims: None,
        exclude_name_regex: None,
        min_bank: None,
        min_bank_share: None,
    };
    let r = named.apply(&data, 0..8);
    assert_eq!(
        tensor(&r),
        ("F32", &[1, 256][..], Some("speaker_embedding"))
    );

    let layer_only =
        safetensors(r#"{"layer.0.weight":{"dtype":"F32","shape":[768,768],"data_offsets":[0,9]}}"#);
    assert_eq!(named.apply(&layer_only, 0..8), PostResult::Drop);

    let unnamed = SafetensorsHeader {
        min_dim: 192,
        name_regex: None,
        embedding_dims: None,
        exclude_name_regex: None,
        min_bank: None,
        min_bank_share: None,
    };
    let r = unnamed.apply(&layer_only, 0..8);
    assert_eq!(tensor(&r).2, Some("layer.0.weight"));
    // with several qualifying tensors the smallest name is reported
    let r = unnamed.apply(&data, 0..8);
    assert_eq!(tensor(&r).2, Some("layer.0.weight"));

    let ints = safetensors(r#"{"t":{"dtype":"I64","shape":[1000],"data_offsets":[0,8]}}"#);
    assert_eq!(unnamed.apply(&ints, 0..8), PostResult::Drop);
}

fn npz(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn npz_members() {
    let p = NpzMembers {
        min_dim: 192,
        embedding_dims: None,
        exclude_name_regex: None,
        min_bank: None,
        min_bank_share: None,
    };
    let both = npz(&[
        ("ids.npy", npy("<i8", "(500,)")),
        ("emb.npy", npy("<f4", "(1, 192)")),
    ]);
    let r = p.apply(&both, 0..4);
    assert_eq!(tensor(&r), ("<f4", &[1, 192][..], Some("emb")));
    let ints = npz(&[
        ("ids.npy", npy("<i8", "(500,)")),
        ("readme.txt", b"x".to_vec()),
    ]);
    assert_eq!(p.apply(&ints, 0..4), PostResult::Drop);
}

#[test]
fn headers_never_panic_on_malformed_input() {
    let npy_p = NpyHeader {
        min_dim: 1,
        embedding_dims: None,
    };
    let npz_p = NpzMembers {
        min_dim: 1,
        embedding_dims: None,
        exclude_name_regex: None,
        min_bank: None,
        min_bank_share: None,
    };
    let st_p = SafetensorsHeader {
        min_dim: 1,
        name_regex: None,
        embedding_dims: None,
        exclude_name_regex: None,
        min_bank: None,
        min_bank_share: None,
    };
    let good_npy = npy("<f4", "(10, 192)");
    let good_st = safetensors(r#"{"t":{"dtype":"F32","shape":[4,4],"data_offsets":[0,64]}}"#);
    let good_npz = npz(&[("a.npy", good_npy.clone())]);
    let mut inputs: Vec<Vec<u8>> = vec![
        vec![],
        b"\x93NUMPY".to_vec(),
        b"\x93NUMPY\x01\x00\xff\xff".to_vec(),
        b"\x93NUMPY\x02\x00\xff\xff\xff\xff".to_vec(),
        b"\x93NUMPY\x09\x00\x00\x00".to_vec(),
        npy("<f4", "(10, x)"),
        npy("<f4", "(99999999999999999999999,)"),
        npy("<f4", "10"),
        u64::MAX.to_le_bytes().to_vec(),
        safetensors("{not json"),
        safetensors(r#"{"t":{"dtype":5,"shape":"x"}}"#),
        safetensors(r#"[1,2]"#),
        safetensors(r#"{"t":{"dtype":"F32","shape":[-1]}}"#),
        b"PK\x03\x04garbage".to_vec(),
    ];
    for g in [&good_npy, &good_st, &good_npz] {
        for cut in 0..g.len() {
            inputs.push(g[..cut].to_vec());
        }
        for i in 0..g.len().min(200) {
            let mut v = g.clone();
            v[i] = v[i].wrapping_add(0x5b);
            inputs.push(v);
        }
    }
    for data in &inputs {
        let _ = npy_p.apply(data, 0..data.len());
        let _ = npz_p.apply(data, 0..data.len());
        let _ = st_p.apply(data, 0..data.len());
    }
    // the unmutated headers still qualify
    assert!(matches!(
        npy_p.apply(&good_npy, 0..4),
        PostResult::KeepWithShape(..)
    ));
    assert!(matches!(
        st_p.apply(&good_st, 0..8),
        PostResult::KeepWithShape(..)
    ));
    assert!(matches!(
        npz_p.apply(&good_npz, 0..4),
        PostResult::KeepWithShape(..)
    ));
}

const DIMS: &[u64] = &[192, 256];

fn kept(r: &PostResult) -> bool {
    matches!(r, PostResult::KeepWithShape(..))
}

#[test]
fn npy_embedding_shape() {
    let p = NpyHeader {
        min_dim: 64,
        embedding_dims: Some(DIMS.to_vec()),
    };
    for (shape, want) in [
        ("(192,)", true),
        ("(1, 192)", true),
        ("(500, 256)", true),
        ("(2, 3, 192)", true),
        ("(2, 2, 2, 192)", false),
        ("(10, 193)", false),
        ("(192, 10)", false),
    ] {
        let f = npy("<f4", shape);
        assert_eq!(kept(&p.apply(&f, 0..4)), want, "{shape}");
    }
    let ints = npy("<i8", "(1, 192)");
    assert_eq!(p.apply(&ints, 0..4), PostResult::Drop);
}

#[test]
fn npz_embedding_shape() {
    let p = NpzMembers {
        min_dim: 64,
        embedding_dims: Some(DIMS.to_vec()),
        exclude_name_regex: None,
        min_bank: None,
        min_bank_share: None,
    };
    let emb = npz(&[
        ("x.npy", npy("<f8", "(5000, 7)")),
        ("emb.npy", npy("<f4", "(3, 256)")),
    ]);
    assert_eq!(tensor(&p.apply(&emb, 0..4)).2, Some("emb"));
    let table = npz(&[("x.npy", npy("<f8", "(5000, 7)"))]);
    assert_eq!(p.apply(&table, 0..4), PostResult::Drop);
}

#[test]
fn safetensors_embedding_shape_and_exclusions() {
    let p = SafetensorsHeader {
        min_dim: 64,
        name_regex: None,
        embedding_dims: Some(DIMS.to_vec()),
        exclude_name_regex: Some(re("(?i)(weight|bias)")),
        min_bank: None,
        min_bank_share: None,
    };
    let emb = safetensors(r#"{"data":{"dtype":"F32","shape":[4,256],"data_offsets":[0,4096]}}"#);
    assert_eq!(tensor(&p.apply(&emb, 0..8)).2, Some("data"));
    let layers = safetensors(
        r#"{"fc.weight":{"dtype":"F32","shape":[10,256],"data_offsets":[0,9]},"fc.bias":{"dtype":"F32","shape":[256],"data_offsets":[9,10]}}"#,
    );
    assert_eq!(p.apply(&layers, 0..8), PostResult::Drop);
    let wide = safetensors(r#"{"x":{"dtype":"F32","shape":[256,257],"data_offsets":[0,9]}}"#);
    assert_eq!(p.apply(&wide, 0..8), PostResult::Drop);
}

#[test]
fn safetensors_embedding_bank() {
    let p = SafetensorsHeader {
        min_dim: 64,
        name_regex: None,
        embedding_dims: Some(DIMS.to_vec()),
        exclude_name_regex: Some(re("(?i)weight")),
        min_bank: Some(3),
        min_bank_share: None,
    };
    let bank = |n: usize, shape: &str| {
        let items: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#""p{}":{{"dtype":"F32","shape":{shape},"data_offsets":[0,9]}}"#,
                    225 + i
                )
            })
            .collect();
        safetensors(&format!(
            r#"{{"__metadata__":{{"a":"b"}},{}}}"#,
            items.join(",")
        ))
    };
    assert_eq!(tensor(&p.apply(&bank(3, "[192]"), 0..8)).2, Some("p225"));
    assert!(kept(&p.apply(&bank(109, "[1,256]"), 0..8)));
    assert_eq!(p.apply(&bank(2, "[192]"), 0..8), PostResult::Drop);
    assert_eq!(p.apply(&bank(5, "[193]"), 0..8), PostResult::Drop);
    // Three embedding-shaped tensors of different shapes are not a bank.
    let mixed = safetensors(
        r#"{"a":{"dtype":"F32","shape":[192],"data_offsets":[0,9]},"b":{"dtype":"F32","shape":[256],"data_offsets":[0,9]},"c":{"dtype":"F32","shape":[2,192],"data_offsets":[0,9]}}"#,
    );
    assert_eq!(p.apply(&mixed, 0..8), PostResult::Drop);
    // Excluded names do not count towards a bank.
    let layers = safetensors(
        r#"{"l1.weight":{"dtype":"F32","shape":[192],"data_offsets":[0,9]},"l2.weight":{"dtype":"F32","shape":[192],"data_offsets":[0,9]},"x":{"dtype":"F32","shape":[192],"data_offsets":[0,9]}}"#,
    );
    assert_eq!(p.apply(&layers, 0..8), PostResult::Drop);
}

#[test]
fn npz_embedding_bank() {
    let p = NpzMembers {
        min_dim: 64,
        embedding_dims: Some(DIMS.to_vec()),
        exclude_name_regex: None,
        min_bank: Some(3),
        min_bank_share: None,
    };
    let members = |n: usize, shape: &str| -> Vec<u8> {
        let m: Vec<(String, Vec<u8>)> = (0..n)
            .map(|i| (format!("person_{i:03}.npy"), npy("<f4", shape)))
            .collect();
        let refs: Vec<(&str, Vec<u8>)> = m.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
        npz(&refs)
    };
    assert_eq!(
        tensor(&p.apply(&members(3, "(3, 256)"), 0..4)).2,
        Some("person_000")
    );
    assert_eq!(p.apply(&members(2, "(3, 256)"), 0..4), PostResult::Drop);
    assert_eq!(p.apply(&members(4, "(3, 7)"), 0..4), PostResult::Drop);
}

#[test]
fn bank_share_counts_every_float_tensor() {
    let p = SafetensorsHeader {
        min_dim: 64,
        name_regex: None,
        embedding_dims: Some(DIMS.to_vec()),
        exclude_name_regex: Some(re("(?i)weight")),
        min_bank: Some(3),
        min_bank_share: Some(50),
    };
    // Three identity vectors plus `others` float tensors that cannot join a
    // bank (excluded names and other shapes still count as float tensors).
    let file = |others: usize| {
        let mut items: Vec<String> = (0..3)
            .map(|i| {
                format!(
                    r#""p{}":{{"dtype":"F32","shape":[192],"data_offsets":[0,9]}}"#,
                    225 + i
                )
            })
            .collect();
        for i in 0..others {
            let (name, shape) = if i % 2 == 0 {
                (format!("l{i}.weight"), "[192]")
            } else {
                (format!("x{i}"), "[7]")
            };
            items.push(format!(
                r#""{name}":{{"dtype":"F32","shape":{shape},"data_offsets":[0,9]}}"#
            ));
        }
        items.push(r#""ids":{"dtype":"I64","shape":[3],"data_offsets":[0,9]}"#.into());
        safetensors(&format!("{{{}}}", items.join(",")))
    };
    assert!(kept(&p.apply(&file(0), 0..8)));
    // 3 of 5 float tensors: more than half. The integer tensor never counts.
    assert!(kept(&p.apply(&file(2), 0..8)));
    // 3 of 6: exactly half is not enough.
    assert_eq!(p.apply(&file(3), 0..8), PostResult::Drop);
}

#[test]
fn npz_exclusions_and_bank_share() {
    let p = NpzMembers {
        min_dim: 64,
        embedding_dims: Some(DIMS.to_vec()),
        exclude_name_regex: Some(re("(?i)(kernel|(^|[._/])[0-9]+[._/])")),
        min_bank: None,
        min_bank_share: None,
    };
    let excluded = npz(&[
        ("dense/kernel.npy", npy("<f4", "(192, 192)")),
        ("dct_1_192.npy", npy("<f8", "(192,)")),
    ]);
    assert_eq!(p.apply(&excluded, 0..4), PostResult::Drop);
    let flat = npz(&[
        ("dense/kernel.npy", npy("<f4", "(192, 192)")),
        ("x2.npy", npy("<f8", "(192,)")),
    ]);
    assert_eq!(tensor(&p.apply(&flat, 0..4)).2, Some("x2"));

    let bank = NpzMembers {
        min_bank: Some(3),
        min_bank_share: Some(50),
        ..p
    };
    let store = |others: usize| {
        let mut m: Vec<(String, Vec<u8>)> = (0..3)
            .map(|i| (format!("spk_{i}.npy"), npy("<f4", "(192,)")))
            .collect();
        for i in 0..others {
            m.push((format!("t{i}.npy"), npy("<f8", "(5,)")));
        }
        m.push(("ids.npy".into(), npy("<i8", "(3,)")));
        let refs: Vec<(&str, Vec<u8>)> = m.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
        npz(&refs)
    };
    assert_eq!(tensor(&bank.apply(&store(2), 0..4)).2, Some("spk_0"));
    assert_eq!(bank.apply(&store(3), 0..4), PostResult::Drop);
    // Excluded members never join a bank.
    let refs: Vec<(String, Vec<u8>)> = (0..4)
        .map(|i| (format!("dct_{i}_192.npy"), npy("<f8", "(192,)")))
        .collect();
    let refs: Vec<(&str, Vec<u8>)> = refs.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
    assert_eq!(bank.apply(&npz(&refs), 0..4), PostResult::Drop);
}

/// `n` floats joined by `sep`, wrapped in `open`/`close`.
fn floats(n: usize, sep: &str, open: &str, close: &str) -> String {
    let v: Vec<String> = (0..n).map(|i| format!("{}.{:04}", i % 3, i)).collect();
    format!("{open}{}{close}", v.join(sep))
}

#[test]
fn float_arrays_of_embedding_width() {
    let one = floats(192, ", ", "x = [", "]\n");
    let r = float_arrays(one.as_bytes(), DIMS);
    assert_eq!(r.len(), 1);
    assert_eq!(&one.as_bytes()[r[0].clone()][..2], b"[0");
    assert!(float_arrays(floats(191, ", ", "[", "]").as_bytes(), DIMS).is_empty());
    // numpy repr, wrapped over lines, and a JSON array with newlines.
    let np = floats(256, ",\n       ", "array([ ", "])");
    assert_eq!(float_arrays(np.as_bytes(), DIMS).len(), 1);
    let js = floats(192, ",\n    ", "{\"v\": [\n    ", "\n  ]}");
    assert_eq!(float_arrays(js.as_bytes(), DIMS).len(), 1);
    // A matrix of embedding rows: one array per row.
    let rows = format!(
        "[{}, {}]",
        floats(192, ", ", "[", "]"),
        floats(256, ", ", "[", "]")
    );
    assert_eq!(float_arrays(rows.as_bytes(), DIMS).len(), 2);
    // Unbracketed runs (CSV) and arrays with a non-float element do not count.
    assert!(float_arrays(floats(192, ",", "", "\n").as_bytes(), DIMS).is_empty());
    let mixed = floats(192, ", ", "[", ", 7]");
    assert!(float_arrays(mixed.as_bytes(), DIMS).is_empty());
    assert!(float_arrays(b"[] [ ] [[", DIMS).is_empty());
    let p = FloatArray {
        embedding_dims: DIMS.to_vec(),
    };
    assert_eq!(
        p.runs(one.as_bytes()),
        Some(float_arrays(one.as_bytes(), DIMS))
    );
}

#[test]
fn line_index() {
    let c = b"a\nbb\n\nccc";
    let li = LineIndex::new(c);
    assert_eq!(li.lines(0, 1), (1, 1));
    assert_eq!(li.lines(2, 4), (2, 2));
    // range covering the newline at byte 4 ends on line 2 (last byte is 4)
    assert_eq!(li.lines(2, 5), (2, 2));
    assert_eq!(li.lines(2, 6), (2, 3));
    assert_eq!(li.lines(6, 9), (4, 4));
    assert_eq!(li.lines(0, 9), (1, 4));
    assert_eq!(li.lines(5, 5), (3, 3));
}
