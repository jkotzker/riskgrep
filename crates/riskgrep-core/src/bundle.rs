//! Compiled rule bundles with an on-disk native-code cache.

use crate::meta::{PostSpec, RuleMeta};
use crate::paths::ensure_private_dir;
use crate::ruleset::{Error, Result, Ruleset};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const YARA_X_VERSION: &str = "1.21.0";

pub struct Bundle {
    pub rules: yara_x::Rules,
    /// Keyed by `namespace:identifier`; the namespace is the ruleset id.
    pub meta: HashMap<String, RuleMeta>,
    pub hash: String,
    /// Stopword lists of all rulesets, merged by list name.
    pub stopwords: BTreeMap<String, Vec<String>>,
    /// True when this load compiled from source rather than reading the cache.
    pub compiled: bool,
    /// Set when the cache was bypassed, found invalid, or could not be written.
    pub cache_warning: Option<String>,
}

/// Hex BLAKE3 over the yara-x version, platform, and every ruleset's id,
/// version, and source bytes, with rulesets taken in id order.
pub fn bundle_key(rulesets: &[&Ruleset]) -> String {
    let mut sorted: Vec<&&Ruleset> = rulesets.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut h = blake3::Hasher::new();
    let mut field = |s: &str| {
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s.as_bytes());
    };
    field(YARA_X_VERSION);
    field(std::env::consts::OS);
    field(std::env::consts::ARCH);
    for rs in sorted {
        field(&rs.id);
        field(&rs.version);
        for (name, src) in &rs.sources {
            field(name);
            field(src);
        }
    }
    h.finalize().to_hex().to_string()
}

fn err(msg: impl std::fmt::Display) -> Error {
    Error(msg.to_string())
}

fn merge_stopwords(rulesets: &[&Ruleset]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rs in rulesets {
        for (name, words) in &rs.stopwords {
            match out.get(name) {
                Some(prev) if prev != words => {
                    return Err(err(format!(
                        "stopword list `{name}` differs between rulesets (second: {})",
                        rs.id
                    )))
                }
                _ => {
                    out.insert(name.clone(), words.clone());
                }
            }
        }
    }
    Ok(out)
}

fn compile(rulesets: &[&Ruleset]) -> Result<yara_x::Rules> {
    let mut c = yara_x::Compiler::new();
    c.define_global("path", "")
        .map_err(|e| err(format!("define_global: {e}")))?;
    for rs in rulesets {
        c.new_namespace(&rs.id);
        for (file, src) in &rs.sources {
            c.add_source(src.as_str())
                .map_err(|e| err(format!("ruleset {} ({file}): {e}", rs.id)))?;
        }
    }
    Ok(c.build())
}

fn collect_meta(rules: &yara_x::Rules, rulesets: &[&Ruleset]) -> Result<HashMap<String, RuleMeta>> {
    let mut out = HashMap::new();
    for rule in rules.iter() {
        let ns = rule.namespace();
        let meta = RuleMeta::from_yara(&rule).map_err(|e| err(format!("ruleset {ns}: {e}")))?;
        for p in &meta.post {
            if let PostSpec::Stopwords { list } = p {
                let found = rulesets
                    .iter()
                    .find(|r| r.id == ns)
                    .is_some_and(|r| r.stopwords.contains_key(list));
                if !found {
                    return Err(err(format!(
                        "ruleset {ns}: rule {}: stopword list `{list}` not found",
                        rule.identifier()
                    )));
                }
            }
        }
        out.insert(format!("{ns}:{}", rule.identifier()), meta);
    }
    Ok(out)
}

/// Read a cached bundle. `Ok(None)` means no cache entry exists; `Err` carries
/// a warning explaining why an existing entry was not used.
fn read_cached(
    cache_dir: &Path,
    dir: &Path,
    file: &Path,
    rulesets: &[&Ruleset],
) -> std::result::Result<Option<(yara_x::Rules, HashMap<String, RuleMeta>)>, String> {
    let euid = unsafe { libc::geteuid() };
    for d in [cache_dir, dir] {
        let md = match fs::symlink_metadata(d) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cache directory {}: {e}", d.display())),
        };
        if !md.is_dir() || md.uid() != euid {
            return Err(format!(
                "cache directory {} is not a directory owned by the current user",
                d.display()
            ));
        }
        if md.mode() & 0o077 != 0 {
            ensure_private_dir(d).map_err(|e| format!("cache directory {}: {e}", d.display()))?;
        }
    }
    let md = match fs::symlink_metadata(file) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cached bundle {}: {e}", file.display())),
    };
    if !md.file_type().is_file() || md.uid() != euid || md.mode() & 0o077 != 0 {
        return Err(format!(
            "cached bundle {} is not a private regular file owned by the current user; not used",
            file.display()
        ));
    }
    let bytes = fs::read(file).map_err(|e| format!("cached bundle {}: {e}", file.display()))?;
    let rules = yara_x::Rules::deserialize(&bytes)
        .map_err(|e| format!("cached bundle {} is invalid: {e}", file.display()))?;
    let meta = collect_meta(&rules, rulesets)
        .map_err(|e| format!("cached bundle {} is invalid: {e}", file.display()))?;
    Ok(Some((rules, meta)))
}

pub fn load_or_compile(rulesets: &[&Ruleset], cache_dir: &Path) -> Result<Bundle> {
    let hash = bundle_key(rulesets);
    let stopwords = merge_stopwords(rulesets)?;
    let dir = cache_dir.join("bundles");
    let file = dir.join(format!("{hash}.yxb"));

    let mut cache_warning = None;
    match read_cached(cache_dir, &dir, &file, rulesets) {
        Ok(Some((rules, meta))) => {
            return Ok(Bundle {
                rules,
                meta,
                hash,
                stopwords,
                compiled: false,
                cache_warning: None,
            })
        }
        Ok(None) => {}
        Err(w) => cache_warning = Some(w),
    }

    let rules = compile(rulesets)?;
    let meta = collect_meta(&rules, rulesets)?;
    let bytes = rules
        .serialize()
        .map_err(|e| err(format!("serialize: {e}")))?;
    if let Err(e) = write_atomic(&dir, &file, &bytes) {
        let msg = format!("cache not written: {e}");
        cache_warning = Some(match cache_warning {
            Some(w) => format!("{w}; {msg}"),
            None => msg,
        });
    }
    Ok(Bundle {
        rules,
        meta,
        hash,
        stopwords,
        compiled: true,
        cache_warning,
    })
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(dir: &Path, file: &Path, bytes: &[u8]) -> Result<()> {
    let io = |e: std::io::Error| err(format!("{}: {e}", file.display()));
    ensure_private_dir(dir).map_err(io)?;
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = file.with_extension(format!("yxb.tmp-{}-{n}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io)?;
    let res = f
        .write_all(bytes)
        .and_then(|_| f.sync_all())
        .and_then(|_| fs::set_permissions(&tmp, Permissions::from_mode(0o600)))
        .and_then(|_| fs::rename(&tmp, file));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(io)
}
