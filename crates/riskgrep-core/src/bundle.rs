//! Compiled rule bundles with an on-disk native-code cache.

use crate::meta::{PostSpec, RuleMeta};
use crate::paths::ensure_private_dir;
use crate::ruleset::{Error, Result, Ruleset};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

const YARA_X_VERSION: &str = "1.22.0";

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

/// Hex BLAKE3 over the yara-x version, this riskgrep version, the platform,
/// and every ruleset's id and [`Ruleset::digest`] (its manifest, sources,
/// and stopword lists), with rulesets taken in id order. Also the evidence
/// cache's key prefix, so any change to the engine or to what a rule's
/// post-processors read gives new keys.
pub fn bundle_key(rulesets: &[&Ruleset]) -> String {
    bundle_key_for_version(env!("CARGO_PKG_VERSION"), rulesets)
}

/// [`bundle_key`] for riskgrep version `version`.
#[doc(hidden)]
pub fn bundle_key_for_version(version: &str, rulesets: &[&Ruleset]) -> String {
    let mut sorted: Vec<&&Ruleset> = rulesets.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut h = blake3::Hasher::new();
    let mut field = |s: &[u8]| {
        h.update(&(s.len() as u64).to_le_bytes());
        h.update(s);
    };
    field(YARA_X_VERSION.as_bytes());
    field(version.as_bytes());
    field(std::env::consts::OS.as_bytes());
    field(std::env::consts::ARCH.as_bytes());
    for rs in sorted {
        field(rs.id.as_bytes());
        field(rs.digest());
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
            c.add_source(src.as_ref())
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

type Cached = (yara_x::Rules, HashMap<String, RuleMeta>);

/// Check that `cache_dir` and `dir` are directories owned by the current user
/// (tightening a loose mode) and that `file`, if present, is a private
/// regular file owned by the current user. `Ok(false)` means something does
/// not exist; `Err` carries a warning explaining why an entry must not be used.
fn check_private(
    cache_dir: &Path,
    dir: &Path,
    file: &Path,
    what: &str,
) -> std::result::Result<bool, String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    for d in [cache_dir, dir] {
        let md = match fs::symlink_metadata(d) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("{what} {}: {e}", file.display())),
    };
    if !md.file_type().is_file() || md.uid() != euid || md.mode() & 0o077 != 0 {
        return Err(format!(
            "{what} {} is not a private regular file owned by the current user; not used",
            file.display()
        ));
    }
    Ok(true)
}

/// Read a cached bundle. `Ok(None)` means no cache entry exists; `Err` carries
/// a warning explaining why an existing entry was not used.
fn read_cached(
    cache_dir: &Path,
    dir: &Path,
    file: &Path,
    rulesets: &[&Ruleset],
) -> std::result::Result<Option<Cached>, String> {
    if !check_private(cache_dir, dir, file, "cached bundle")? {
        return Ok(None);
    }
    let bytes = fs::read(file).map_err(|e| format!("cached bundle {}: {e}", file.display()))?;
    let rules = yara_x::Rules::deserialize(&bytes)
        .map_err(|e| format!("cached bundle {} is invalid: {e}", file.display()))?;
    let meta = collect_meta(&rules, rulesets)
        .map_err(|e| format!("cached bundle {} is invalid: {e}", file.display()))?;
    Ok(Some((rules, meta)))
}

fn sidecar_path(dir: &Path, key: &str) -> std::path::PathBuf {
    dir.join(format!("{key}.meta.json"))
}

/// The rule metadata stored beside the bundle `key`, so scoring cached
/// evidence needs no compiled rules. `None` when the sidecar is missing,
/// fails the privacy checks, or does not parse; the caller then loads the
/// full bundle (which rewrites the sidecar).
pub fn load_meta_sidecar(cache_dir: &Path, key: &str) -> Option<HashMap<String, RuleMeta>> {
    let dir = cache_dir.join("bundles");
    let file = sidecar_path(&dir, key);
    if !matches!(
        check_private(cache_dir, &dir, &file, "rule metadata"),
        Ok(true)
    ) {
        return None;
    }
    let bytes = fs::read(&file).ok()?;
    let meta: BTreeMap<String, RuleMeta> = serde_json::from_slice(&bytes).ok()?;
    let valid = |m: &RuleMeta| {
        (-100.0..=100.0).contains(&m.weight)
            && m.family_cap.is_none_or(|c| (0.0..=100.0).contains(&c))
    };
    if meta.is_empty() || !meta.iter().all(|(k, m)| k.contains(':') && valid(m)) {
        return None;
    }
    Some(meta.into_iter().collect())
}

fn write_sidecar(dir: &Path, key: &str, meta: &HashMap<String, RuleMeta>) -> Result<()> {
    let sorted: BTreeMap<&String, &RuleMeta> = meta.iter().collect();
    let json = serde_json::to_vec(&sorted).map_err(|e| err(format!("rule metadata: {e}")))?;
    write_atomic(dir, &sidecar_path(dir, key), &json)
}

fn add_warning(b: &mut Bundle, msg: String) {
    b.cache_warning = Some(match b.cache_warning.take() {
        Some(w) => format!("{w}; {msg}"),
        None => msg,
    });
}

/// True when `file` is a private regular file owned by the current user.
fn private_file(file: &Path) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    fs::symlink_metadata(file)
        .is_ok_and(|m| m.file_type().is_file() && m.uid() == euid && m.mode() & 0o077 == 0)
}

/// What [`load_or_compile_keyed`] does with the rule-metadata sidecar of a
/// bundle read from the cache (a compiled bundle always writes one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sidecar {
    /// Parse it and rewrite it when it does not load.
    Validate,
    /// Rewrite it only when it is missing (or not a private file); used by
    /// callers that have not found it unusable, so it is not parsed again.
    IfMissing,
    /// Rewrite it: the caller tried it and could not use it.
    Rewrite,
}

/// Load the bundle for `rulesets` from `cache_dir`, compiling and caching it
/// on a miss; validates the sidecar. See [`load_or_compile_keyed`].
pub fn load_or_compile(rulesets: &[&Ruleset], cache_dir: &Path) -> Result<Bundle> {
    load_or_compile_keyed(
        rulesets,
        cache_dir,
        &bundle_key(rulesets),
        Sidecar::Validate,
    )
}

/// [`load_or_compile`] with the bundle key already computed (it must be
/// [`bundle_key`] of `rulesets`) and a choice of sidecar handling.
pub fn load_or_compile_keyed(
    rulesets: &[&Ruleset],
    cache_dir: &Path,
    key: &str,
    sidecar: Sidecar,
) -> Result<Bundle> {
    let hash = key.to_string();
    let stopwords = merge_stopwords(rulesets)?;
    let dir = cache_dir.join("bundles");
    let file = dir.join(format!("{hash}.yxb"));

    let mut cache_warning = None;
    match read_cached(cache_dir, &dir, &file, rulesets) {
        Ok(Some((rules, meta))) => {
            let mut b = Bundle {
                rules,
                meta,
                hash,
                stopwords,
                compiled: false,
                cache_warning: None,
            };
            let rewrite = match sidecar {
                Sidecar::Validate => load_meta_sidecar(cache_dir, &b.hash).is_none(),
                Sidecar::IfMissing => !private_file(&sidecar_path(&dir, &b.hash)),
                Sidecar::Rewrite => true,
            };
            if rewrite {
                if let Err(e) = write_sidecar(&dir, &b.hash, &b.meta) {
                    add_warning(&mut b, format!("rule metadata not written: {e}"));
                }
            }
            return Ok(b);
        }
        Ok(None) => {}
        Err(w) => cache_warning = Some(w),
    }

    let mut b = compile_bundle(rulesets, hash, stopwords)?;
    b.cache_warning = cache_warning;
    let bytes = b
        .rules
        .serialize()
        .map_err(|e| err(format!("serialize: {e}")))?;
    if let Err(e) = write_atomic(&dir, &file, &bytes) {
        add_warning(&mut b, format!("cache not written: {e}"));
    } else if let Err(e) = write_sidecar(&dir, &b.hash, &b.meta) {
        add_warning(&mut b, format!("rule metadata not written: {e}"));
    }
    Ok(b)
}

/// Compile without reading or writing any cache; for callers with no usable
/// cache directory. `cache_warning` is always set.
pub fn compile_uncached(rulesets: &[&Ruleset]) -> Result<Bundle> {
    let mut b = compile_bundle(rulesets, bundle_key(rulesets), merge_stopwords(rulesets)?)?;
    b.cache_warning = Some("cache disabled: no absolute cache directory".into());
    Ok(b)
}

fn compile_bundle(
    rulesets: &[&Ruleset],
    hash: String,
    stopwords: BTreeMap<String, Vec<String>>,
) -> Result<Bundle> {
    let rules = compile(rulesets)?;
    let meta = collect_meta(&rules, rulesets)?;
    Ok(Bundle {
        rules,
        meta,
        hash,
        stopwords,
        compiled: true,
        cache_warning: None,
    })
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(dir: &Path, file: &Path, bytes: &[u8]) -> Result<()> {
    let io = |e: std::io::Error| err(format!("{}: {e}", file.display()));
    ensure_private_dir(dir).map_err(io)?;
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}-{n}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
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

/// A temporary file left by a write that did not finish is removed after
/// this long, whatever the configured age.
const STRAY_TEMP_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// What [`prune_bundles`] removed (or, in a dry run, would remove).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BundlePrune {
    /// Keys whose bundle and metadata files were removed, in key order.
    pub removed_keys: Vec<String>,
    /// Files removed, including stray temporary files.
    pub removed_files: u64,
    pub removed_bytes: u64,
    /// Keys that still have a compiled bundle (`.yxb`) afterwards.
    pub kept_keys: BTreeSet<String>,
    pub kept_bytes: u64,
}

/// The bundle key a file in `bundles/` belongs to, and whether it is a
/// stray temporary file. `None` for any name this module did not write.
fn bundle_file_key(name: &str) -> Option<(&str, bool)> {
    let (key, rest) = name.split_once('.')?;
    if key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let stem = rest.split(".tmp-").next().unwrap_or(rest);
    (stem == "yxb" || stem == "meta.json").then_some((key, rest.contains(".tmp-")))
}

/// Remove compiled bundles (and their metadata files) whose key is not in
/// `protected` and whose newest file was written more than `max_age` ago.
/// Temporary files from interrupted writes go after a day. Files this module
/// did not write are left alone. A bundle that goes is compiled again on the
/// next scan that needs it.
pub fn prune_bundles(
    cache_dir: &Path,
    protected: &BTreeSet<String>,
    max_age: Duration,
    now: SystemTime,
    dry_run: bool,
) -> std::io::Result<BundlePrune> {
    let dir = cache_dir.join("bundles");
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BundlePrune::default()),
        Err(e) => return Err(e),
    };
    struct Item {
        path: std::path::PathBuf,
        bytes: u64,
        age: Duration,
        has_bundle: bool,
    }
    let mut keys: BTreeMap<String, Vec<Item>> = BTreeMap::new();
    let mut strays: Vec<Item> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((key, temp)) = bundle_file_key(&name) else {
            continue;
        };
        let md = fs::symlink_metadata(entry.path())?;
        if !md.file_type().is_file() {
            continue;
        }
        let age = md
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .unwrap_or_default();
        let item = Item {
            path: entry.path(),
            bytes: md.len(),
            age,
            has_bundle: name.ends_with(".yxb"),
        };
        if temp {
            strays.push(item);
        } else {
            keys.entry(key.to_string()).or_default().push(item);
        }
    }
    let mut out = BundlePrune::default();
    let mut remove = |item: &Item| -> std::io::Result<()> {
        if !dry_run {
            match fs::remove_file(&item.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        out.removed_files += 1;
        out.removed_bytes += item.bytes;
        Ok(())
    };
    for item in strays.iter().filter(|i| i.age > STRAY_TEMP_AGE) {
        remove(item)?;
    }
    let mut kept: Vec<(String, u64, bool)> = Vec::new();
    let mut removed_keys = Vec::new();
    for (key, items) in &keys {
        // The youngest file stands for the key: a metadata file rewritten
        // recently keeps the bundle.
        let age = items.iter().map(|i| i.age).min().unwrap_or_default();
        if protected.contains(key) || age <= max_age {
            let bytes = items.iter().map(|i| i.bytes).sum();
            kept.push((key.clone(), bytes, items.iter().any(|i| i.has_bundle)));
            continue;
        }
        for item in items {
            remove(item)?;
        }
        removed_keys.push(key.clone());
    }
    out.removed_keys = removed_keys;
    for (key, bytes, has_bundle) in kept {
        out.kept_bytes += bytes;
        if has_bundle {
            out.kept_keys.insert(key);
        }
    }
    Ok(out)
}
