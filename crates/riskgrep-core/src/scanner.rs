//! The library facade: one [`RiskGrep`] built from configuration and reused
//! for every scan. It ties together classification, the evidence cache, the
//! lazily loaded rules bundle, suppression, and scoring.
//!
//! The bundle is compiled or loaded only when some target misses the cache;
//! scoring cached evidence reads the rule-metadata sidecar instead.

use crate::bundle;
use crate::cache::{Cache, StatKey};
use crate::classify::{self, Content, FileClass, Known};
use crate::config::{self, Config};
use crate::engine::{Engine, ScanError};
use crate::meta::RuleMeta;
use crate::model::{Category, Evidence, Report, TargetReport, TargetStatus};
use crate::ruleset::{builtin_rulesets, Ruleset};
use crate::score::score_target;
use crate::suppress::{self, Baseline};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::RangeInclusive;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

/// Test hook: called with the resolved path after a file's content has been
/// read and before the file is re-examined for changes.
#[doc(hidden)]
pub static AFTER_READ: OnceLock<fn(&Path)> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskGrepError(pub String);

impl fmt::Display for RiskGrepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RiskGrepError {}

fn error(msg: impl fmt::Display) -> RiskGrepError {
    RiskGrepError(msg.to_string())
}

enum EngineState {
    NotLoaded,
    Loaded(Box<Engine>),
    Failed,
}

/// Scoring metadata after weight overrides, plus bare rule id to
/// `namespace:rule` key.
struct ScoringMeta {
    meta: HashMap<String, RuleMeta>,
    keys: HashMap<String, String>,
}

enum MetaState {
    NotLoaded,
    Loaded(ScoringMeta),
    Failed,
}

pub struct RiskGrep {
    cfg: Config,
    rulesets: Vec<Ruleset>,
    /// `bundle::bundle_key` of `rulesets`; also the evidence-cache key prefix.
    key: String,
    categories: BTreeSet<Category>,
    cache_dir: Option<PathBuf>,
    cache: Option<Cache>,
    engine: EngineState,
    meta: MetaState,
    baseline: Option<Baseline>,
    /// Suppression paths are relative to this (repository root, else cwd).
    rel_base: Option<PathBuf>,
    /// Canonical working directory; the `path` rule external is relative to it.
    cwd: Option<PathBuf>,
}

/// A target before suppression and scoring.
struct Raw {
    target: String,
    status: TargetStatus,
    evidence: Vec<Evidence>,
    /// Path used for ignore globs and baseline fingerprints.
    rel: String,
    /// False for targets that are not content (a directory that hit the walk
    /// limit): they get no scores.
    content: bool,
}

impl Raw {
    fn status(target: String, status: TargetStatus) -> Raw {
        Raw {
            rel: target.clone(),
            target,
            status,
            evidence: Vec::new(),
            content: false,
        }
    }

    fn scanned(target: String, rel: String, status: TargetStatus, evidence: Vec<Evidence>) -> Raw {
        Raw {
            target,
            status,
            evidence,
            rel,
            content: true,
        }
    }
}

/// Content read and ready for the scan engine.
struct Pending {
    target: String,
    rel: String,
    path_ext: String,
    ekey: String,
    content: Content,
    /// Evidence-cache key; `None` when the result must not be cached.
    hash: Option<[u8; 32]>,
    /// Stat entry to record, with the time the file was examined (taken
    /// before the read, so the racy-edit window measures from it); `None`
    /// when the file changed while being read.
    stat: Option<(StatKey, SystemTime)>,
}

enum Step {
    Done(Raw),
    Scan(Pending),
}

enum Job {
    Done(Raw),
    File {
        target: String,
        input: PathBuf,
        explicit: bool,
    },
}

fn unreadable(e: &io::Error) -> TargetStatus {
    TargetStatus::Unscanned {
        reason: format!("unreadable: {:?}", e.kind()),
    }
}

fn skipped(reason: &str) -> TargetStatus {
    TargetStatus::Skipped {
        reason: reason.into(),
    }
}

fn unscanned(reason: &str) -> TargetStatus {
    TargetStatus::Unscanned {
        reason: reason.into(),
    }
}

/// Classification with the safetensors size check applied.
fn classify(name: &str, head: &[u8], size: u64) -> FileClass {
    match classify::classify(name, head) {
        FileClass::KnownBinary(Known::Safetensors)
            if !classify::safetensors_header_fits(head, size) =>
        {
            FileClass::UnknownBinary
        }
        c => c,
    }
}

/// The status for classes v1 does not scan.
fn not_scanned(class: &FileClass) -> Option<TargetStatus> {
    match class {
        FileClass::Archive(kind) => Some(unscanned(&format!("{kind} not scanned in v1"))),
        FileClass::Image(kind) => Some(skipped(&format!("{kind} image not scanned in v1"))),
        FileClass::UnknownBinary => Some(skipped("binary file of unknown format")),
        FileClass::Text | FileClass::KnownBinary(_) => None,
    }
}

fn relative_to(base: Option<&Path>, p: &Path) -> String {
    base.and_then(|b| p.strip_prefix(b).ok())
        .filter(|r| !r.as_os_str().is_empty())
        .unwrap_or(p)
        .display()
        .to_string()
}

/// Keep only locations whose lines meet `only`; evidence left with none is
/// dropped. Location-free evidence (path and whole-file rules) is kept.
fn keep_lines(evidence: &mut Vec<Evidence>, only: &[RangeInclusive<u32>]) {
    let hit = |a: u32, b: u32| only.iter().any(|r| a <= *r.end() && *r.start() <= b);
    evidence.retain_mut(|e| {
        if e.locations.is_empty() {
            return true;
        }
        let keep: Vec<bool> = e
            .locations
            .iter()
            .map(|l| hit(l.line_start, l.line_end))
            .collect();
        let mut i = 0;
        e.locations.retain(|_| {
            i += 1;
            keep[i - 1]
        });
        if e.fingerprints.len() == keep.len() {
            let mut i = 0;
            e.fingerprints.retain(|_| {
                i += 1;
                keep[i - 1]
            });
        }
        e.count = e.locations.len() as u32;
        e.count > 0
    });
}

fn new_scanner<'r>(engine: &'r Engine, cfg: &Config) -> yara_x::Scanner<'r> {
    let mut s = yara_x::Scanner::new(engine.rules());
    s.set_timeout(cfg.limits.time_budget);
    s
}

/// Resolve the enabled rulesets: built-ins plus `extra_ruleset_dirs`, narrowed
/// to `cfg.rulesets` when it names any, then to rulesets scoring an enabled
/// category.
fn resolve_rulesets(cfg: &Config, base: Option<&Path>) -> Result<Vec<Ruleset>, RiskGrepError> {
    let mut all = builtin_rulesets();
    for d in &cfg.extra_ruleset_dirs {
        let dir = match base {
            Some(b) if d.is_relative() => b.join(d),
            _ => d.clone(),
        };
        let rs = Ruleset::load_dir(&dir).map_err(|e| error(format!("ruleset: {e}")))?;
        if all.iter().any(|r| r.id == rs.id) {
            return Err(error(format!(
                "ruleset id `{}` in {} is already defined",
                rs.id,
                dir.display()
            )));
        }
        all.push(rs);
    }
    let mut selected = if cfg.rulesets.is_empty() {
        all
    } else {
        let mut out: Vec<Ruleset> = Vec::new();
        for id in &cfg.rulesets {
            if out.iter().any(|r| &r.id == id) {
                continue;
            }
            let rs = all
                .iter()
                .find(|r| &r.id == id)
                .ok_or_else(|| error(format!("unknown ruleset `{id}`")))?;
            out.push(rs.clone());
        }
        out
    };
    if let Some(cats) = &cfg.categories {
        selected.retain(|r| r.categories.iter().any(|c| cats.contains(c)));
    }
    if selected.is_empty() {
        return Err(error("no rulesets enabled"));
    }
    Ok(selected)
}

impl RiskGrep {
    /// Opens the evidence cache and resolves the enabled rulesets; the rules
    /// bundle is loaded on the first cache miss. `repo_root` anchors relative
    /// `extra_ruleset_dirs`, the baseline, and suppression paths.
    pub fn new(cfg: Config, repo_root: Option<&Path>) -> Result<RiskGrep, RiskGrepError> {
        let dir = crate::paths::cache_dir();
        if dir.is_none() {
            eprintln!("riskgrep: cache disabled: no absolute cache directory");
        }
        Self::with_cache_dir(cfg, repo_root, dir)
    }

    /// [`RiskGrep::new`] with an explicit cache directory (`None`: no cache).
    #[doc(hidden)]
    pub fn with_cache_dir(
        cfg: Config,
        repo_root: Option<&Path>,
        cache_dir: Option<PathBuf>,
    ) -> Result<RiskGrep, RiskGrepError> {
        let cwd = std::env::current_dir().and_then(fs::canonicalize).ok();
        let root = repo_root.map(|r| fs::canonicalize(r).unwrap_or_else(|_| r.to_path_buf()));
        let base = root.clone().or_else(|| cwd.clone());
        let rulesets = resolve_rulesets(&cfg, base.as_deref())?;
        let refs: Vec<&Ruleset> = rulesets.iter().collect();
        let key = bundle::bundle_key(&refs);
        let categories: BTreeSet<Category> = rulesets
            .iter()
            .flat_map(|r| r.categories.iter().cloned())
            .filter(|c| cfg.categories.as_ref().is_none_or(|cs| cs.contains(c)))
            .collect();
        let baseline = match config::baseline_path(cfg.mode, root.as_deref(), &cfg) {
            Some(p) if fs::symlink_metadata(&p).is_ok() => {
                Some(Baseline::load(&p).map_err(|e| error(e.0))?)
            }
            _ => None,
        };
        let cache = match &cache_dir {
            Some(d) if !cfg.no_cache => Cache::open(d),
            _ => None,
        };
        Ok(RiskGrep {
            cfg,
            rulesets,
            key,
            categories,
            cache_dir,
            cache,
            engine: EngineState::NotLoaded,
            meta: MetaState::NotLoaded,
            baseline,
            rel_base: base,
            cwd,
        })
    }

    /// True once the compiled rules bundle has been loaded.
    pub fn bundle_loaded(&self) -> bool {
        matches!(self.engine, EngineState::Loaded(_))
    }

    /// Scan files and directories. Explicit paths follow symlinks; directory
    /// walks do not, ignore `.gitignore`, and stop at `limits.walk_files`.
    pub fn scan_paths(&mut self, paths: &[PathBuf]) -> Report {
        let jobs = self.expand(paths);
        let mut raws = Vec::with_capacity(jobs.len());
        let mut jobs = jobs.into_iter();
        let mut first = None;
        for job in jobs.by_ref() {
            match self.prepare(job) {
                Step::Done(r) => raws.push(r),
                Step::Scan(p) => {
                    first = Some(p);
                    break;
                }
            }
        }
        if let Some(p) = first {
            self.load_engine();
            let engine = match &self.engine {
                EngineState::Loaded(e) => Some(&**e),
                _ => None,
            };
            let mut scanner = engine.map(|e| new_scanner(e, &self.cfg));
            raws.push(self.finish(engine.zip(scanner.as_mut()), p));
            for job in jobs {
                let raw = match self.prepare(job) {
                    Step::Done(r) => r,
                    Step::Scan(p) => self.finish(engine.zip(scanner.as_mut()), p),
                };
                raws.push(raw);
            }
        }
        let targets = self.finalize(raws);
        self.report(targets)
    }

    /// Scan raw text (stdin). Never cached; text limits apply.
    pub fn scan_bytes(&mut self, name: &str, bytes: &[u8]) -> Report {
        let raw = match classify::slice_for_scan(bytes, &FileClass::Text, &self.cfg.limits) {
            Err(e) => Raw::status(name.to_string(), unreadable(&e)),
            Ok(content) => self.scan_now(Pending {
                target: name.to_string(),
                rel: name.to_string(),
                path_ext: "<stdin>".into(),
                ekey: String::new(),
                content,
                hash: None,
                stat: None,
            }),
        };
        let targets = self.finalize(vec![raw]);
        self.report(targets)
    }

    /// Scan one git blob. `name` is its repository-relative path; results are
    /// cached by `blob_id`. With `only_lines`, evidence located outside those
    /// lines is dropped before scoring.
    pub fn scan_blob(
        &mut self,
        name: &str,
        blob_id: &[u8],
        bytes: &[u8],
        only_lines: Option<&[RangeInclusive<u32>]>,
    ) -> TargetReport {
        let mut raw = self.prepare_blob(name, blob_id, bytes);
        if let Some(only) = only_lines {
            keep_lines(&mut raw.evidence, only);
        }
        self.finalize(vec![raw]).remove(0)
    }

    fn prepare_blob(&mut self, name: &str, blob_id: &[u8], bytes: &[u8]) -> Raw {
        let size = bytes.len() as u64;
        let head = &bytes[..bytes.len().min(self.cfg.limits.sniff)];
        let class = classify(name, head, size);
        if let Some(s) = not_scanned(&class) {
            return Raw::status(name.to_string(), s);
        }
        let ekey = format!("{}:{name}", self.key);
        let mut h = blake3::Hasher::new();
        h.update(b"riskgrep-git-blob\0");
        h.update(blob_id);
        let blob_key = *h.finalize().as_bytes();
        if let Some(ev) = self
            .cache
            .as_ref()
            .and_then(|c| c.evidence(blob_key, &ekey))
        {
            return Raw::scanned(name.into(), name.into(), TargetStatus::Scanned, ev);
        }
        match classify::slice_for_scan(bytes, &class, &self.cfg.limits) {
            Err(e) => Raw::status(name.to_string(), unreadable(&e)),
            Ok(content) => self.scan_now(Pending {
                target: name.to_string(),
                rel: name.to_string(),
                path_ext: name.to_string(),
                ekey,
                hash: content.partial.is_none().then_some(blob_key),
                content,
                stat: None,
            }),
        }
    }

    /// Load the engine if needed and scan one pending target.
    fn scan_now(&mut self, p: Pending) -> Raw {
        self.load_engine();
        let engine = match &self.engine {
            EngineState::Loaded(e) => Some(&**e),
            _ => None,
        };
        let mut scanner = engine.map(|e| new_scanner(e, &self.cfg));
        self.finish(engine.zip(scanner.as_mut()), p)
    }

    fn report(&self, targets: Vec<TargetReport>) -> Report {
        Report::from_targets(env!("CARGO_PKG_VERSION"), &self.key, targets)
    }

    /// Turn the requested paths into file jobs and finished targets.
    fn expand(&self, paths: &[PathBuf]) -> Vec<Job> {
        let mut jobs = Vec::new();
        let mut budget = self.cfg.limits.walk_files;
        for p in paths {
            let target = p.display().to_string();
            let md = match fs::symlink_metadata(p) {
                Ok(m) if m.file_type().is_symlink() => fs::metadata(p),
                other => other,
            };
            match md {
                Err(e) => jobs.push(Job::Done(Raw::status(target, unreadable(&e)))),
                Ok(m) if m.is_dir() => {
                    if walk(p, &mut jobs, &mut budget) {
                        jobs.push(Job::Done(Raw::status(
                            target,
                            TargetStatus::Partial {
                                not_read: format!(
                                    "directory walk stopped at {} files",
                                    self.cfg.limits.walk_files
                                ),
                            },
                        )));
                    }
                }
                Ok(_) => jobs.push(Job::File {
                    target,
                    input: p.clone(),
                    explicit: true,
                }),
            }
        }
        jobs
    }

    /// Everything up to the engine scan: type checks, classification, cache
    /// lookups, and the bounded read. Never loads the bundle.
    fn prepare(&self, job: Job) -> Step {
        let (target, input, explicit) = match job {
            Job::Done(r) => return Step::Done(r),
            Job::File {
                target,
                input,
                explicit,
            } => (target, input, explicit),
        };
        match self.prepare_file(&target, &input, explicit) {
            Ok(step) => step,
            Err(e) => Step::Done(Raw::status(target, unreadable(&e))),
        }
    }

    fn prepare_file(&self, target: &str, input: &Path, explicit: bool) -> io::Result<Step> {
        let done = |s: TargetStatus| Ok(Step::Done(Raw::status(target.to_string(), s)));
        let mut md = fs::symlink_metadata(input)?;
        if md.file_type().is_symlink() {
            if !explicit {
                return done(skipped("symlink not followed"));
            }
            md = fs::metadata(input)?;
        }
        if !md.is_file() {
            return done(skipped("not a regular file"));
        }
        let real = fs::canonicalize(input)?;
        // Non-blocking, so a file swapped for a FIFO after the check above
        // cannot hang the open (reads of regular files are unaffected); no
        // follow, so a symlink swapped in after `canonicalize` is refused.
        let file: File = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(&real)?;
        let fmd = file.metadata()?;
        // Taken with the stat: recorded as the stat entry's write time, so
        // the racy-edit window is not narrowed by read or scan time.
        let now = SystemTime::now();
        if !fmd.is_file() {
            return done(skipped("not a regular file"));
        }
        // The opened file must be the one checked above: a walk entry
        // replaced by a symlink (which `canonicalize` would follow) or any
        // other swap is not scanned.
        if (fmd.dev(), fmd.ino()) != (md.dev(), md.ino()) {
            return done(unscanned("file replaced during scan"));
        }
        let size = fmd.len();
        let key = StatKey::from_metadata(&real, &fmd);
        let mut head = vec![0u8; size.min(self.cfg.limits.sniff as u64) as usize];
        file.read_exact_at(&mut head, 0)?;
        let name = real
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let class = classify(&name, &head, size);
        if let Some(s) = not_scanned(&class) {
            return done(s);
        }

        let path_ext = relative_to(self.cwd.as_deref(), &real);
        let ekey = format!("{}:{path_ext}", self.key);
        let rel = relative_to(self.rel_base.as_deref(), &real);
        let cache = self.cache.as_ref();
        let hit = |ev: Vec<Evidence>| {
            Ok(Step::Done(Raw::scanned(
                target.to_string(),
                rel.clone(),
                TargetStatus::Scanned,
                ev,
            )))
        };
        if let Some(c) = cache {
            if let Some(ev) = c
                .content_hash_for(&key, now)
                .and_then(|h| c.evidence(h, &ekey))
            {
                return hit(ev);
            }
        }

        let content = classify::read_for_scan(&file, size, &class, &self.cfg.limits)?;
        if let Some(hook) = AFTER_READ.get() {
            hook(&real);
        }
        // A file that changed while being read still gets its evidence
        // cached: that row is content-addressed (keyed by the hash of the
        // bytes actually scanned), so it is correct for that content. Only
        // the stat row, which would tie the pre-read identity to this
        // content, is withheld.
        let stable = fs::metadata(&real)
            .map(|m| StatKey::from_metadata(&real, &m) == key)
            .unwrap_or(false);
        // Partial reads are never cached, so a hit always means a full scan.
        let hash = content
            .partial
            .is_none()
            .then(|| *blake3::hash(&content.bytes).as_bytes());
        if let (Some(c), Some(h)) = (cache, hash) {
            if let Some(ev) = c.evidence(h, &ekey) {
                if stable {
                    c.put_stat(&key, h, now);
                }
                return hit(ev);
            }
        }
        Ok(Step::Scan(Pending {
            target: target.to_string(),
            rel,
            path_ext,
            ekey,
            content,
            hash,
            stat: stable.then_some((key, now)),
        }))
    }

    /// Run the engine over pending content and record the result in the
    /// cache. `None` for the engine means the rules could not be loaded.
    fn finish(&self, engine: Option<(&Engine, &mut yara_x::Scanner<'_>)>, p: Pending) -> Raw {
        let Some((engine, scanner)) = engine else {
            return Raw::status(p.target, unscanned("rule load failure"));
        };
        let ev = match engine.scan_content(scanner, &p.path_ext, &p.content.bytes) {
            Ok(ev) => ev,
            Err(ScanError::Timeout) => return Raw::status(p.target, unscanned("timeout")),
            Err(ScanError::Yara(_)) => return Raw::status(p.target, unscanned("scan error")),
        };
        if let (Some(c), Some(h)) = (self.cache.as_ref(), p.hash) {
            c.put_evidence(h, &p.ekey, &ev);
            if let Some((k, examined)) = &p.stat {
                c.put_stat(k, h, *examined);
            }
        }
        let status = match p.content.partial {
            Some(not_read) => TargetStatus::Partial { not_read },
            None => TargetStatus::Scanned,
        };
        Raw::scanned(p.target, p.rel, status, ev)
    }

    fn load_engine(&mut self) {
        if !matches!(self.engine, EngineState::NotLoaded) {
            return;
        }
        let refs: Vec<&Ruleset> = self.rulesets.iter().collect();
        let loaded = match &self.cache_dir {
            Some(d) => bundle::load_or_compile(&refs, d),
            None => bundle::compile_uncached(&refs),
        };
        let b = match loaded {
            Ok(b) => b,
            Err(e) => {
                eprintln!("riskgrep: rules: {e}");
                self.engine = EngineState::Failed;
                return;
            }
        };
        if self.cache_dir.is_some() {
            if let Some(w) = &b.cache_warning {
                eprintln!("riskgrep: rules cache: {w}");
            }
        }
        if matches!(self.meta, MetaState::NotLoaded) {
            self.meta = self.scoring_meta(b.meta.clone());
        }
        self.engine = match Engine::new(b) {
            Ok(e) => EngineState::Loaded(Box::new(e)),
            Err(e) => {
                eprintln!("riskgrep: rules: {e}");
                EngineState::Failed
            }
        };
    }

    /// Apply weight overrides and index rules by bare id.
    fn scoring_meta(&self, mut meta: HashMap<String, RuleMeta>) -> MetaState {
        if let Err(e) = self.cfg.apply_weight_overrides(&mut meta) {
            eprintln!("riskgrep: config: {e}");
            return MetaState::Failed;
        }
        let mut keys: HashMap<String, String> = HashMap::new();
        let mut sorted: Vec<&String> = meta.keys().collect();
        sorted.sort();
        for k in sorted {
            let Some((_, rule)) = k.split_once(':') else {
                continue;
            };
            if let Some(prev) = keys.insert(rule.to_string(), k.clone()) {
                eprintln!(
                    "riskgrep: rules: rule id `{rule}` is defined by both `{prev}` and `{k}`"
                );
                return MetaState::Failed;
            }
        }
        MetaState::Loaded(ScoringMeta { meta, keys })
    }

    /// Scoring metadata: the sidecar when it is usable, else the full bundle.
    fn ensure_meta(&mut self) {
        if !matches!(self.meta, MetaState::NotLoaded) {
            return;
        }
        if let Some(m) = self
            .cache_dir
            .as_deref()
            .and_then(|d| bundle::load_meta_sidecar(d, &self.key))
        {
            self.meta = self.scoring_meta(m);
            return;
        }
        self.load_engine();
        if matches!(self.meta, MetaState::NotLoaded) {
            self.meta = MetaState::Failed;
        }
    }

    /// Category filter, weight overrides, suppression, then scoring.
    fn finalize(&mut self, raws: Vec<Raw>) -> Vec<TargetReport> {
        if raws.iter().any(|r| r.content) {
            self.ensure_meta();
        }
        raws.into_iter().map(|r| self.finalize_one(r)).collect()
    }

    fn finalize_one(&self, raw: Raw) -> TargetReport {
        let mut t = TargetReport {
            target: raw.target,
            status: raw.status,
            scores: BTreeMap::new(),
            evidence: raw.evidence,
            suppressed: 0,
        };
        if !raw.content {
            return t;
        }
        let sm = match &self.meta {
            MetaState::Loaded(sm) => sm,
            _ => {
                t.status = unscanned("rule load failure");
                t.evidence.clear();
                return t;
            }
        };
        t.evidence.retain(|e| self.categories.contains(&e.category));
        for e in &mut t.evidence {
            if let Some(m) = sm.keys.get(&e.rule).and_then(|k| sm.meta.get(k)) {
                e.weight = m.weight;
            }
        }
        let rel = raw.rel;
        suppress::apply(
            std::slice::from_mut(&mut t),
            &self.cfg.ignore,
            self.baseline.as_ref(),
            |_| rel.clone(),
        );
        t.scores = score_target(&t.evidence, &sm.meta);
        for c in &self.categories {
            t.scores.entry(c.clone()).or_insert(0.0);
        }
        t
    }
}

/// Walk `dir` without following symlinks, sorted per directory. Every
/// non-directory entry spends one unit of `budget`; returns true when the
/// walk stopped because the budget ran out.
fn walk(dir: &Path, jobs: &mut Vec<Job>, budget: &mut usize) -> bool {
    let target = dir.display().to_string();
    let entries = match fs::read_dir(dir).and_then(|rd| rd.collect::<io::Result<Vec<_>>>()) {
        Ok(e) => e,
        Err(e) => {
            jobs.push(Job::Done(Raw::status(target, unreadable(&e))));
            return false;
        }
    };
    let mut entries: Vec<(std::ffi::OsString, io::Result<fs::FileType>)> = entries
        .into_iter()
        .map(|e| (e.file_name(), e.file_type()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, ft) in entries {
        let p = dir.join(&name);
        let target = p.display().to_string();
        match ft {
            Ok(ft) if ft.is_dir() => {
                if walk(&p, jobs, budget) {
                    return true;
                }
                continue;
            }
            _ if *budget == 0 => return true,
            _ => *budget -= 1,
        }
        jobs.push(match ft {
            Err(e) => Job::Done(Raw::status(target, unreadable(&e))),
            Ok(ft) if ft.is_symlink() => {
                Job::Done(Raw::status(target, skipped("symlink not followed")))
            }
            Ok(ft) if ft.is_file() => Job::File {
                target,
                input: p,
                explicit: false,
            },
            Ok(_) => Job::Done(Raw::status(target, skipped("not a regular file"))),
        });
    }
    false
}
