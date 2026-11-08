//! The library facade: one [`RiskGrep`] built from configuration and reused
//! for every scan. It ties together classification, the evidence cache, the
//! lazily loaded rules bundle, suppression, and scoring.
//!
//! The bundle is compiled or loaded only when some target misses the cache;
//! scoring cached evidence reads the rule-metadata sidecar instead.

use crate::bundle::{self, Sidecar};
use crate::cache::{Cache, ContainerRow, Entry, StatKey};
use crate::classify::{self, Content, FileClass, Known, Source, Tail};
use crate::config::{self, Config};
use crate::container::{self, Cause, Extracted, Extractor, Unread};
use crate::engine::{Engine, ScanError};
use crate::meta::RuleMeta;
use crate::model::{
    Category, ContainerReport, Evidence, MemberReport, Report, TargetReport, TargetStatus,
};
use crate::ruleset::{builtin_rulesets, Ruleset};
use crate::score::{score_container, score_target};
use crate::suppress::{self, Baseline};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::RangeInclusive;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

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
    /// Set when the rule-metadata sidecar was found unusable, so the next
    /// bundle load rewrites it.
    sidecar_bad: bool,
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
    /// The content was scanned as text (see [`TargetReport::text`]).
    text: bool,
    /// Set for a container whose members were read.
    container: Option<ContainerInfo>,
    /// See [`TargetReport::read_failed`].
    read_failed: bool,
}

/// What a container's walk and scan found besides evidence.
struct ContainerInfo {
    /// `scanned` counts members read whole and scanned.
    counts: ContainerRow,
    read_in_part: u64,
    not_read: u64,
    opened: u64,
    /// Members not read whole (empty for a cached container).
    unread: Vec<Unread>,
}

impl ContainerInfo {
    /// Members were counted, none was scanned, and every one is a skipped
    /// file or a nested container of them. Only meaningful for a container
    /// with nothing unread.
    fn all_skipped(&self) -> bool {
        self.counts.scanned == 0 && self.read_in_part == 0 && self.counts.skipped > 0
    }

    fn report(self, listed: Vec<MemberReport>) -> ContainerReport {
        ContainerReport {
            format: self.counts.format,
            members: self.counts.members,
            scanned: self.counts.scanned,
            read_in_part: self.read_in_part,
            skipped: self.counts.skipped,
            not_read: self.not_read,
            opened: self.opened,
            listed,
        }
    }
}

impl Raw {
    fn status(target: String, status: TargetStatus) -> Raw {
        Raw {
            rel: target.clone(),
            target,
            status,
            evidence: Vec::new(),
            content: false,
            text: false,
            container: None,
            read_failed: false,
        }
    }

    /// A container read whole with nothing in it scanned: it is what a lone
    /// file of its members' kind would be, so `on_skipped` applies.
    fn all_skipped(target: String, info: ContainerInfo) -> Raw {
        let mut raw = Raw::status(
            target,
            TargetStatus::Skipped {
                reason: container::ALL_SKIPPED.to_string(),
            },
        );
        raw.container = Some(info);
        raw
    }

    /// A target answered from the cache.
    fn cached(target: String, rel: String, entry: Entry, text: bool) -> Raw {
        // Only a container read whole is cached, and the row does not count
        // the nested containers: they are the members left over.
        let container = entry.container.map(|counts| ContainerInfo {
            read_in_part: 0,
            not_read: 0,
            opened: counts
                .members
                .saturating_sub(counts.scanned + counts.skipped),
            counts,
            unread: Vec::new(),
        });
        let container = match container {
            Some(info) if info.all_skipped() => return Raw::all_skipped(target, info),
            other => other,
        };
        Raw {
            target,
            status: TargetStatus::Scanned,
            evidence: entry.evidence,
            rel,
            content: true,
            text: text && container.is_none(),
            container,
            read_failed: false,
        }
    }

    fn scanned(
        target: String,
        rel: String,
        status: TargetStatus,
        evidence: Vec<Evidence>,
        text: bool,
    ) -> Raw {
        Raw {
            target,
            status,
            evidence,
            rel,
            content: true,
            text,
            container: None,
            read_failed: false,
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
    /// The content is text (see [`TargetReport::text`]).
    text: bool,
    /// Evidence-cache key; `None` when the result must not be cached.
    hash: Option<[u8; 32]>,
    /// Stat entry to record, with the time the file was examined (taken
    /// before the read, so the racy-edit window measures from it); `None`
    /// when the file changed while being read.
    stat: Option<(StatKey, SystemTime)>,
    /// Set for a container: its members, scanned in place of `content`.
    container: Option<Box<Walked>>,
}

/// A container read and classified, waiting for its members' scans.
struct Walked {
    extracted: Extracted,
    /// Time the walk took: the members' scans get the rest of the target's
    /// time budget. Loading the rules between the walk and the scans is not
    /// counted.
    spent: Duration,
}

enum Step {
    Done(Raw),
    Scan(Box<Pending>),
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

/// Classification of a container member, as for a file.
pub(crate) fn classify_member(name: &str, head: &[u8], size: u64) -> FileClass {
    classify(name, head, size)
}

/// The largest container file whose result is cached: such a file is read
/// into memory whole, hashed, and walked from that copy.
const CONTAINER_HASH_MAX: u64 = 64 << 20;

/// The extractor that reads `class`, when it is a container with one.
fn container_of(class: &FileClass) -> Option<&'static dyn Extractor> {
    match class {
        FileClass::Container(kind) => container::extractor(*kind),
        _ => None,
    }
}

/// The evidence-cache key of a target: the bundle key, the extractor and
/// its version for a container, and the path the rules see.
fn evidence_key(bundle: &str, ext: Option<&dyn Extractor>, path_ext: &str) -> String {
    match ext {
        Some(x) => format!("{bundle}:{}@{}:{path_ext}", x.id(), x.version()),
        None => format!("{bundle}:{path_ext}"),
    }
}

/// Classification with the safetensors size check applied.
fn classify(name: &str, head: &[u8], size: u64) -> FileClass {
    match classify::classify_sized(name, head, size) {
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
        FileClass::Container(kind) if container::extractor(*kind).is_none() => {
            Some(unscanned(&container::not_scanned_reason(*kind)))
        }
        FileClass::Container(_) => None,
        FileClass::Image(kind) => Some(skipped(&format!("{kind} image not scanned in v1"))),
        FileClass::UnknownBinary => Some(skipped("binary file of unknown format")),
        FileClass::Text | FileClass::EncodedText(_) | FileClass::KnownBinary(_) => None,
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

/// Move evidence found in the tail sample of a partly read text file to its
/// offsets in the file. Its line numbers are unknown (0): the lines of the
/// unread middle were never counted. A range across the joint keeps its
/// start and also loses its lines.
fn place_tail(evidence: &mut [Evidence], tail: Tail) {
    let to_file = |o: u64| o - tail.at + tail.file_offset;
    for l in evidence.iter_mut().flat_map(|e| e.locations.iter_mut()) {
        if l.end < tail.at {
            continue;
        }
        if l.start >= tail.at {
            l.start = to_file(l.start);
        }
        l.end = to_file(l.end.max(tail.at));
        l.line_start = 0;
        l.line_end = 0;
    }
}

fn new_scanner<'r>(engine: &'r Engine, cfg: &Config) -> yara_x::Scanner<'r> {
    let mut s = yara_x::Scanner::new(engine.rules());
    s.set_timeout(cfg.limits.time_budget);
    s
}

/// Resolve the enabled rulesets: built-ins plus `extra_ruleset_dirs`, narrowed
/// to `cfg.rulesets` when it names any, then to rulesets scoring an enabled
/// category. [`config::load`] makes every directory absolute (relative to
/// the config file that named it); `base` anchors a relative directory only
/// in a configuration built by hand.
pub fn resolve_rulesets(cfg: &Config, base: Option<&Path>) -> Result<Vec<Ruleset>, RiskGrepError> {
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
    /// bundle is loaded on the first cache miss. `repo_root` anchors the
    /// baseline and suppression paths (and, in a hand-built configuration,
    /// relative `extra_ruleset_dirs`; see [`resolve_rulesets`]).
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
            sidecar_bad: false,
            baseline,
            rel_base: base,
            cwd,
        })
    }

    /// Close the evidence cache now: its SQLite connection closes, which
    /// checkpoints the write-ahead log into the database. Later scans on this
    /// instance still work, uncached (the compiled-rules cache is unaffected).
    /// For callers that end the process without running destructors.
    pub fn close_cache(&mut self) {
        self.cache = None;
    }

    /// True once the compiled rules bundle has been loaded.
    pub fn bundle_loaded(&self) -> bool {
        matches!(self.engine, EngineState::Loaded(_))
    }

    /// Scan files and directories. Explicit paths follow symlinks; directory
    /// walks do not, ignore `.gitignore`, and stop at `limits.walk_files`
    /// (the directory is then reported unscanned).
    pub fn scan_paths(&mut self, paths: &[PathBuf]) -> Report {
        let jobs = self.expand(paths);
        let mut raws = Vec::with_capacity(jobs.len());
        let mut jobs = jobs.into_iter();
        let mut first = None;
        for job in jobs.by_ref() {
            match self.prepare(job) {
                Step::Done(r) => raws.push(r),
                Step::Scan(p) => {
                    first = Some(*p);
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
                    Step::Scan(p) => self.finish(engine.zip(scanner.as_mut()), *p),
                };
                raws.push(raw);
            }
        }
        let targets = self.finalize(raws);
        self.report(targets)
    }

    /// Scan raw text (stdin). Never cached; text limits apply. UTF-16 and
    /// UTF-32 text is recognised from the first bytes as for a file and
    /// transcoded, with evidence offsets in the input's bytes. Any other
    /// input is scanned as text, including bytes a file of that kind would
    /// skip as binary of unknown format. Input that starts like an archive,
    /// a database, or a compressed stream is scanned as bytes too, since its
    /// members are not read, and is reported `unscanned` with the format's
    /// name, so that a gate which treats `unscanned` as an error does not
    /// take the word `scanned` to mean that the members were read.
    pub fn scan_bytes(&mut self, name: &str, bytes: &[u8]) -> Report {
        let head = &bytes[..bytes.len().min(self.cfg.limits.sniff)];
        let (class, container) = match classify(name, head, bytes.len() as u64) {
            c @ FileClass::EncodedText(_) => (c, None),
            FileClass::Container(kind) => (FileClass::Text, Some(kind)),
            _ => (FileClass::Text, None),
        };
        let mut raw = match classify::slice_for_scan(bytes, &class, &self.cfg.limits) {
            Err(e) => Raw::status(name.to_string(), unreadable(&e)),
            Ok(content) => self.scan_now(Pending {
                target: name.to_string(),
                rel: name.to_string(),
                path_ext: "<stdin>".into(),
                ekey: String::new(),
                content,
                text: class.is_text(),
                hash: None,
                stat: None,
                container: None,
            }),
        };
        if let (Some(kind), TargetStatus::Scanned | TargetStatus::Partial { .. }) =
            (container, &raw.status)
        {
            raw.status = unscanned(&format!("{} not scanned on standard input", kind.name()));
            raw.text = false;
        }
        let targets = self.finalize(vec![raw]);
        self.report(targets)
    }

    /// Score file names without their content: each name is scanned as an
    /// empty text file of that name, so only rules that need no content
    /// (path rules) can match. One scan engine serves every name; never
    /// cached.
    pub fn scan_names(&mut self, names: &[String]) -> Report {
        self.load_engine();
        let engine = match &self.engine {
            EngineState::Loaded(e) => Some(&**e),
            _ => None,
        };
        let mut scanner = engine.map(|e| new_scanner(e, &self.cfg));
        let mut raws = Vec::with_capacity(names.len());
        for name in names {
            let raw = match classify::slice_for_scan(b"", &FileClass::Text, &self.cfg.limits) {
                Err(e) => Raw::status(name.clone(), unreadable(&e)),
                Ok(content) => self.finish(
                    engine.zip(scanner.as_mut()),
                    Pending {
                        target: name.clone(),
                        rel: name.clone(),
                        path_ext: name.clone(),
                        ekey: String::new(),
                        content,
                        text: true,
                        hash: None,
                        stat: None,
                        container: None,
                    },
                ),
            };
            raws.push(raw);
        }
        let targets = self.finalize(raws);
        self.report(targets)
    }

    /// Scan one git blob. `name` is its repository-relative path; results are
    /// cached by `blob_id`. With `only_lines`, evidence located outside those
    /// lines is dropped before scoring, unless the blob was only partly read
    /// (line numbers of its tail are unknown) or is not text (a key store or
    /// tensor file, whose offsets are not lines of a diff): then all evidence
    /// is kept.
    pub fn scan_blob(
        &mut self,
        name: &str,
        blob_id: &[u8],
        bytes: &[u8],
        only_lines: Option<&[RangeInclusive<u32>]>,
    ) -> TargetReport {
        let mut raw = self.prepare_blob(name, blob_id, bytes);
        if let Some(only) = only_lines {
            if raw.text && !matches!(raw.status, TargetStatus::Partial { .. }) {
                keep_lines(&mut raw.evidence, only);
            }
        }
        self.finalize(vec![raw]).remove(0)
    }

    fn prepare_blob(&mut self, name: &str, blob_id: &[u8], bytes: &[u8]) -> Raw {
        let size = bytes.len() as u64;
        let head = &bytes[..bytes.len().min(self.cfg.limits.sniff)];
        let class = classify::settle_npz(classify(name, head, size), bytes, size, &self.cfg.limits);
        if let Some(s) = not_scanned(&class) {
            return Raw::status(name.to_string(), s);
        }
        // Git numbers a blob's lines at 0x0A bytes, which a UTF-16 or
        // UTF-32 code unit other than LF can hold, so only UTF-8 text has
        // lines a diff's line ranges can be matched against.
        let blob_text = class == FileClass::Text;
        let ext = container_of(&class);
        let ekey = evidence_key(&self.key, ext, name);
        let mut h = blake3::Hasher::new();
        h.update(b"riskgrep-git-blob\0");
        h.update(blob_id);
        let blob_key = *h.finalize().as_bytes();
        if let Some(entry) = self.cache.as_ref().and_then(|c| c.entry(blob_key, &ekey)) {
            return Raw::cached(name.into(), name.into(), entry, blob_text);
        }
        if let Some(ext) = ext {
            let start = Instant::now();
            let x = container::extract_named(
                ext,
                name,
                &bytes,
                size,
                &self.cfg.limits,
                start + self.cfg.limits.time_budget,
            );
            if let s @ TargetStatus::Unscanned { .. } = x.status() {
                return Raw::status(name.to_string(), s);
            }
            return self.scan_now(Pending {
                target: name.to_string(),
                rel: name.to_string(),
                path_ext: name.to_string(),
                ekey,
                hash: (x.status() == TargetStatus::Scanned).then_some(blob_key),
                content: Content::default(),
                text: false,
                stat: None,
                container: Some(Box::new(Walked {
                    extracted: x,
                    spent: start.elapsed(),
                })),
            });
        }
        match classify::slice_for_scan(bytes, &class, &self.cfg.limits) {
            Err(e) => Raw::status(name.to_string(), unreadable(&e)),
            Ok(Content {
                unscanned: Some(reason),
                ..
            }) => Raw::status(name.to_string(), unscanned(&reason)),
            Ok(content) => self.scan_now(Pending {
                target: name.to_string(),
                rel: name.to_string(),
                path_ext: name.to_string(),
                ekey,
                hash: content.partial.is_none().then_some(blob_key),
                content,
                text: blob_text,
                stat: None,
                container: None,
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
                        // An error, not a partial read: files were left out.
                        jobs.push(Job::Done(Raw::status(
                            target,
                            unscanned(&format!(
                                "directory walk stopped at the limit of {} files \
                                 (limits.walk_files)",
                                self.cfg.limits.walk_files
                            )),
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
        let class =
            classify::settle_npz(classify(&name, &head, size), &file, size, &self.cfg.limits);
        if let Some(s) = not_scanned(&class) {
            return done(s);
        }

        let path_ext = relative_to(self.cwd.as_deref(), &real);
        let ext = container_of(&class);
        let ekey = evidence_key(&self.key, ext, &path_ext);
        let rel = relative_to(self.rel_base.as_deref(), &real);
        let beside = ext.map_or_else(Vec::new, |x| x.beside(&real));
        let cache = self.cache.as_ref().filter(|_| beside.is_empty());
        let text = class.is_text();
        let hit = |entry: Entry| {
            Ok(Step::Done(Raw::cached(
                target.to_string(),
                rel.clone(),
                entry,
                text,
            )))
        };
        if let Some(c) = cache {
            if let Some(entry) = c
                .content_hash_for(&key, now)
                .and_then(|h| c.entry(h, &ekey))
            {
                return hit(entry);
            }
        }
        if let Some(ext) = ext {
            let start = Instant::now();
            // A container small enough to cache is read once into memory,
            // hashed, and walked from that copy, so the cache key is the
            // hash of exactly the bytes whose members were scanned.
            let whole = if size <= CONTAINER_HASH_MAX {
                Some(file.range(0, size)?)
            } else {
                None
            };
            let hash = whole.as_deref().map(|b| *blake3::hash(b).as_bytes());
            if let (Some(c), Some(h)) = (cache, hash) {
                if let Some(entry) = c.entry(h, &ekey) {
                    // As for other files: the stat row only when the file
                    // did not change while it was read.
                    let stable = fs::metadata(&real)
                        .map(|m| StatKey::from_metadata(&real, &m) == key)
                        .unwrap_or(false);
                    if stable {
                        c.put_stat(&key, h, now);
                    }
                    return hit(entry);
                }
            }
            let deadline = start + self.cfg.limits.time_budget;
            let mut x = match &whole {
                Some(b) => container::extract_named(
                    ext,
                    &name,
                    &b.as_slice(),
                    size,
                    &self.cfg.limits,
                    deadline,
                ),
                None => {
                    container::extract_named(ext, &name, &file, size, &self.cfg.limits, deadline)
                }
            };
            drop(whole);
            for (member, what) in beside {
                x.beside_not_read(member, what);
            }
            if let Some(hook) = AFTER_READ.get() {
                hook(&real);
            }
            let status = x.status();
            if let TargetStatus::Unscanned { reason } = status {
                return done(unscanned(&reason));
            }
            // As for other files, the content-addressed row is cached even
            // if the file changed; the stat row only if it did not.
            let stable = fs::metadata(&real)
                .map(|m| StatKey::from_metadata(&real, &m) == key)
                .unwrap_or(false);
            let hash = hash.filter(|_| status == TargetStatus::Scanned);
            return Ok(Step::Scan(Box::new(Pending {
                target: target.to_string(),
                rel,
                path_ext,
                ekey,
                content: Content::default(),
                text: false,
                hash,
                stat: stable.then_some((key, now)),
                container: Some(Box::new(Walked {
                    extracted: x,
                    spent: start.elapsed(),
                })),
            })));
        }

        let content = classify::read_for_scan(&file, size, &class, &self.cfg.limits)?;
        if let Some(hook) = AFTER_READ.get() {
            hook(&real);
        }
        if let Some(reason) = &content.unscanned {
            return done(unscanned(reason));
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
            .then(|| *blake3::hash(content.cache_bytes()).as_bytes());
        if let (Some(c), Some(h)) = (cache, hash) {
            if let Some(entry) = c.entry(h, &ekey) {
                if stable {
                    c.put_stat(&key, h, now);
                }
                return hit(entry);
            }
        }
        Ok(Step::Scan(Box::new(Pending {
            target: target.to_string(),
            rel,
            path_ext,
            ekey,
            content,
            text,
            hash,
            stat: stable.then_some((key, now)),
            container: None,
        })))
    }

    /// Run the engine over pending content and record the result in the
    /// cache. `None` for the engine means the rules could not be loaded.
    fn finish(&self, engine: Option<(&Engine, &mut yara_x::Scanner<'_>)>, p: Pending) -> Raw {
        let Some((engine, scanner)) = engine else {
            return Raw::status(p.target, unscanned("rule load failure"));
        };
        if p.container.is_some() {
            return self.finish_container(engine, scanner, p);
        }
        let scan = match engine.scan_content_checked(scanner, &p.path_ext, &p.content.bytes) {
            Ok(scan) => scan,
            Err(ScanError::Timeout) => return Raw::status(p.target, unscanned("timeout")),
            Err(ScanError::Yara(_)) => return Raw::status(p.target, unscanned("scan error")),
        };
        let (mut ev, engine_not_read) = (scan.evidence, scan.not_read);
        if let Some(d) = &p.content.decoded {
            d.place(&mut ev);
        } else if let Some(tail) = p.content.tail {
            place_tail(&mut ev, tail);
        }
        // Evidence from content a processor could not fully inspect is not
        // cached: a hit means a full scan, as with partial reads.
        if let (Some(c), Some(h), None) = (self.cache.as_ref(), p.hash, &engine_not_read) {
            c.put_evidence(h, &p.ekey, &ev);
            if let Some((k, examined)) = &p.stat {
                c.put_stat(k, h, *examined);
            }
        }
        let read_failed = p.content.read_failed || engine_not_read.is_some();
        let status = match p.content.partial.or(engine_not_read) {
            Some(not_read) => TargetStatus::Partial { not_read },
            None => TargetStatus::Scanned,
        };
        let mut raw = Raw::scanned(p.target, p.rel, status, ev, p.text);
        raw.read_failed = read_failed;
        raw
    }

    /// Scan each member of a walked container under the time left before
    /// its deadline, attribute the evidence to its member, and record the
    /// result in the cache when the container was read whole.
    fn finish_container(
        &self,
        engine: &Engine,
        scanner: &mut yara_x::Scanner<'_>,
        mut p: Pending,
    ) -> Raw {
        let Walked {
            extracted: x,
            spent,
        } = *p.container.take().expect("container");
        let deadline = Instant::now() + self.cfg.limits.time_budget.saturating_sub(spent);
        let mut unread = x.unread;
        let mut ev_all: Vec<Evidence> = Vec::new();
        let mut scanned: Vec<u64> = Vec::new();
        for m in x.members {
            let left = deadline.saturating_duration_since(Instant::now());
            let cause = if left.is_zero() {
                Some(Cause::Limit("limits.time_budget_ms".into()))
            } else {
                scanner.set_timeout(left);
                let path = format!("{}!/{}", p.path_ext, m.path);
                match engine.scan_content_checked(scanner, &path, &m.content.bytes) {
                    Ok(scan) => {
                        let mut ev = scan.evidence;
                        if let Some(note) = scan.not_read {
                            unread.push(Unread {
                                seq: m.seq,
                                last: m.seq,
                                path: Some(m.path.clone()),
                                cause: Cause::Scan(note),
                                partly: true,
                            });
                        }
                        if let Some(d) = &m.content.decoded {
                            d.place(&mut ev);
                        } else if let Some(tail) = m.content.tail {
                            place_tail(&mut ev, tail);
                        }
                        for e in &mut ev {
                            e.member = Some(m.path.clone());
                        }
                        ev_all.extend(ev);
                        scanned.push(m.seq);
                        None
                    }
                    Err(ScanError::Timeout) => Some(Cause::Scan("timeout".into())),
                    Err(ScanError::Yara(_)) => Some(Cause::Scan("scan error".into())),
                }
            };
            if let Some(cause) = cause {
                unread.push(Unread {
                    seq: m.seq,
                    last: m.seq,
                    path: Some(m.path),
                    cause,
                    partly: false,
                });
            }
        }
        scanner.set_timeout(self.cfg.limits.time_budget);
        let any = !scanned.is_empty();
        let status = container::status(
            any,
            &unread,
            x.uncovered,
            &x.directories,
            x.error.as_deref(),
        );
        if let TargetStatus::Unscanned { reason } = status {
            return Raw::status(p.target, TargetStatus::Unscanned { reason });
        }
        let (not_read, in_part) = container::unread_counts(&unread);
        let counts = ContainerRow {
            format: x.format.to_string(),
            members: x.total,
            scanned: scanned.iter().filter(|s| !in_part.contains(s)).count() as u64,
            skipped: x.skipped,
        };
        if status == TargetStatus::Scanned {
            if let (Some(c), Some(h)) = (self.cache.as_ref(), p.hash) {
                c.put_entry(h, &p.ekey, &ev_all, Some(&counts));
                if let Some((k, examined)) = &p.stat {
                    c.put_stat(k, h, *examined);
                }
            }
        }
        let info = ContainerInfo {
            counts,
            read_in_part: in_part.len() as u64,
            not_read,
            opened: x.opened,
            unread,
        };
        if status == TargetStatus::Scanned && info.all_skipped() {
            return Raw::all_skipped(p.target, info);
        }
        let mut raw = Raw::scanned(p.target, p.rel, status, ev_all, false);
        raw.container = Some(info);
        raw
    }

    fn load_engine(&mut self) {
        if !matches!(self.engine, EngineState::NotLoaded) {
            return;
        }
        let refs: Vec<&Ruleset> = self.rulesets.iter().collect();
        let sidecar = if self.sidecar_bad {
            Sidecar::Rewrite
        } else {
            Sidecar::IfMissing
        };
        let loaded = match &self.cache_dir {
            Some(d) => bundle::load_or_compile_keyed(&refs, d, &self.key, sidecar),
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
        self.sidecar_bad = self.cache_dir.is_some();
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
            text: raw.text,
            container: None,
            read_failed: raw.read_failed,
        };
        let info = raw.container;
        if !raw.content {
            // A skipped container keeps its counts; it has nothing to list.
            t.container = info.map(|i| i.report(Vec::new()));
            return t;
        }
        let sm = match &self.meta {
            MetaState::Loaded(sm) => sm,
            _ => {
                t.status = unscanned("rule load failure");
                t.evidence.clear();
                t.text = false;
                return t;
            }
        };
        t.evidence.retain(|e| self.categories.contains(&e.category));
        for e in &mut t.evidence {
            let m = sm.keys.get(&e.rule).and_then(|k| sm.meta.get(k));
            if let Some(m) = m {
                e.weight = m.weight;
            }
            e.line_complete = m.is_some_and(|m| m.line_complete);
        }
        let rel = raw.rel;
        suppress::apply(
            std::slice::from_mut(&mut t),
            &self.cfg.ignore,
            self.baseline.as_ref(),
            |_| rel.clone(),
        );
        let zero = |mut s: BTreeMap<Category, f64>| {
            for c in &self.categories {
                s.entry(c.clone()).or_insert(0.0);
            }
            s
        };
        match info {
            Some(info) => {
                t.scores = zero(score_container(&t.evidence, &sm.meta));
                t.container = Some(self.container_report(&t.evidence, info, &sm.meta, zero));
            }
            None => t.scores = zero(score_target(&t.evidence, &sm.meta)),
        }
        t
    }

    /// The member table of a container target: members with evidence
    /// (their own scores) in path order, then members not read whole.
    fn container_report(
        &self,
        evidence: &[Evidence],
        info: ContainerInfo,
        meta: &HashMap<String, RuleMeta>,
        zero: impl Fn(BTreeMap<Category, f64>) -> BTreeMap<Category, f64>,
    ) -> ContainerReport {
        let mut by_member: BTreeMap<&str, Vec<Evidence>> = BTreeMap::new();
        for e in evidence {
            if let Some(m) = &e.member {
                by_member.entry(m).or_default().push(e.clone());
            }
        }
        let unread_status = |u: &Unread| {
            if u.partly {
                TargetStatus::Partial {
                    not_read: u.cause.truncated_phrase(),
                }
            } else {
                TargetStatus::Unscanned {
                    reason: u.cause.phrase(),
                }
            }
        };
        let mut listed: Vec<MemberReport> = Vec::new();
        for (path, ev) in &by_member {
            let status = info
                .unread
                .iter()
                .find(|u| u.path.as_deref() == Some(*path))
                .map_or(TargetStatus::Scanned, unread_status);
            listed.push(MemberReport {
                path: path.to_string(),
                status,
                scores: zero(score_target(ev, meta)),
            });
        }
        for u in &info.unread {
            let Some(path) = &u.path else { continue };
            if listed.iter().any(|l| &l.path == path) {
                continue;
            }
            listed.push(MemberReport {
                path: path.clone(),
                status: unread_status(u),
                scores: zero(BTreeMap::new()),
            });
        }
        listed.truncate(container::LISTED_MAX);
        info.report(listed)
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Versioned(u32);

    impl Extractor for Versioned {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn version(&self) -> u32 {
            self.0
        }

        fn extract(
            &self,
            _: &dyn Source,
            _: u64,
            _: &mut dyn container::Walk,
        ) -> Result<(), container::ContainerError> {
            Ok(())
        }
    }

    /// Evidence cached from an older extractor's output must not be used.
    #[test]
    fn evidence_key_changes_with_the_extractor_version() {
        let key = |v| evidence_key("bundle", Some(&Versioned(v)), "a.zip");
        assert_ne!(key(1), key(2));
        assert_ne!(key(1), evidence_key("bundle", None, "a.zip"));
    }
}
