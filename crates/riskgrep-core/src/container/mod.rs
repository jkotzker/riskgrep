//! Container files: archives whose members are read and scanned like files.
//!
//! A format is one [`Extractor`]: it walks its container's structure and
//! hands each member's decompressed stream to a [`Walk`]. The framework
//! ([`extract`]) owns everything else: the shared budgets (members, bytes,
//! nesting depth, compression ratio, one deadline), member names, member
//! classification, nesting, and the status. Members are held in memory only,
//! for the scan that follows; nothing extracted is written anywhere.
//!
//! A member is named by its path inside the container, joined to the
//! container with `!/` (`backup.zip!/config/.env`, nested
//! `outer.zip!/inner.zip!/x`). Reasons for `partial` and `unscanned` never
//! name a member, only its position in the walk (names may be personal
//! data); names appear only where a file path would.

use crate::classify::{self, Content, FileClass, Limits, Source};
use crate::model::TargetStatus;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::io::Read;
use std::time::Instant;

pub mod zip;

/// A container format, as classification recognises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    Zip,
    Tar,
    Gzip,
    SevenZ,
    Pdf,
    Sqlite,
}

impl ContainerKind {
    /// The name used in reasons (`7z not scanned`).
    pub fn name(self) -> &'static str {
        match self {
            ContainerKind::Zip => "zip",
            ContainerKind::Tar => "tar",
            ContainerKind::Gzip => "gzip",
            ContainerKind::SevenZ => "7z",
            ContainerKind::Pdf => "pdf",
            ContainerKind::Sqlite => "sqlite",
        }
    }
}

/// One format's reader. Implementations walk the container's structure and
/// hand each member to `walk`; they never scan, classify, or score.
pub trait Extractor: Sync {
    /// Stable id, reported as the container's `format` and part of the
    /// evidence-cache key, e.g. `"zip"`.
    fn id(&self) -> &'static str;
    /// Bumped whenever the extractor's output for some input changes, so
    /// cached evidence of the old output is not used.
    fn version(&self) -> u32;
    /// Walk the container in `src` (`size` bytes). An error means its
    /// structure could not be read; problems with single members are
    /// reported through [`Walk::not_read`].
    fn extract(
        &self,
        src: &dyn Source,
        size: u64,
        walk: &mut dyn Walk,
    ) -> Result<(), ContainerError>;
}

/// The reason a container of `kind` that has no extractor is not scanned.
pub fn not_scanned_reason(kind: ContainerKind) -> String {
    format!("{} not scanned in v1", kind.name())
}

/// The extractor for `kind`, if that format is read. The only list a new
/// format is added to.
pub fn extractor(kind: ContainerKind) -> Option<&'static dyn Extractor> {
    match kind {
        ContainerKind::Zip => Some(&zip::ZIP),
        ContainerKind::Tar
        | ContainerKind::Gzip
        | ContainerKind::SevenZ
        | ContainerKind::Pdf
        | ContainerKind::Sqlite => None,
    }
}

/// The container's structure could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerError(pub String);

/// What an extractor knows about a member before reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberMeta {
    /// Path inside this container, as stored; the framework escapes it.
    pub name: String,
    /// Uncompressed size as the container declares it (it may lie).
    pub declared_size: Option<u64>,
    /// Compressed size as the container declares it, for the ratio limit.
    pub compressed_size: Option<u64>,
}

/// Why an extractor could not hand over a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotRead {
    Encrypted,
    /// Stored with a method the extractor cannot decode.
    Unsupported,
    /// Its data or header could not be read.
    Corrupt,
}

/// Whether the extractor should go on offering members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

/// Where an extractor sends members. The framework implements it.
pub trait Walk {
    /// A member and its decompressed bytes. After `Flow::Stop` the
    /// extractor offers no more members and calls [`Walk::rest`].
    fn member(&mut self, meta: MemberMeta, data: &mut dyn Read) -> Flow;
    /// A member that could not be read.
    fn not_read(&mut self, meta: MemberMeta, why: NotRead) -> Flow;
    /// A comment, scanned as text with the same limits as a member: the
    /// comment of the entry named `owner` as stored, under that name and
    /// [`ENTRY_COMMENT`], or with no owner the container's own, under
    /// [`COMMENT_MEMBER`].
    fn comment(&mut self, owner: Option<&str>, data: &mut dyn Read) -> Flow;
    /// The number of members left unoffered after a `Flow::Stop`.
    fn rest(&mut self, n: u64);
    /// The deadline has passed: work done before offering members (such as
    /// reading headers) should stop.
    fn expired(&self) -> bool;
    /// Bytes of the container that belong to no member offered (data
    /// before the first member or between members, a comment): they are
    /// not read, so the container is never reported whole.
    fn unaccounted(&mut self, bytes: u64);
}

/// Bytes a member may always produce whatever its compression ratio, so a
/// small, very repetitive file is not mistaken for a decompression bomb.
pub const RATIO_FLOOR: u64 = 1 << 20;

/// The member name an archive's comment is scanned under. It ends in a
/// single `!`, which [`escape_name`] never produces (a stored name ending
/// in `!` gains one more), so no stored member can take it.
pub const COMMENT_MEMBER: &str = "comment!";

/// Added to an entry's escaped name to name its comment
/// (`config/app.ini!comment!`). The result ends in a single `!`, so no stored
/// member can take it, as for [`COMMENT_MEMBER`].
pub const ENTRY_COMMENT: &str = "!comment!";

/// Longest member path reported, in bytes; longer names are cut and marked.
pub const NAME_MAX: usize = 1024;

/// Members listed in a report, at most.
pub const LISTED_MAX: usize = 1000;

/// Why a member was not read, or not read whole.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Cause {
    /// Over a limit, by its configuration key (`limits.container_members`).
    Limit(String),
    Encrypted,
    Unsupported,
    Corrupt,
    /// A nested container that was not opened, with the reason it would
    /// get as a file (`7z not scanned`).
    Nested(String),
    /// The member was read but its scan did not finish.
    Scan(String),
}

impl Cause {
    /// How the cause reads in a reason: `encrypted`,
    /// `not read (limits.container_members)`.
    pub fn phrase(&self) -> String {
        match self {
            Cause::Limit(key) => format!("not read ({key})"),
            Cause::Encrypted => "encrypted".into(),
            Cause::Unsupported => "stored with an unsupported method".into(),
            Cause::Corrupt => "unreadable".into(),
            Cause::Nested(reason) => format!("not opened ({reason})"),
            Cause::Scan(reason) => format!("not scanned ({reason})"),
        }
    }

    /// The phrase for a member read and scanned only in part.
    pub fn truncated_phrase(&self) -> String {
        match self {
            Cause::Limit(key) => format!("read only in part ({key})"),
            other => other.phrase(),
        }
    }
}

/// A member read into memory and classified, ready for the scan engine.
#[derive(Debug)]
pub struct Member {
    /// Position in the walk, 1-based, nested members included.
    pub seq: u64,
    /// Escaped path relative to the top-level container
    /// (`config/.env`, `inner.zip!/x`).
    pub path: String,
    pub content: Content,
    /// The member is text (see [`crate::model::TargetReport::text`]).
    pub text: bool,
    /// Set when only part of the member was read.
    pub truncated: Option<Cause>,
}

/// A member that was not read whole, or a run of members never offered
/// (past a limit): positions `seq..=last`, with `path` unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    pub seq: u64,
    pub last: u64,
    pub path: Option<String>,
    pub cause: Cause,
    /// Some of it was read and scanned.
    pub partly: bool,
}

/// The result of walking a container, before any scan.
#[derive(Debug)]
pub struct Extracted {
    pub format: &'static str,
    pub members: Vec<Member>,
    /// Members examined or counted, nested members included.
    pub total: u64,
    /// Members classified as formats that are not scanned (images, binary
    /// files of unknown format); they do not make the container partial.
    pub skipped: u64,
    pub unread: Vec<Unread>,
    /// Bytes of the container, nested ones included, outside every member
    /// (see [`Walk::unaccounted`]).
    pub uncovered: u64,
    /// Set when the container's own structure could not be read.
    pub error: Option<String>,
}

impl Extracted {
    /// Status before scanning (see [`status`]).
    pub fn status(&self) -> TargetStatus {
        status(
            !self.members.is_empty(),
            &self.unread,
            self.uncovered,
            self.error.as_deref(),
        )
    }
}

/// A container's status: `unscanned` when no member in scope was read
/// (`read_any` false) but something was not, or its structure could not be
/// read at all; `partial` when some member was not read whole or the
/// structure failed part way; else `scanned`.
pub fn status(
    read_any: bool,
    unread: &[Unread],
    uncovered: u64,
    error: Option<&str>,
) -> TargetStatus {
    if !read_any {
        if let (Some(e), true) = (error, unread.is_empty()) {
            return TargetStatus::Unscanned {
                reason: e.to_string(),
            };
        }
        if !unread.is_empty() || uncovered > 0 {
            return TargetStatus::Unscanned {
                reason: describe(unread, uncovered, error),
            };
        }
    }
    if unread.is_empty() && uncovered == 0 && error.is_none() {
        TargetStatus::Scanned
    } else {
        TargetStatus::Partial {
            not_read: describe(unread, uncovered, error),
        }
    }
}

/// Sorted, merged position ranges.
fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (a, b) in ranges {
        match out.last_mut() {
            Some(r) if a <= r.1.saturating_add(1) => r.1 = r.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// Members in `unread`, each counted once.
pub fn unread_count(unread: &[Unread]) -> u64 {
    merge(unread.iter().map(|u| (u.seq, u.last)).collect())
        .iter()
        .map(|(a, b)| b - a + 1)
        .sum()
}

/// `members 3, 7..9 encrypted; members 1001..4096 not read
/// (limits.container_members)`: causes in order of first appearance, each
/// with its member positions as ranges. Never a member name.
pub fn describe(unread: &[Unread], uncovered: u64, error: Option<&str>) -> String {
    const RANGES: usize = 10;
    let mut causes: Vec<(String, Vec<(u64, u64)>)> = Vec::new();
    for u in unread {
        let phrase = if u.partly {
            u.cause.truncated_phrase()
        } else {
            u.cause.phrase()
        };
        match causes.iter_mut().find(|(p, _)| *p == phrase) {
            Some((_, r)) => r.push((u.seq, u.last)),
            None => causes.push((phrase, vec![(u.seq, u.last)])),
        }
    }
    let mut parts: Vec<String> = Vec::new();
    for (phrase, ranges) in causes {
        let ranges = merge(ranges);
        let one = ranges.len() == 1 && ranges[0].0 == ranges[0].1;
        let mut shown: Vec<String> = ranges
            .iter()
            .take(RANGES)
            .map(|&(a, b)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}..{b}")
                }
            })
            .collect();
        if ranges.len() > RANGES {
            shown.push("…".into());
        }
        let noun = if one { "member" } else { "members" };
        parts.push(format!("{noun} {} {phrase}", shown.join(", ")));
    }
    if uncovered > 0 {
        parts.push(format!(
            "{uncovered} bytes outside the listed members not read"
        ));
    }
    if let Some(e) = error {
        parts.push(format!("container structure: {e}"));
    }
    parts.join("; ")
}

/// A member name as reported: control characters escaped, `!/` written
/// `!!/` so a joined path splits unambiguously, and at most [`NAME_MAX`]
/// bytes (a longer name is cut and ends with `…#` and its position).
pub fn escape_name(name: &str, seq: u64) -> String {
    let mut s = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_control() {
            let _ = write!(s, "{}", ch.escape_default());
        } else {
            s.push(ch);
        }
    }
    let mut s = s.replace("!/", "!!/");
    if s.ends_with('!') {
        // Else `a!` joined to a nested member `x` (`a!!/x`) would read as
        // the escaped name `a!/x`.
        s.push('!');
    }
    if s.len() > NAME_MAX {
        let mark = format!("…#{seq}");
        let mut cut = NAME_MAX - mark.len();
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str(&mark);
    }
    s
}

/// The walk state: budgets shared by a top-level container and everything
/// nested in it, and what has been found so far.
struct Walker<'l> {
    limits: &'l Limits,
    /// Extractors for nested containers ([`extractor`] outside tests).
    lookup: Lookup,
    deadline: Instant,
    bytes_left: u64,
    /// Compressed and uncompressed bytes so far, for the overall ratio.
    consumed: u64,
    produced: u64,
    seq: u64,
    depth: u32,
    /// Escaped paths of the nested containers being walked.
    prefix: Vec<String>,
    /// Why the walk stopped offering members, once it has.
    stop: Option<Cause>,
    out: Extracted,
}

type Lookup = fn(ContainerKind) -> Option<&'static dyn Extractor>;

/// Read and classify the members of the container in `src`, under the
/// container limits and one `deadline` for the whole target.
pub fn extract(
    ext: &dyn Extractor,
    src: &dyn Source,
    size: u64,
    limits: &Limits,
    deadline: Instant,
) -> Extracted {
    extract_with(ext, extractor, src, size, limits, deadline)
}

/// [`extract`] with nested containers opened by `lookup`'s extractors.
fn extract_with(
    ext: &dyn Extractor,
    lookup: Lookup,
    src: &dyn Source,
    size: u64,
    limits: &Limits,
    deadline: Instant,
) -> Extracted {
    let mut w = Walker {
        limits,
        lookup,
        deadline,
        bytes_left: limits.container_bytes,
        consumed: 0,
        produced: 0,
        seq: 0,
        depth: 1,
        prefix: Vec::new(),
        stop: None,
        out: Extracted {
            format: ext.id(),
            members: Vec::new(),
            total: 0,
            skipped: 0,
            unread: Vec::new(),
            uncovered: 0,
            error: None,
        },
    };
    if Instant::now() >= deadline {
        w.out.error = Some("timeout".into());
        return w.out;
    }
    if let Err(ContainerError(e)) = ext.extract(src, size, &mut w) {
        w.out.error = Some(e);
    }
    w.out
}

/// What reading a member's stream produced.
enum Got {
    Bytes(Vec<u8>, Option<Cause>),
    Failed(Cause),
}

impl Walker<'_> {
    fn path(&self, name: &str, seq: u64) -> String {
        self.join(escape_name(name, seq))
    }

    /// `own`, an escaped or reserved name, under the nested containers
    /// being walked.
    fn join(&self, own: String) -> String {
        if self.prefix.is_empty() {
            own
        } else {
            format!("{}!/{own}", self.prefix.join("!/"))
        }
    }

    /// Assign the next position, or refuse it (setting `stop`) when the
    /// member count or the deadline is spent.
    fn admit(&mut self) -> Result<u64, Cause> {
        self.seq += 1;
        self.out.total += 1;
        if self.seq > u64::from(self.limits.container_members) {
            return Err(self.halt(Cause::Limit("limits.container_members".into())));
        }
        if Instant::now() >= self.deadline {
            return Err(self.halt(Cause::Limit("limits.time_budget_ms".into())));
        }
        Ok(self.seq)
    }

    fn halt(&mut self, c: Cause) -> Cause {
        self.stop.get_or_insert(c).clone()
    }

    fn unread(&mut self, seq: u64, path: Option<String>, cause: Cause, partly: bool) {
        self.out.unread.push(Unread {
            seq,
            last: seq,
            path,
            cause,
            partly,
        });
    }

    /// Read `data` to the member and container byte budgets, the ratio
    /// limit, and the deadline.
    fn read(&mut self, data: &mut dyn Read, compressed: Option<u64>) -> Got {
        let member_cap = self.limits.member_bytes;
        let cap = member_cap.min(self.bytes_left);
        let cap_cause = if member_cap <= self.bytes_left {
            "limits.member_bytes"
        } else {
            "limits.container_bytes"
        };
        let ratio = u64::from(self.limits.container_ratio);
        let mut out: Vec<u8> = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            if Instant::now() >= self.deadline {
                return Got::Failed(Cause::Limit("limits.time_budget_ms".into()));
            }
            let room = (cap - out.len() as u64 + 1).min(buf.len() as u64) as usize;
            let n = match data.read(&mut buf[..room]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Got::Failed(Cause::Corrupt),
            };
            out.extend_from_slice(&buf[..n]);
            let len = out.len() as u64;
            let over_ratio = |produced: u64, consumed: u64| {
                produced > RATIO_FLOOR && produced > consumed.saturating_mul(ratio)
            };
            if compressed.is_some_and(|c| over_ratio(len, c))
                || over_ratio(
                    self.produced + len,
                    self.consumed + compressed.unwrap_or(len),
                )
            {
                return Got::Failed(Cause::Limit("limits.container_ratio".into()));
            }
            if len > cap {
                out.truncate(cap as usize);
                return Got::Bytes(out, Some(Cause::Limit(cap_cause.into())));
            }
        }
        Got::Bytes(out, None)
    }
}

impl Walk for Walker<'_> {
    fn member(&mut self, meta: MemberMeta, data: &mut dyn Read) -> Flow {
        let seq = match self.admit() {
            Ok(s) => s,
            Err(cause) => {
                self.unread(self.seq, None, cause, false);
                return Flow::Stop;
            }
        };
        let path = self.path(&meta.name, seq);
        if self.bytes_left == 0 {
            // Spent bytes stop only members that need some: an encrypted
            // member after this keeps its own cause.
            let cause = Cause::Limit("limits.container_bytes".into());
            self.unread(seq, Some(path), cause, false);
            return Flow::Continue;
        }
        let (bytes, truncated) = match self.read(data, meta.compressed_size) {
            Got::Bytes(b, t) => (b, t),
            Got::Failed(cause) => {
                let stop = matches!(&cause, Cause::Limit(k) if k == "limits.time_budget_ms");
                if stop {
                    self.halt(cause.clone());
                }
                self.unread(seq, Some(path), cause, false);
                return if stop { Flow::Stop } else { Flow::Continue };
            }
        };
        let len = bytes.len() as u64;
        self.bytes_left -= len;
        self.produced += len;
        self.consumed += meta.compressed_size.unwrap_or(len);
        self.place(seq, path, &meta, bytes, truncated);
        if self.stop.is_some() {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn not_read(&mut self, meta: MemberMeta, why: NotRead) -> Flow {
        let seq = match self.admit() {
            Ok(s) => s,
            Err(cause) => {
                self.unread(self.seq, None, cause, false);
                return Flow::Stop;
            }
        };
        let path = self.path(&meta.name, seq);
        let cause = match why {
            NotRead::Encrypted => Cause::Encrypted,
            NotRead::Unsupported => Cause::Unsupported,
            NotRead::Corrupt => Cause::Corrupt,
        };
        self.unread(seq, Some(path), cause, false);
        Flow::Continue
    }

    fn comment(&mut self, owner: Option<&str>, data: &mut dyn Read) -> Flow {
        let seq = match self.admit() {
            Ok(s) => s,
            Err(cause) => {
                self.unread(self.seq, None, cause, false);
                return Flow::Stop;
            }
        };
        let path = self.join(match owner {
            Some(name) => format!("{}{ENTRY_COMMENT}", escape_name(name, seq)),
            None => COMMENT_MEMBER.to_string(),
        });
        if self.bytes_left == 0 {
            let cause = Cause::Limit("limits.container_bytes".into());
            self.unread(seq, Some(path), cause, false);
            return Flow::Continue;
        }
        let (bytes, truncated) = match self.read(data, None) {
            Got::Bytes(b, t) => (b, t),
            Got::Failed(cause) => {
                self.unread(seq, Some(path), cause, false);
                return Flow::Continue;
            }
        };
        let len = bytes.len() as u64;
        self.bytes_left -= len;
        self.produced += len;
        self.consumed += len;
        // Text whatever it holds: a NUL byte must not turn it into a
        // skipped binary, nor its first bytes into a nested container.
        let head = &bytes[..bytes.len().min(self.limits.sniff)];
        let class = match crate::scanner::classify_member(COMMENT_MEMBER, head, len) {
            c @ FileClass::EncodedText(_) => c,
            _ => FileClass::Text,
        };
        self.keep(seq, path, &class, &bytes, truncated);
        if self.stop.is_some() {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn unaccounted(&mut self, bytes: u64) {
        self.out.uncovered = self.out.uncovered.saturating_add(bytes);
    }

    fn rest(&mut self, n: u64) {
        let cause = self.stop.clone().unwrap_or_else(|| {
            Cause::Limit(if self.expired() {
                "limits.time_budget_ms".into()
            } else {
                "limits.container_members".into()
            })
        });
        if n == 0 {
            return;
        }
        let first = self.seq + 1;
        self.seq += n;
        self.out.total += n;
        self.out.unread.push(Unread {
            seq: first,
            last: self.seq,
            path: None,
            cause,
            partly: false,
        });
    }
}

impl Walker<'_> {
    /// Classify a member read into memory: open it when it is a container,
    /// count it when it is not scanned, else keep it for the scan.
    fn place(
        &mut self,
        seq: u64,
        path: String,
        meta: &MemberMeta,
        bytes: Vec<u8>,
        truncated: Option<Cause>,
    ) {
        let base = meta.name.rsplit('/').next().unwrap_or(&meta.name);
        let head = &bytes[..bytes.len().min(self.limits.sniff)];
        let size = match &truncated {
            Some(_) => meta
                .declared_size
                .unwrap_or(bytes.len() as u64)
                .max(bytes.len() as u64),
            None => bytes.len() as u64,
        };
        let class = crate::scanner::classify_member(base, head, size);
        let nested = match class {
            FileClass::Container(kind) => Some(kind),
            _ => None,
        };
        if let Some(kind) = nested {
            if let Some(t) = truncated {
                self.unread(seq, Some(path), t, false);
                return;
            }
            let Some(ext) = (self.lookup)(kind) else {
                let reason = not_scanned_reason(kind);
                self.unread(seq, Some(path), Cause::Nested(reason), false);
                return;
            };
            if self.depth >= self.limits.container_depth {
                let cause = Cause::Limit("limits.container_depth".into());
                self.unread(seq, Some(path), cause, false);
                return;
            }
            self.depth += 1;
            self.prefix.push(escape_name(&meta.name, seq));
            let r = ext.extract(&&bytes[..], bytes.len() as u64, self);
            self.prefix.pop();
            self.depth -= 1;
            if let Err(ContainerError(e)) = r {
                self.unread(seq, Some(path), Cause::Nested(e), false);
            }
            return;
        }
        if matches!(class, FileClass::Image(_) | FileClass::UnknownBinary) {
            self.out.skipped += 1;
            return;
        }
        self.keep(seq, path, &class, &bytes, truncated);
    }

    /// Prepare a member's bytes for the scan as `class`, recording it as
    /// read in part or not read when so.
    fn keep(
        &mut self,
        seq: u64,
        path: String,
        class: &FileClass,
        bytes: &[u8],
        truncated: Option<Cause>,
    ) {
        let content = match classify::slice_for_scan(bytes, class, self.limits) {
            Ok(c) => c,
            Err(_) => {
                self.unread(seq, Some(path), Cause::Corrupt, false);
                return;
            }
        };
        if let Some(reason) = &content.unscanned {
            self.unread(seq, Some(path), Cause::Nested(reason.clone()), false);
            return;
        }
        if let Some(t) = &truncated {
            self.unread(seq, Some(path.clone()), t.clone(), true);
        } else if let Some(p) = &content.partial {
            let cause = if content.unseen {
                Cause::Scan(p.clone())
            } else {
                Cause::Scan(format!("sampled: {p}"))
            };
            self.unread(seq, Some(path.clone()), cause, true);
        }
        let text = class.is_text();
        self.out.members.push(Member {
            seq,
            path,
            content,
            text,
            truncated,
        });
    }
}

#[cfg(test)]
mod tests;
