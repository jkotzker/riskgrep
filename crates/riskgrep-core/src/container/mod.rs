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
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::time::Instant;

pub mod gzip;
pub mod sqlite;
pub mod tar;
pub mod zip;

/// A container format, as classification recognises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContainerKind {
    Zip,
    Tar,
    Gzip,
    SevenZ,
    Pdf,
    Sqlite,
    /// A compressed stream of a format with no reader, by the name reasons
    /// give it (`xz`).
    Compressed(&'static str),
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
            ContainerKind::Compressed(name) => name,
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
    /// Files beside the container at `path` that hold part of its content and
    /// are not read: each one's reserved member name and what it is. They
    /// can change while the container's own bytes stay the same, so a cached
    /// answer is not used while there are any.
    fn beside(&self, _path: &Path) -> Vec<(&'static str, &'static str)> {
        Vec::new()
    }
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

/// The extractor for `kind`, if that format is read. A new format also needs
/// a `ContainerKind` and its detection in `classify`.
pub fn extractor(kind: ContainerKind) -> Option<&'static dyn Extractor> {
    match kind {
        ContainerKind::Zip => Some(&zip::ZIP),
        ContainerKind::Tar => Some(&tar::TAR),
        ContainerKind::Gzip => Some(&gzip::GZIP),
        ContainerKind::Sqlite => Some(&sqlite::SQLITE),
        ContainerKind::SevenZ | ContainerKind::Pdf | ContainerKind::Compressed(_) => None,
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
#[non_exhaustive]
pub enum NotRead {
    Encrypted,
    /// Stored with a method the extractor cannot decode.
    Unsupported,
    /// Its data or header could not be read.
    Corrupt,
}

/// Part of an entry's stored form that its member's stream does not show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Hidden {
    /// Bytes inside the declared compressed size, after the end of the data.
    PastData(u64),
    /// The local header names the entry differently from the directory.
    LocalName,
    /// The local header could not be read to compare its name.
    LocalHeader,
    /// Its data ends before it should, or a checksum over it does not hold.
    Damaged,
    /// Rows of the table, or parts of its cells, were not read.
    RowsNotRead,
    /// Free pages of the database were not read.
    FreePagesNotRead,
    /// Pages or cells of the table could not be read.
    PagesUnreadable,
}

impl Hidden {
    fn phrase(self) -> String {
        match self {
            Hidden::PastData(1) => "1 byte after its data not read".into(),
            Hidden::PastData(n) => format!("{n} bytes after its data not read"),
            Hidden::LocalName => "local header name differs from the directory".into(),
            Hidden::LocalHeader => "local header not read".into(),
            Hidden::Damaged => "its data ends early or is corrupt".into(),
            Hidden::RowsNotRead => "rows not read".into(),
            Hidden::FreePagesNotRead => "free pages not read".into(),
            Hidden::PagesUnreadable => "unreadable pages".into(),
        }
    }
}

/// What a stream wrapped around a container's members (gzip around a tar) may
/// produce. The walk's limits count members, so the stream needs its own count
/// to stop a bomb before any member is seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    /// Bytes to produce at most: [`FRAMING`] for each member left, and one more
    /// than the walk can still read, so a stream stopped here always runs over
    /// the walk's own limit and is never taken for a whole member.
    pub bytes: u64,
    /// Bytes produced per byte consumed, past [`RATIO_FLOOR`].
    pub ratio: u64,
}

/// How a region that is not a stored file is named.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Region<'a> {
    /// A name as stored; the framework escapes it.
    Stored(&'a str),
    /// A reserved name, already in its final form (it ends in a single `!`).
    Reserved(&'a str),
}

/// What the scanner makes of a value stored inside a member's structure, such
/// as a database's BLOB cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoredValue {
    /// No format the scanner knows: its bytes belong with the text around it.
    Bytes,
    /// A format with a reader of its own: offer it as a member.
    Member,
    /// A format that is not scanned (an image). Counted as a skipped member,
    /// without using up the member limit.
    Skipped,
}

/// Whether the extractor should go on offering members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// An entry with nothing to read (a link or a device). It takes a position
    /// and counts as skipped, so it counts toward the member limit.
    fn without_data(&mut self) -> Flow;
    /// A comment, scanned as text with the same limits as a member: the
    /// comment of the entry named `owner` as stored, under that name and
    /// [`ENTRY_COMMENT`], or with no owner the container's own, under
    /// [`COMMENT_MEMBER`].
    fn comment(&mut self, owner: Option<&str>, data: &mut dyn Read) -> Flow;
    /// Whether the member last offered was read to the end of its stream.
    fn read_to_end(&self) -> bool;
    /// Part of the member last offered was not in its stream, so it was not
    /// read. Ignored when that member was not read at all.
    fn hidden(&mut self, what: Hidden);
    /// Part of an entry that is no member (a directory entry) was not seen.
    /// No member is unread for it, but the container is never reported whole.
    fn directory_entry(&mut self, what: Hidden);
    /// The number of members left unoffered after a `Flow::Stop`.
    fn rest(&mut self, n: u64);
    /// The deadline has passed: work done before offering members (such as
    /// reading headers) should stop.
    fn expired(&self) -> bool;
    /// Bytes of the container that belong to no member or comment offered
    /// (data before the first member or between members): they are not read,
    /// so the container is never reported whole.
    fn unaccounted(&mut self, bytes: u64);
    /// What a stream wrapped around this container's members may produce now.
    fn stream_limits(&self) -> StreamLimits;
    /// The container's own name as stored (empty when not known), for a format
    /// that names its one member after the container.
    fn own_name(&self) -> &str;
    /// Bytes of a region that always scans as text, whatever they hold: a
    /// NUL byte does not make it a skipped binary, nor its first bytes a
    /// nested container. [`Walk::read_to_end`] and [`Walk::hidden`] apply to it.
    fn region(&mut self, name: Region<'_>, data: &mut dyn Read) -> Flow;
    /// Uncompressed bytes the shared budget still allows.
    fn bytes_left(&self) -> u64;
    /// Tell a stored value's format from its first bytes and its size.
    fn stored_value(&mut self, head: &[u8], size: u64) -> StoredValue;
}

/// Bytes a member may always produce whatever its compression ratio, so a
/// small, very repetitive file is not mistaken for a decompression bomb.
pub const RATIO_FLOOR: u64 = 1 << 20;

/// Bytes a stream may produce for each member beyond its content: a tar header,
/// its padding, and a PAX or GNU long-name header for it.
pub const FRAMING: u64 = 4096;

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
#[non_exhaustive]
pub enum Cause {
    /// Over a limit, by its configuration key (`limits.container_members`).
    Limit(String),
    Encrypted,
    Unsupported,
    Corrupt,
    /// A nested container that was not opened, with the reason it would
    /// get as a file (`7z not scanned`).
    Nested(String),
    /// The member's scan did not finish, or could not see all of it.
    Scan(String),
    /// The member was read in part by design, as a file of its class is.
    Sampled(String),
    /// Part of the entry's stored form was not in the member's stream.
    Hidden(Hidden),
    /// A file beside the container holding part of its content, as the
    /// extractor describes it (see [`Extractor::beside`]).
    Beside(String),
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
            Cause::Beside(what) => format!("not read ({what})"),
            Cause::Sampled(_) | Cause::Hidden(_) => self.truncated_phrase(),
        }
    }

    /// The phrase for a member read and scanned only in part.
    pub fn truncated_phrase(&self) -> String {
        match self {
            Cause::Limit(what) | Cause::Scan(what) => format!("read only in part ({what})"),
            Cause::Sampled(note) => format!("sampled ({note})"),
            Cause::Hidden(what) => format!("read only in part ({})", what.phrase()),
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
    /// Some of it was read.
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
    /// Nested containers opened; their members are counted as members.
    pub opened: u64,
    /// `skipped` by kind: an image's format (`png`), [`UNKNOWN_KIND`], or
    /// [`LINK_KIND`]. Each member counts once, at any nesting level, so the
    /// counts add up to `skipped`. No member is named.
    pub skipped_kinds: BTreeMap<&'static str, u64>,
    /// `opened` by the extractor that read each nested container (`zip`,
    /// `tar`, `gzip`, `sqlite`), counted as `skipped_kinds` is.
    pub opened_formats: BTreeMap<&'static str, u64>,
    pub unread: Vec<Unread>,
    /// Bytes of the container, nested ones included, outside every member
    /// (see [`Walk::unaccounted`]).
    pub uncovered: u64,
    /// Entries that are no members, by what their stored form does not show
    /// (see [`Walk::directory_entry`]).
    pub directories: BTreeMap<Hidden, u64>,
    /// Set when the container's own structure could not be read.
    pub error: Option<String>,
}

impl Extracted {
    /// Record a file beside the container (see [`Extractor::beside`]) as a
    /// member that was not read, under its reserved name `path`.
    pub fn beside_not_read(&mut self, path: &str, what: &str) {
        self.total += 1;
        self.unread.push(Unread {
            seq: self.total,
            last: self.total,
            path: Some(path.to_string()),
            cause: Cause::Beside(what.to_string()),
            partly: false,
        });
    }

    /// Status before scanning (see [`status`]).
    pub fn status(&self) -> TargetStatus {
        status(
            !self.members.is_empty(),
            &self.unread,
            self.uncovered,
            &self.directories,
            self.error.as_deref(),
        )
    }
}

/// The kind of a skipped member of no format the scanner recognises.
pub const UNKNOWN_KIND: &str = "unknown";
/// The kind of a skipped entry with nothing to read (a link or a device).
pub const LINK_KIND: &str = "link_or_device";

/// Add one to `kind` in `map`.
fn bump(map: &mut BTreeMap<&'static str, u64>, kind: &'static str) {
    *map.entry(kind).or_insert(0) += 1;
}

/// Take one from `kind` in `map`, dropping a kind that reaches 0.
fn unbump(map: &mut BTreeMap<&'static str, u64>, kind: &'static str) {
    if let Some(n) = map.get_mut(kind) {
        *n -= 1;
        if *n == 0 {
            map.remove(kind);
        }
    }
}

/// Why a container is `skipped`: all of its members were, and nothing in it
/// went unread for any other reason.
pub const ALL_SKIPPED: &str =
    "every member is an image, a binary of unknown format, or an archive of them";

/// A container's status: `unscanned` when no member in scope was read, whole
/// (`read_any`) or in part (listed in `unread` as such), but something was not,
/// or its structure could not be read at all; `partial` when some member was
/// not read whole, an entry's stored form was not all seen, or the structure
/// failed part way; else `scanned`.
pub fn status(
    read_any: bool,
    unread: &[Unread],
    uncovered: u64,
    directories: &BTreeMap<Hidden, u64>,
    error: Option<&str>,
) -> TargetStatus {
    let reason = || describe(unread, uncovered, directories, error);
    if !read_any && unread_counts(unread).1.is_empty() {
        if let (Some(e), true) = (error, unread.is_empty()) {
            return TargetStatus::Unscanned {
                reason: e.to_string(),
            };
        }
        if !unread.is_empty() || uncovered > 0 {
            return TargetStatus::Unscanned { reason: reason() };
        }
    }
    if unread.is_empty() && uncovered == 0 && directories.is_empty() && error.is_none() {
        TargetStatus::Scanned
    } else {
        TargetStatus::Partial { not_read: reason() }
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

/// The members in `unread` not read at all, each counted once, and those
/// read only in part. A member can be listed as both (read in part, then its
/// scan did not finish): it counts as not read.
pub fn unread_counts(unread: &[Unread]) -> (u64, BTreeSet<u64>) {
    let none = merge(
        unread
            .iter()
            .filter(|u| !u.partly)
            .map(|u| (u.seq, u.last))
            .collect(),
    );
    let in_part = unread
        .iter()
        .filter(|u| u.partly && !none.iter().any(|&(a, b)| (a..=b).contains(&u.seq)))
        .map(|u| u.seq)
        .collect();
    (none.iter().map(|(a, b)| b - a + 1).sum(), in_part)
}

/// `members 3, 7..9 encrypted; members 1001..4096 not read
/// (limits.container_members)`: causes in order of first appearance, each
/// with its member positions as ranges. Never a member name.
pub fn describe(
    unread: &[Unread],
    uncovered: u64,
    directories: &BTreeMap<Hidden, u64>,
    error: Option<&str>,
) -> String {
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
    for (what, n) in directories {
        let noun = if *n == 1 { "entry" } else { "entries" };
        parts.push(format!("{n} directory {noun}: {}", what.phrase()));
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
    let mut s = crate::model::escape_controls(name).replace("!/", "!!/");
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
    /// The name of the container being walked, as stored.
    own_name: String,
    /// Why the walk stopped offering members, once it has.
    stop: Option<Cause>,
    /// The member last offered, when any of it was read.
    last: Option<Last>,
    out: Extracted,
}

/// A member read, for what the extractor reports about it afterwards.
struct Last {
    seq: u64,
    path: String,
    placed: Placed,
    /// Its stream was read to the end.
    whole: bool,
}

/// What became of a member read into memory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placed {
    Kept,
    /// Skipped, of this kind (see [`Extracted::skipped_kinds`]).
    Skipped(&'static str),
    /// A nested container opened by this extractor.
    Opened(&'static str),
    NotRead,
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
    extract_named(ext, "", src, size, limits, deadline)
}

/// [`extract`] for a container with a file name, which a format with no member
/// names of its own (gzip) names its member after.
pub fn extract_named(
    ext: &dyn Extractor,
    name: &str,
    src: &dyn Source,
    size: u64,
    limits: &Limits,
    deadline: Instant,
) -> Extracted {
    extract_with(ext, extractor, name, src, size, limits, deadline)
}

/// [`extract`] with nested containers opened by `lookup`'s extractors.
fn extract_with(
    ext: &dyn Extractor,
    lookup: Lookup,
    name: &str,
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
        own_name: name.to_string(),
        stop: None,
        last: None,
        out: Extracted {
            format: ext.id(),
            members: Vec::new(),
            total: 0,
            skipped: 0,
            opened: 0,
            skipped_kinds: BTreeMap::new(),
            opened_formats: BTreeMap::new(),
            unread: Vec::new(),
            uncovered: 0,
            directories: BTreeMap::new(),
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
        self.last = None;
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
        let whole = truncated.is_none();
        let placed = self.place(seq, path.clone(), &meta, bytes, truncated);
        self.last = (placed != Placed::NotRead).then_some(Last {
            seq,
            path,
            placed,
            whole,
        });
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

    fn without_data(&mut self) -> Flow {
        match self.admit() {
            Ok(_) => {
                self.out.skipped += 1;
                bump(&mut self.out.skipped_kinds, LINK_KIND);
                Flow::Continue
            }
            Err(cause) => {
                self.unread(self.seq, None, cause, false);
                Flow::Stop
            }
        }
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
        // Text whatever it holds, unless a byte-order mark says how to read it.
        self.keep_text(
            seq,
            path,
            data,
            |head, len| match crate::scanner::classify_member(COMMENT_MEMBER, head, len) {
                c @ FileClass::EncodedText(_) => c,
                _ => FileClass::Text,
            },
        )
    }

    fn region(&mut self, name: Region<'_>, data: &mut dyn Read) -> Flow {
        let seq = match self.admit() {
            Ok(s) => s,
            Err(cause) => {
                self.unread(self.seq, None, cause, false);
                return Flow::Stop;
            }
        };
        let path = match name {
            Region::Stored(n) => self.path(n, seq),
            Region::Reserved(n) => self.join(n.to_string()),
        };
        self.keep_text(seq, path, data, |_, _| FileClass::Text)
    }

    fn bytes_left(&self) -> u64 {
        self.bytes_left
    }

    fn stored_value(&mut self, head: &[u8], size: u64) -> StoredValue {
        let head = &head[..head.len().min(self.limits.sniff)];
        match crate::scanner::classify_member("", head, size) {
            FileClass::Image(kind) => {
                self.out.total += 1;
                self.out.skipped += 1;
                bump(&mut self.out.skipped_kinds, kind);
                StoredValue::Skipped
            }
            FileClass::KnownBinary(_) | FileClass::Container(_) => StoredValue::Member,
            _ => StoredValue::Bytes,
        }
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn read_to_end(&self) -> bool {
        self.last.as_ref().is_some_and(|l| l.whole)
    }

    fn hidden(&mut self, what: Hidden) {
        let Some(last) = self.last.as_mut() else {
            return;
        };
        // Read in part now, whatever else it was.
        match last.placed {
            Placed::Skipped(kind) => {
                self.out.skipped -= 1;
                unbump(&mut self.out.skipped_kinds, kind);
            }
            Placed::Opened(format) => {
                self.out.opened -= 1;
                unbump(&mut self.out.opened_formats, format);
            }
            Placed::Kept | Placed::NotRead => {}
        }
        last.placed = Placed::Kept;
        let (seq, path) = (last.seq, last.path.clone());
        self.unread(seq, Some(path), Cause::Hidden(what), true);
    }

    fn directory_entry(&mut self, what: Hidden) {
        *self.out.directories.entry(what).or_insert(0) += 1;
    }

    fn unaccounted(&mut self, bytes: u64) {
        self.out.uncovered = self.out.uncovered.saturating_add(bytes);
    }

    fn stream_limits(&self) -> StreamLimits {
        let members = u64::from(self.limits.container_members).saturating_sub(self.seq);
        StreamLimits {
            bytes: self
                .bytes_left
                .saturating_add(members.saturating_mul(FRAMING))
                .saturating_add(1),
            ratio: u64::from(self.limits.container_ratio),
        }
    }

    fn own_name(&self) -> &str {
        &self.own_name
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
    ) -> Placed {
        let base = meta.name.rsplit('/').next().unwrap_or(&meta.name);
        let head = &bytes[..bytes.len().min(self.limits.sniff)];
        let size = match &truncated {
            Some(_) => meta
                .declared_size
                .unwrap_or(bytes.len() as u64)
                .max(bytes.len() as u64),
            None => bytes.len() as u64,
        };
        let class = classify::settle_npz(
            crate::scanner::classify_member(base, head, size),
            &bytes[..],
            bytes.len() as u64,
            self.limits,
        );
        let nested = match class {
            FileClass::Container(kind) => Some(kind),
            _ => None,
        };
        if let Some(kind) = nested {
            if let Some(t) = truncated {
                self.unread(seq, Some(path), t, false);
                return Placed::NotRead;
            }
            let Some(ext) = (self.lookup)(kind) else {
                let reason = not_scanned_reason(kind);
                self.unread(seq, Some(path), Cause::Nested(reason), false);
                return Placed::NotRead;
            };
            if self.depth >= self.limits.container_depth {
                let cause = Cause::Limit("limits.container_depth".into());
                self.unread(seq, Some(path), cause, false);
                return Placed::NotRead;
            }
            self.depth += 1;
            self.prefix.push(escape_name(&meta.name, seq));
            let outer = std::mem::replace(&mut self.own_name, meta.name.clone());
            let r = ext.extract(&&bytes[..], bytes.len() as u64, self);
            self.own_name = outer;
            self.prefix.pop();
            self.depth -= 1;
            return match r {
                Ok(()) => {
                    self.out.opened += 1;
                    bump(&mut self.out.opened_formats, ext.id());
                    Placed::Opened(ext.id())
                }
                Err(ContainerError(e)) => {
                    self.unread(seq, Some(path), Cause::Nested(e), false);
                    Placed::NotRead
                }
            };
        }
        let skipped = match class {
            FileClass::Image(kind) => Some(kind),
            FileClass::UnknownBinary => Some(UNKNOWN_KIND),
            _ => None,
        };
        if let Some(kind) = skipped {
            self.out.skipped += 1;
            bump(&mut self.out.skipped_kinds, kind);
            return Placed::Skipped(kind);
        }
        self.keep(seq, path, &class, &bytes, truncated)
    }

    /// Read a comment or region and keep it for the scan as text, as `class`
    /// says: a NUL byte must not turn it into a skipped binary, nor its first
    /// bytes into a nested container.
    fn keep_text(
        &mut self,
        seq: u64,
        path: String,
        data: &mut dyn Read,
        class: impl Fn(&[u8], u64) -> FileClass,
    ) -> Flow {
        if self.bytes_left == 0 {
            let cause = Cause::Limit("limits.container_bytes".into());
            self.unread(seq, Some(path), cause, false);
            return Flow::Continue;
        }
        let (bytes, truncated) = match self.read(data, None) {
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
        self.consumed += len;
        let head = &bytes[..bytes.len().min(self.limits.sniff)];
        let class = class(head, len);
        let whole = truncated.is_none();
        let placed = self.keep(seq, path.clone(), &class, &bytes, truncated);
        self.last = (placed != Placed::NotRead).then_some(Last {
            seq,
            path,
            placed,
            whole,
        });
        if self.stop.is_some() {
            Flow::Stop
        } else {
            Flow::Continue
        }
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
    ) -> Placed {
        let content = match classify::slice_for_scan(bytes, class, self.limits) {
            Ok(c) => c,
            Err(_) => {
                self.unread(seq, Some(path), Cause::Corrupt, false);
                return Placed::NotRead;
            }
        };
        if let Some(reason) = &content.unscanned {
            self.unread(seq, Some(path), Cause::Nested(reason.clone()), false);
            return Placed::NotRead;
        }
        if let Some(t) = &truncated {
            self.unread(seq, Some(path.clone()), t.clone(), true);
        } else if let Some(p) = &content.partial {
            let cause = if content.read_failed {
                Cause::Scan(p.clone())
            } else {
                Cause::Sampled(p.clone())
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
        Placed::Kept
    }
}

#[cfg(test)]
mod tests;
