//! SQLite databases, read through the file format's documented layout
//! (<https://www.sqlite.org/fileformat2.html>) rather than through the SQLite
//! library. All access is [`Source::range`], so nothing can write a journal, a
//! checkpoint, or a lock; a database in an archive reads like one on disk; a
//! large one is read a page at a time; and damage cannot do worse than a
//! `None` here.
//!
//! Each column of each table is a member, its region: `table/column`, whose
//! bytes are the column's cells joined by line feeds, so a location in a
//! region is a line and an offset in that joined text, not a row. The schema's
//! `CREATE` statements are the region `sqlite_schema/sql`. Free pages and the
//! unused space of the pages read are the region [`UNUSED_MEMBER`].
//!
//! A table is read from both ends (oldest rows, then newest) within a share of
//! the byte budget. Tables are visited smallest first, so what a small table
//! leaves goes to the larger ones. Integers and floats are not read as text.
//! When everything was read, a page nothing reached makes the database partial.

use super::{ContainerError, Extractor, Flow, Hidden, MemberMeta, Region, StoredValue, Walk};
use crate::classify::Source;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

pub const MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The start of a write-ahead log: a magic number with its low bit free for
/// the byte order of its checksums, then file format version 3007000.
const WAL_MAGIC: [&[u8; 8]; 2] = [
    b"\x37\x7f\x06\x82\x00\x2d\xe2\x18",
    b"\x37\x7f\x06\x83\x00\x2d\xe2\x18",
];
const JOURNAL_MAGIC: &[u8; 8] = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7";

/// The reserved member name of free pages and unused space. It ends in a
/// single `!`, which no escaped name does.
pub const UNUSED_MEMBER: &str = "unused!";
/// The reserved member names of the logs beside a database (never read).
pub const WAL_MEMBER: &str = "wal!";
pub const JOURNAL_MEMBER: &str = "journal!";

const HEADER: usize = 100;
/// Deepest b-tree followed. SQLite itself stops at 20.
const DEPTH_MAX: u32 = 32;
/// SQLite's largest possible column count (`SQLITE_MAX_COLUMN`'s ceiling).
const COLUMNS_MAX: usize = 32767;
/// The longest `CREATE` statement parsed for column names; a longer one's
/// columns go by position.
const SQL_PARSE_MAX: usize = 1 << 20;
/// The largest file whose index pages are walked to see that every page is
/// reached. A larger one that would otherwise be whole reports its unreached
/// pages unread rather than spend the time budget on its indexes.
const INDEX_WALK_MAX: u64 = 64 << 20;
/// The offset whose page SQLite reserves for its file locks, in files that big.
const LOCK_BYTE_OFFSET: u64 = 1 << 30;
/// Bytes a stored value's format is told from.
const VALUE_HEAD: usize = 8192;

/// Whether `head` starts a write-ahead log or rollback journal, which belong
/// to a database and are not one.
pub fn is_log(head: &[u8]) -> bool {
    WAL_MAGIC.iter().any(|m| head.starts_with(*m)) || head.starts_with(JOURNAL_MAGIC)
}

pub struct Sqlite;

pub static SQLITE: Sqlite = Sqlite;

fn be16(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes(
        b.get(at..at + 2)?.try_into().ok()?,
    )))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A big-endian varint of up to nine bytes, and its length.
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..8 {
        let x = *b.get(i)?;
        v = (v << 7) | u64::from(x & 0x7F);
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    Some(((v << 8) | u64::from(*b.get(8)?), 9))
}

/// The text encoding of a database.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TextEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

struct Db<'a> {
    src: &'a dyn Source,
    page_size: u64,
    usable: u64,
    pages: u32,
    encoding: TextEncoding,
    first_free: u32,
    /// Auto-vacuum is on, so the file holds pointer-map pages.
    pointer_maps: bool,
    /// The pages fetched so far.
    reached: RefCell<HashSet<u32>>,
}

impl<'a> Db<'a> {
    /// Read the header. `Err` when this is not a database that can be read,
    /// which includes one encrypted past its first bytes. Also returns the
    /// bytes the header's page count does not account for.
    fn open(src: &'a dyn Source, size: u64) -> Result<(Db<'a>, u64), ContainerError> {
        let unreadable =
            || ContainerError("sqlite header not readable: encrypted or corrupt".into());
        let head = src
            .range(0, size.min(HEADER as u64))
            .map_err(|_| unreadable())?;
        if !head.starts_with(MAGIC) {
            if WAL_MAGIC.iter().any(|m| head.starts_with(*m)) {
                return Err(ContainerError("sqlite write-ahead log not read".into()));
            }
            if head.starts_with(JOURNAL_MAGIC) {
                return Err(ContainerError("sqlite rollback journal not read".into()));
            }
            return Err(ContainerError(
                "no sqlite header: encrypted or not a database".into(),
            ));
        }
        if head.len() < HEADER {
            return Err(unreadable());
        }
        let page_size = match be16(&head, 16).ok_or_else(unreadable)? {
            1 => 65536,
            n if (512..=32768).contains(&n) && n.is_power_of_two() => n as u64,
            _ => return Err(unreadable()),
        };
        let usable = page_size - u64::from(head[20]);
        // The payload fractions are fixed by the format, and an encrypted
        // body would not keep them.
        if usable < 480 || head[21..24] != [64, 32, 32] {
            return Err(unreadable());
        }
        let encoding = match be32(&head, 56).ok_or_else(unreadable)? {
            0 | 1 => TextEncoding::Utf8,
            2 => TextEncoding::Utf16Le,
            3 => TextEncoding::Utf16Be,
            _ => return Err(unreadable()),
        };
        let in_file = u32::try_from(size / page_size).unwrap_or(u32::MAX);
        // The header's page count holds only when written by the writer that
        // last changed the file.
        let declared = (be32(&head, 24) == be32(&head, 92))
            .then(|| be32(&head, 28))
            .flatten()
            .filter(|&n| n > 0);
        let pages = declared.map_or(in_file, |n| n.min(in_file));
        // Pages past the declared end, a partial page, or pages the file has
        // lost: none of them can be read as part of a table.
        let held = u64::from(pages) * page_size;
        let missing = declared.map_or(0, |n| u64::from(n.saturating_sub(in_file)) * page_size);
        let db = Db {
            src,
            page_size,
            usable,
            pages,
            encoding,
            first_free: be32(&head, 32).ok_or_else(unreadable)?,
            pointer_maps: be32(&head, 52).ok_or_else(unreadable)? != 0,
            reached: RefCell::new(HashSet::new()),
        };
        Ok((db, (size - held) + missing))
    }

    /// Page `n`, 1-based.
    fn page(&self, n: u32) -> Option<Vec<u8>> {
        if n == 0 || n > self.pages {
            return None;
        }
        self.reached.borrow_mut().insert(n);
        self.src
            .range(u64::from(n - 1) * self.page_size, self.page_size)
            .ok()
    }

    /// How much of a payload of `total` bytes sits in its b-tree cell.
    fn local(&self, total: u64, index: bool) -> u64 {
        let u = self.usable;
        let max = if index {
            (u - 12) * 64 / 255 - 23
        } else {
            u - 35
        };
        if total <= max {
            return total;
        }
        let min = (u - 12) * 32 / 255 - 23;
        let k = min + (total - min) % (u - 4);
        if k <= max {
            k
        } else {
            min
        }
    }

    /// `v` as UTF-8, transcoded when the database stores UTF-16.
    fn decoded(&self, v: &[u8], out: &mut Vec<u8>) {
        let be = match self.encoding {
            TextEncoding::Utf8 => {
                out.extend_from_slice(v);
                return;
            }
            TextEncoding::Utf16Le => false,
            TextEncoding::Utf16Be => true,
        };
        let units = v.as_chunks::<2>().0.iter().map(|&c| {
            if be {
                u16::from_be_bytes(c)
            } else {
                u16::from_le_bytes(c)
            }
        });
        let mut buf = [0u8; 4];
        for ch in char::decode_utf16(units) {
            let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }

    /// Fetch every page of the index at `n`, for [`Db::unreached`]: its
    /// interior and leaf pages and its cells' overflow chains.
    fn walk_index(&self, n: u32, depth: u32, entered: &mut HashSet<u32>, walk: &dyn Walk) {
        if walk.expired() || depth > DEPTH_MAX || !entered.insert(n) {
            return;
        }
        let Some(page) = self.page(n) else { return };
        let Some(node) = Node::parse(&page, n, self.usable) else {
            return;
        };
        let skip = if node.interior() { 4 } else { 0 };
        for i in 0..node.cells {
            let Some(cell) = node.cell(i) else { continue };
            if let (true, Some(child)) = (node.interior(), be32(cell, 0)) {
                self.walk_index(child, depth + 1, entered, walk);
            }
            let row = cell.get(skip..).and_then(|rest| {
                let (total, k) = varint(rest)?;
                Some((total, rest.get(k..)?))
            });
            if let Some((total, rest)) = row {
                self.follow_overflow(rest, total, entered, walk);
            }
        }
        if let (true, Some(right)) = (node.interior(), node.right_child()) {
            self.walk_index(right, depth + 1, entered, walk);
        }
    }

    /// Fetch the overflow chain of an index cell's payload of `total` bytes.
    fn follow_overflow(
        &self,
        rest: &[u8],
        total: u64,
        entered: &mut HashSet<u32>,
        walk: &dyn Walk,
    ) {
        let local = self.local(total, true);
        if total == local {
            return;
        }
        let mut next = be32(rest, local as usize).unwrap_or(0);
        while next != 0 && !walk.expired() && entered.insert(next) {
            let Some(page) = self.page(next) else { return };
            next = be32(&page, 0).unwrap_or(0);
        }
    }

    /// Bytes of the pages no table, index, or free list has reached. Pointer
    /// maps and the lock-byte page hold no rows, and no tree reaches them.
    fn unreached(&self, entries: &[SchemaEntry], size: u64, walk: &dyn Walk) -> u64 {
        if size <= INDEX_WALK_MAX {
            let mut entered = HashSet::new();
            for e in entries.iter().filter(|e| e.kind == "index") {
                if let Ok(root) = u32::try_from(e.root) {
                    self.walk_index(root, 0, &mut entered, walk);
                }
            }
        }
        // Counted from what was reached, not by visiting every page number: a
        // sparse file can claim billions of them.
        let per_map = self.usable / 5 + 1;
        let lock_byte = LOCK_BYTE_OFFSET / self.page_size + 1;
        let pages = u64::from(self.pages);
        let map = |n: u64| is_pointer_map(self.pointer_maps, n, per_map);
        let maps = if self.pointer_maps && pages >= 2 {
            (pages - 2) / per_map + 1
        } else {
            0
        };
        let lock = u64::from(lock_byte <= pages && !map(lock_byte));
        let reached = self.reached.borrow();
        let plain = reached
            .iter()
            .filter(|&&n| !map(u64::from(n)) && u64::from(n) != lock_byte)
            .count() as u64;
        (pages - maps - lock - plain) * self.page_size
    }

    fn text(&self, v: &[u8]) -> String {
        let mut out = Vec::with_capacity(v.len());
        self.decoded(v, &mut out);
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// Whether page `n` is a pointer map, in a database that has them.
fn is_pointer_map(pointer_maps: bool, n: u64, per_map: u64) -> bool {
    pointer_maps && n >= 2 && (n - 2).is_multiple_of(per_map)
}

/// A b-tree page's header.
struct Node<'p> {
    page: &'p [u8],
    base: usize,
    kind: u8,
    cells: usize,
    /// Offset of the cell pointer array.
    pointers: usize,
    usable: usize,
}

impl<'p> Node<'p> {
    fn parse(page: &'p [u8], n: u32, usable: u64) -> Option<Node<'p>> {
        let base = if n == 1 { HEADER } else { 0 };
        let kind = *page.get(base)?;
        let header = match kind {
            2 | 5 => 12,
            10 | 13 => 8,
            _ => return None,
        };
        let usable = usable as usize;
        let cells = be16(page, base + 3)?;
        let pointers = base + header;
        (pointers + cells * 2 <= usable).then_some(Node {
            page,
            base,
            kind,
            cells,
            pointers,
            usable,
        })
    }

    fn interior(&self) -> bool {
        matches!(self.kind, 2 | 5)
    }

    fn index(&self) -> bool {
        matches!(self.kind, 2 | 10)
    }

    /// The bytes from cell `i` to the end of the usable page.
    fn cell(&self, i: usize) -> Option<&'p [u8]> {
        let at = be16(self.page, self.pointers + i * 2)?;
        if at < self.pointers + self.cells * 2 || at >= self.usable {
            return None;
        }
        self.page.get(at..self.usable)
    }

    fn right_child(&self) -> Option<u32> {
        be32(self.page, self.base + 8)
    }
}

/// A record's field: serial type, and offset and length in the payload.
type Field = (u64, usize, u64);

/// A record's fields, and the length its header says the whole record has.
fn fields(p: &[u8]) -> Option<(Vec<Field>, u64)> {
    let (header, n) = varint(p)?;
    if header < n as u64 {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = n;
    let mut body = header;
    let end = header.min(p.len() as u64) as usize;
    while pos < end {
        let (serial, k) = varint(&p[pos..end])?;
        pos += k;
        let len = match serial {
            0 | 8 | 9 => 0,
            1..=4 => serial,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return None,
            s => (s - 12) / 2,
        };
        out.push((serial, usize::try_from(body).ok()?, len));
        body = body.checked_add(len)?;
        if out.len() > COLUMNS_MAX {
            return None;
        }
    }
    Some((out, body))
}

/// The value of an integer field.
fn int_value(serial: u64, v: &[u8]) -> Option<i64> {
    match serial {
        8 => Some(0),
        9 => Some(1),
        1..=6 => {
            let mut x: i64 = if *v.first()? & 0x80 != 0 { -1 } else { 0 };
            for b in v {
                x = (x << 8) | i64::from(*b);
            }
            Some(x)
        }
        _ => None,
    }
}

/// A value too structured to read as bytes: offered as a member of its own
/// once every table's text has been read.
struct Deferred {
    name: String,
    declared: u64,
    bytes: Vec<u8>,
}

/// What reading one b-tree produced.
#[derive(Default)]
struct TableData {
    /// Text and bytes by stored field position.
    regions: BTreeMap<usize, Vec<u8>>,
    deferred: Vec<Deferred>,
    /// The schema's rows, when reading the schema.
    entries: Vec<SchemaEntry>,
    /// Rows or parts of rows were not read, by limit or deadline.
    sampled: bool,
    /// Pages or cells could not be read.
    damaged: bool,
}

struct SchemaEntry {
    kind: String,
    name: String,
    root: i64,
    sql: Option<String>,
}

/// The b-tree to read.
#[derive(Clone, Copy)]
struct Target<'r> {
    root: u32,
    table: &'r str,
    /// The stored fields' names.
    names: &'r [String],
    /// It is `sqlite_schema`: its rows describe the database.
    schema: bool,
}

/// One walk of one table's b-tree: both ends, within `limit` bytes.
struct Tree<'r, 'a> {
    db: &'r Db<'a>,
    walk: &'r mut dyn Walk,
    target: Target<'r>,
    /// Bytes the whole walk may read.
    share: u64,
    /// Bytes at which this pass reads no further leaf.
    limit: u64,
    used: u64,
    /// Leaves read, by either pass. A leaf is read whole or not at all.
    leaves: HashSet<u32>,
    /// Interior keys read (tables without a rowid hold rows in them too).
    keys: HashSet<(u32, usize)>,
    /// Pages this pass has entered: a page reached twice is damage.
    entered: HashSet<u32>,
    /// The second pass reached a leaf the first read: nothing lies between
    /// them, unless the tree is damaged, in which case the pages between them
    /// are found unreached ([`Db::unreached`]).
    met: bool,
    index: bool,
    out: TableData,
    unused: &'r mut Vec<u8>,
    /// The number of member values so far, per field.
    values: BTreeMap<usize, u64>,
}

impl Tree<'_, '_> {
    /// Visit page `n` and everything under it; `Flow::Stop` ends the pass.
    fn descend(&mut self, n: u32, depth: u32, reverse: bool) -> Flow {
        if self.walk.expired() {
            self.out.sampled = true;
            return Flow::Stop;
        }
        if depth > DEPTH_MAX || !self.entered.insert(n) {
            self.out.damaged = true;
            return Flow::Continue;
        }
        let Some(page) = self.db.page(n) else {
            self.out.damaged = true;
            return Flow::Continue;
        };
        let node = Node::parse(&page, n, self.db.usable);
        let Some(node) = node.filter(|p| depth == 0 || p.index() == self.index) else {
            self.out.damaged = true;
            return Flow::Continue;
        };
        if depth == 0 {
            self.index = node.index();
        }
        if !node.interior() {
            if self.leaves.contains(&n) {
                self.met = true;
                return Flow::Stop;
            }
            if reverse && self.used >= self.limit {
                return Flow::Stop;
            }
            for i in 0..node.cells {
                self.leaf_cell(&node, i);
            }
            self.note_unused(&node);
            self.leaves.insert(n);
            return if self.used >= self.limit {
                Flow::Stop
            } else {
                Flow::Continue
            };
        }
        if reverse {
            let right = node.right_child();
            if self.child(right, depth, reverse) == Flow::Stop {
                return Flow::Stop;
            }
        }
        for k in 0..node.cells {
            let i = if reverse { node.cells - 1 - k } else { k };
            let cell = node.cell(i);
            if cell.is_none() {
                self.out.damaged = true;
            }
            let child = cell.and_then(|c| be32(c, 0));
            if reverse && self.interior_key(n, i, cell) == Flow::Stop {
                return Flow::Stop;
            }
            if cell.is_some() && self.child(child, depth, reverse) == Flow::Stop {
                return Flow::Stop;
            }
            if !reverse && self.interior_key(n, i, cell) == Flow::Stop {
                return Flow::Stop;
            }
        }
        if !reverse {
            let right = node.right_child();
            if self.child(right, depth, reverse) == Flow::Stop {
                return Flow::Stop;
            }
        }
        Flow::Continue
    }

    fn child(&mut self, n: Option<u32>, depth: u32, reverse: bool) -> Flow {
        match n {
            Some(n) => self.descend(n, depth + 1, reverse),
            None => {
                self.out.damaged = true;
                Flow::Continue
            }
        }
    }

    /// An interior cell's key, which in a table without a rowid is a row.
    fn interior_key(&mut self, n: u32, i: usize, cell: Option<&[u8]>) -> Flow {
        if !self.index {
            return Flow::Continue;
        }
        let Some(cell) = cell else {
            return Flow::Continue;
        };
        if self.keys.contains(&(n, i)) {
            return Flow::Continue;
        }
        if self.used >= self.limit {
            return Flow::Stop;
        }
        self.keys.insert((n, i));
        let row = cell.get(4..).and_then(|rest| {
            let (total, k) = varint(rest)?;
            Some((total, rest.get(k..)?))
        });
        match row {
            Some((total, rest)) => self.row(rest, total, true),
            None => self.out.damaged = true,
        }
        if self.used >= self.limit {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn leaf_cell(&mut self, node: &Node<'_>, i: usize) {
        let row = node.cell(i).and_then(|cell| {
            let (total, a) = varint(cell)?;
            let at = if node.index() {
                a
            } else {
                a + varint(cell.get(a..)?)?.1
            };
            Some((total, cell.get(at..)?))
        });
        match row {
            Some((total, rest)) => self.row(rest, total, node.index()),
            None => self.out.damaged = true,
        }
    }

    /// Up to `room` bytes of a payload of `total`, the first of them in
    /// `rest`, the others along its overflow chain. Stops at the chain's end,
    /// so a loop costs no more than a chain as long as `room`.
    fn payload(&mut self, rest: &[u8], total: u64, index: bool, room: u64) -> Option<Vec<u8>> {
        let local = self.db.local(total, index);
        let in_cell = rest.get(..usize::try_from(local).ok()?)?;
        let mut out = in_cell.to_vec();
        if total == local {
            return Some(out);
        }
        let mut next = be32(rest, local as usize)?;
        let want = total.min(room.max(local));
        while (out.len() as u64) < want {
            if self.walk.expired() {
                self.out.sampled = true;
                break;
            }
            let Some(page) = (next != 0).then(|| self.db.page(next)).flatten() else {
                self.out.damaged = true;
                break;
            };
            let data = page.get(4..self.db.usable as usize)?;
            let take = (want - out.len() as u64).min(data.len() as u64) as usize;
            out.extend_from_slice(&data[..take]);
            next = be32(&page, 0)?;
        }
        Some(out)
    }

    /// A row: its record, the first `rest` bytes of a payload of `total`.
    fn row(&mut self, rest: &[u8], total: u64, index: bool) {
        let room = self.share.saturating_sub(self.used);
        let Some(p) = self.payload(rest, total, index, room) else {
            self.out.damaged = true;
            return;
        };
        self.used += (p.len() as u64).max(1);
        if (p.len() as u64) < total {
            self.out.sampled = true;
        }
        // Cut inside its header, a record cannot be judged damaged. Read whole,
        // one whose lengths do not add up to its payload holds bytes no field
        // shows, or fields the payload does not hold.
        let whole = (p.len() as u64) == total;
        let record = match fields(&p) {
            Some((record, length)) if !whole || length == total => record,
            Some((record, _)) => {
                self.out.damaged = true;
                record
            }
            None => {
                self.out.damaged |= whole;
                return;
            }
        };
        if self.target.schema {
            self.schema_row(&p, &record);
            return;
        }
        for (i, &(serial, at, len)) in record.iter().enumerate() {
            if serial < 12 {
                continue;
            }
            let end = at.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
            let Some(v) = p.get(at.min(p.len())..end.min(p.len())) else {
                continue;
            };
            if at > p.len() || (v.is_empty() && len > 0) {
                continue;
            }
            if serial % 2 == 1 {
                let r = self.out.regions.entry(i).or_default();
                self.db.decoded(v, r);
                r.push(b'\n');
                continue;
            }
            let head = &v[..v.len().min(VALUE_HEAD)];
            match self.walk.stored_value(head, len) {
                StoredValue::Bytes => {
                    let r = self.out.regions.entry(i).or_default();
                    r.extend_from_slice(v);
                    r.push(b'\n');
                }
                StoredValue::Skipped => {}
                StoredValue::Member => {
                    let k = self.values.entry(i).or_insert(0);
                    *k += 1;
                    let name = format!(
                        "{}/{}!blob!{k}",
                        name_part(self.target.table),
                        name_part(&column_name(self.target.names, i))
                    );
                    self.out.deferred.push(Deferred {
                        name,
                        declared: len,
                        bytes: v.to_vec(),
                    });
                }
            }
        }
    }

    /// A row of `sqlite_schema`: type, name, table name, root page, statement.
    fn schema_row(&mut self, p: &[u8], record: &[Field]) {
        let value = |i: usize| {
            let &(serial, at, len) = record.get(i)?;
            let end = at.checked_add(usize::try_from(len).ok()?)?;
            Some((serial, p.get(at..end)?))
        };
        let text = |i: usize| match value(i) {
            Some((s, v)) if s >= 13 && s % 2 == 1 => Some(self.db.text(v)),
            _ => None,
        };
        let (Some(kind), Some(name), Some((serial, root))) = (text(0), text(1), value(3)) else {
            self.out.damaged = true;
            return;
        };
        let sql = text(4);
        if let Some(sql) = &sql {
            let r = self.out.regions.entry(0).or_default();
            r.extend_from_slice(sql.as_bytes());
            r.push(b'\n');
        }
        self.out.entries.push(SchemaEntry {
            kind,
            name,
            root: int_value(serial, root).unwrap_or(-1),
            sql,
        });
    }

    /// Keep what a leaf's unused space holds: its gap and its freeblocks, where
    /// a deleted row's bytes stay until they are overwritten.
    fn note_unused(&mut self, node: &Node<'_>) {
        let pointers_end = node.pointers + node.cells * 2;
        let content = match be16(node.page, node.base + 5) {
            Some(0) => node.usable,
            Some(n) => n.min(node.usable),
            None => return,
        };
        if let Some(gap) = node.page.get(pointers_end..content) {
            self.keep_unused(gap);
        }
        let mut at = be16(node.page, node.base + 1).unwrap_or(0);
        while at >= pointers_end && at + 4 <= node.usable {
            let (Some(next), Some(size)) = (be16(node.page, at), be16(node.page, at + 2)) else {
                break;
            };
            if size >= 4 {
                if let Some(block) = node.page.get(at + 4..(at + size).min(node.usable)) {
                    self.keep_unused(block);
                }
            }
            // Freeblocks ascend, which also ends a loop.
            if next <= at {
                break;
            }
            at = next;
        }
    }

    fn keep_unused(&mut self, bytes: &[u8]) {
        if bytes.iter().any(|&b| b != 0) {
            self.unused.extend_from_slice(bytes);
            self.unused.push(b'\n');
            self.used += bytes.len() as u64;
        }
    }
}

/// `name` as a path component: `/` and `%` are written `%2F` and `%25`, so a
/// region's path splits into its table and column.
fn name_part(name: &str) -> String {
    name.replace('%', "%25").replace('/', "%2F")
}

/// The name of stored field `i`; a field the schema does not name goes by its
/// position, as `?1`. Names cannot be empty in a schema SQLite accepted.
fn column_name(names: &[String], i: usize) -> String {
    names
        .get(i)
        .cloned()
        .unwrap_or_else(|| format!("?{}", i + 1))
}

/// Read a table's tree: from the left for half of `share`, then from the right
/// until the share is spent or the passes meet.
fn read_tree(
    db: &Db<'_>,
    walk: &mut dyn Walk,
    target: Target<'_>,
    share: u64,
    unused: &mut Vec<u8>,
) -> TableData {
    let mut t = Tree {
        db,
        walk,
        target,
        share,
        limit: share / 2 + share % 2,
        used: 0,
        leaves: HashSet::new(),
        keys: HashSet::new(),
        entered: HashSet::new(),
        met: false,
        index: false,
        out: TableData::default(),
        unused,
        values: BTreeMap::new(),
    };
    if t.descend(target.root, 0, false) == Flow::Continue {
        return t.out;
    }
    if !t.walk.expired() {
        t.limit = share;
        t.entered.clear();
        if t.descend(target.root, 0, true) == Flow::Continue || t.met {
            return t.out;
        }
    }
    t.out.sampled = true;
    t.out
}

/// A cheap size estimate: the fan-out along the left edge of the tree, in
/// bytes, so tables can be visited smallest first.
fn estimated_size(db: &Db<'_>, root: u32, walk: &dyn Walk) -> u64 {
    let mut n = root;
    let mut leaves = 1u64;
    for _ in 0..DEPTH_MAX {
        if walk.expired() {
            break;
        }
        let Some(page) = db.page(n) else { break };
        let Some(node) = Node::parse(&page, n, db.usable) else {
            break;
        };
        if !node.interior() {
            break;
        }
        leaves = leaves.saturating_mul(node.cells as u64 + 1);
        let Some(next) = node.cell(0).and_then(|c| be32(c, 0)) else {
            break;
        };
        n = next;
    }
    leaves.saturating_mul(db.usable)
}

/// Free pages, as stored, up to `budget` bytes. Returns whether the free list
/// was read to its end and whether it was sound.
fn read_free_pages(db: &Db<'_>, walk: &dyn Walk, budget: u64, out: &mut Vec<u8>) -> (bool, bool) {
    let usable = db.usable as usize;
    let mut keep = |bytes: &[u8]| {
        if bytes.iter().any(|&b| b != 0) {
            out.extend_from_slice(bytes);
            out.push(b'\n');
        }
    };
    let mut seen = HashSet::new();
    let mut read = 0u64;
    let mut trunk = db.first_free;
    while trunk != 0 {
        if walk.expired() || read >= budget {
            return (false, true);
        }
        if !seen.insert(trunk) {
            return (true, false);
        }
        let Some(page) = db.page(trunk) else {
            return (true, false);
        };
        let (Some(next), Some(count)) = (be32(&page, 0), be32(&page, 4)) else {
            return (true, false);
        };
        let Some(end) = (count as usize)
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .filter(|&e| e <= usable)
        else {
            return (true, false);
        };
        keep(&page[end..usable]);
        read += db.page_size;
        for i in 0..count as usize {
            if walk.expired() || read >= budget {
                return (false, true);
            }
            let Some(n) = be32(&page, 8 + i * 4) else {
                return (true, false);
            };
            if !seen.insert(n) {
                return (true, false);
            }
            let Some(leaf) = db.page(n) else {
                return (true, false);
            };
            keep(&leaf[..usable]);
            read += db.page_size;
        }
        trunk = next;
    }
    (true, true)
}

/// A table to read.
struct TableEntry {
    name: String,
    root: u32,
    columns: Vec<String>,
    size: u64,
}

impl Extractor for Sqlite {
    fn id(&self) -> &'static str {
        "sqlite"
    }

    fn version(&self) -> u32 {
        1
    }

    fn beside(&self, path: &Path) -> Vec<(&'static str, &'static str)> {
        let named = |suffix: &str| {
            let mut p = path.as_os_str().to_os_string();
            p.push(suffix);
            p
        };
        let mut out = Vec::new();
        if fs::metadata(named("-wal")).is_ok_and(|m| m.len() > 0) {
            out.push((WAL_MEMBER, "write-ahead log beside the database"));
        }
        if journal_is_live(Path::new(&named("-journal"))) {
            out.push((JOURNAL_MEMBER, "rollback journal beside the database"));
        }
        out
    }

    fn extract(
        &self,
        src: &dyn Source,
        size: u64,
        walk: &mut dyn Walk,
    ) -> Result<(), ContainerError> {
        let (db, outside) = Db::open(src, size)?;
        let not_readable =
            || ContainerError("sqlite page 1 not readable: encrypted or corrupt".into());
        let first = db.page(1).ok_or_else(not_readable)?;
        // An encrypted body with a plaintext header stops here, unless its
        // first bytes happen to look like a page and its cells then fail.
        let root = Node::parse(&first, 1, db.usable).ok_or_else(not_readable)?;
        if root.index() {
            return Err(not_readable());
        }
        walk.unaccounted(outside);
        let fits = size <= walk.bytes_left();

        // The schema, within all the budget there is.
        let mut unused = Vec::new();
        let share = walk.bytes_left();
        let target = Target {
            root: 1,
            table: "sqlite_schema",
            names: &[],
            schema: true,
        };
        let schema = read_tree(&db, walk, target, share, &mut unused);
        // A damaged first page with nothing readable under it is not a
        // database that was read.
        if schema.entries.is_empty() && schema.damaged {
            return Err(not_readable());
        }
        let mut tables: Vec<TableEntry> = schema
            .entries
            .iter()
            .filter(|e| e.kind == "table")
            .filter_map(|e| table_entry(&db, e, fits, walk))
            .collect();
        if !fits {
            tables.sort_by_key(|t| t.size);
        }
        // Tables not yet offered.
        let mut left = tables.len() as u64;
        let sql = schema.regions.get(&0);
        if sql.is_some() || schema.sampled || schema.damaged {
            let mut bytes = sql.map_or(&[][..], Vec::as_slice);
            let flow = walk.region(Region::Stored("sqlite_schema/sql"), &mut bytes);
            mark(walk, schema.sampled, schema.damaged);
            if flow == Flow::Stop {
                walk.rest(left);
                return Ok(());
            }
        }

        let mut deferred: Vec<Deferred> = Vec::new();
        let mut held = unused.len() as u64;
        // Nothing was left unread by a limit or damage, so any page not
        // reached so far is one nothing leads to.
        let mut whole = !schema.sampled && !schema.damaged;
        for (k, t) in tables.iter().enumerate() {
            left -= 1;
            if walk.expired() {
                walk.rest(left + 1 + deferred.len() as u64);
                return Ok(());
            }
            let room = walk.bytes_left().saturating_sub(held);
            let share = if fits {
                room
            } else {
                room / (tables.len() - k) as u64
            };
            let before = unused.len();
            let data = if share == 0 {
                TableData {
                    sampled: true,
                    ..TableData::default()
                }
            } else {
                let target = Target {
                    root: t.root,
                    table: &t.name,
                    names: &t.columns,
                    schema: false,
                };
                read_tree(&db, walk, target, share, &mut unused)
            };
            held += (unused.len() - before) as u64;
            held += data
                .deferred
                .iter()
                .map(|d| d.bytes.len() as u64)
                .sum::<u64>();
            deferred.extend(data.deferred);
            whole &= !data.sampled && !data.damaged;
            let mut to_offer = data.regions.len() as u64;
            let table = name_part(&t.name);
            for (i, bytes) in &data.regions {
                to_offer -= 1;
                let name = format!("{table}/{}", name_part(&column_name(&t.columns, *i)));
                let flow = walk.region(Region::Stored(&name), &mut &bytes[..]);
                mark(walk, data.sampled, data.damaged);
                if flow == Flow::Stop {
                    walk.rest(to_offer + left + deferred.len() as u64);
                    return Ok(());
                }
            }
            if data.regions.is_empty() && (data.sampled || data.damaged) {
                // Something of this table was not read, and no region says so.
                let flow = walk.region(Region::Stored(&table), &mut &[][..]);
                mark(walk, data.sampled, data.damaged);
                if flow == Flow::Stop {
                    walk.rest(left + deferred.len() as u64);
                    return Ok(());
                }
            }
        }

        // Free pages and unused space, then values with a format of their own.
        let pending: u64 = deferred.iter().map(|d| d.bytes.len() as u64).sum();
        let room = walk
            .bytes_left()
            .saturating_sub(pending + unused.len() as u64);
        let (to_end, sound) = read_free_pages(&db, walk, room, &mut unused);
        if whole && to_end && sound {
            walk.unaccounted(db.unreached(&schema.entries, size, walk));
        }
        if !unused.is_empty() || !to_end || !sound {
            let flow = walk.region(Region::Reserved(UNUSED_MEMBER), &mut &unused[..]);
            if !to_end {
                walk.hidden(Hidden::FreePagesNotRead);
            }
            if !sound {
                walk.hidden(Hidden::PagesUnreadable);
            }
            if flow == Flow::Stop {
                walk.rest(deferred.len() as u64);
                return Ok(());
            }
        }
        let mut to_offer = deferred.len() as u64;
        for d in &deferred {
            to_offer -= 1;
            let meta = MemberMeta {
                name: d.name.clone(),
                declared_size: Some(d.declared),
                compressed_size: None,
            };
            let flow = walk.member(meta, &mut &d.bytes[..]);
            if (d.bytes.len() as u64) < d.declared {
                walk.hidden(Hidden::RowsNotRead);
            }
            if flow == Flow::Stop {
                walk.rest(to_offer);
                return Ok(());
            }
        }
        Ok(())
    }
}

/// Whether a rollback journal holds pages to roll back. One with a zeroed
/// header (`journal_mode=PERSIST`, after a commit) has none.
fn journal_is_live(path: &Path) -> bool {
    if !fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0) {
        return false;
    }
    let mut head = [0u8; 8];
    let read = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|f| f.read_exact_at(&mut head, 0));
    // A journal too short or unreadable to tell counts as holding pages.
    read.is_err() || head != [0u8; 8]
}

/// Record what the region just offered does not show.
fn mark(walk: &mut dyn Walk, sampled: bool, damaged: bool) {
    if damaged {
        walk.hidden(Hidden::PagesUnreadable);
    }
    if sampled {
        walk.hidden(Hidden::RowsNotRead);
    }
}

/// The table a schema row describes, when it stores rows in this file. A
/// virtual table has no pages of its own (its shadow tables are ordinary
/// tables), and a view's only data is its statement.
fn table_entry(db: &Db<'_>, e: &SchemaEntry, fits: bool, walk: &dyn Walk) -> Option<TableEntry> {
    if e.root == 0 && e.sql.as_deref().is_some_and(is_virtual) {
        return None;
    }
    // A root outside the file reads as a damaged page.
    let root = u32::try_from(e.root).unwrap_or(0);
    let columns = e
        .sql
        .as_deref()
        .filter(|s| s.len() <= SQL_PARSE_MAX)
        .map(stored_columns)
        .unwrap_or_default();
    Some(TableEntry {
        name: e.name.clone(),
        root,
        columns,
        // The order matters only when the tables must share the budget.
        size: if fits {
            0
        } else {
            estimated_size(db, root, walk)
        },
    })
}

fn is_virtual(sql: &str) -> bool {
    let t = tokens(sql);
    keyword(t.first(), "CREATE") && keyword(t.get(1), "VIRTUAL")
}

/// A token of a `CREATE` statement.
#[derive(Debug, PartialEq, Eq)]
enum Tok<'a> {
    /// An unquoted word: a keyword, a name, or a number.
    Word(&'a str),
    /// A quoted name or string, unescaped.
    Quoted(String),
    Sym(u8),
}

fn tokens(sql: &str) -> Vec<Tok<'_>> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80;
    while i < b.len() {
        let c = b[i];
        match c {
            c if c.is_ascii_whitespace() => i += 1,
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i += 2;
            }
            b'\'' | b'"' | b'`' | b'[' => {
                let close = if c == b'[' { b']' } else { c };
                i += 1;
                let mut q = Vec::new();
                while i < b.len() {
                    if b[i] == close {
                        if close != b']' && b.get(i + 1) == Some(&close) {
                            q.push(close);
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    q.push(b[i]);
                    i += 1;
                }
                i += 1;
                out.push(Tok::Quoted(String::from_utf8_lossy(&q).into_owned()));
            }
            c if is_word(c) => {
                let start = i;
                while i < b.len() && is_word(b[i]) {
                    i += 1;
                }
                out.push(Tok::Word(&sql[start..i]));
            }
            c => {
                out.push(Tok::Sym(c));
                i += 1;
            }
        }
    }
    out
}

fn keyword(t: Option<&Tok<'_>>, w: &str) -> bool {
    matches!(t, Some(Tok::Word(x)) if x.eq_ignore_ascii_case(w))
}

fn name_of(t: &Tok<'_>) -> Option<String> {
    match t {
        Tok::Word(w) => Some((*w).to_string()),
        Tok::Quoted(q) => Some(q.clone()),
        Tok::Sym(_) => None,
    }
}

/// The columns of a `CREATE TABLE` in the order a record stores them, which
/// leaves out virtual generated columns and, in a table without a rowid, puts
/// the primary key first. Empty when the statement does not parse: its fields
/// then go by position.
fn stored_columns(sql: &str) -> Vec<String> {
    let t = tokens(sql);
    let Some(open) = t.iter().position(|x| *x == Tok::Sym(b'(')) else {
        return Vec::new();
    };
    // The definitions between the outer parentheses, split at their commas.
    let mut defs: Vec<&[Tok<'_>]> = Vec::new();
    let mut depth = 1usize;
    let mut start = open + 1;
    let mut close = None;
    for (i, tok) in t.iter().enumerate().skip(open + 1) {
        match tok {
            Tok::Sym(b'(') => depth += 1,
            Tok::Sym(b')') => {
                depth -= 1;
                if depth == 0 {
                    defs.push(&t[start..i]);
                    close = Some(i);
                    break;
                }
            }
            Tok::Sym(b',') if depth == 1 => {
                defs.push(&t[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return Vec::new();
    };
    let tail = &t[close + 1..];
    let without_rowid = tail
        .windows(2)
        .any(|w| keyword(w.first(), "WITHOUT") && keyword(w.get(1), "ROWID"));

    let mut stored: Vec<String> = Vec::new();
    let mut key: Vec<String> = Vec::new();
    for def in defs {
        let Some(first) = def.first() else { continue };
        let constraint = ["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"]
            .iter()
            .any(|w| keyword(Some(first), w));
        if constraint {
            if let Some(at) = def.iter().position(|x| keyword(Some(x), "PRIMARY")) {
                key.extend(key_columns(&def[at..]));
            }
            continue;
        }
        let Some(name) = name_of(first) else {
            return Vec::new();
        };
        let (mut generated, mut virt_or_stored, mut primary) = (false, false, false);
        let mut d = 0usize;
        for (i, tok) in def.iter().enumerate().skip(1) {
            match tok {
                Tok::Sym(b'(') => d += 1,
                Tok::Sym(b')') => d = d.saturating_sub(1),
                _ if d > 0 => {}
                x if keyword(Some(x), "AS") && def.get(i + 1) == Some(&Tok::Sym(b'(')) => {
                    generated = true;
                }
                x if keyword(Some(x), "STORED") => virt_or_stored = true,
                x if keyword(Some(x), "PRIMARY") => primary = true,
                _ => {}
            }
        }
        if primary {
            key.push(name.clone());
        }
        // A generated column is virtual unless it says otherwise.
        if !generated || virt_or_stored {
            stored.push(name);
        }
    }
    if without_rowid {
        let mut ordered: Vec<String> = Vec::new();
        for k in &key {
            let found = stored.iter().find(|c| c.eq_ignore_ascii_case(k));
            if let Some(c) = found {
                if !ordered.iter().any(|o| o.eq_ignore_ascii_case(c)) {
                    ordered.push(c.clone());
                }
            }
        }
        for c in stored {
            if !ordered.iter().any(|o| o.eq_ignore_ascii_case(&c)) {
                ordered.push(c);
            }
        }
        return ordered;
    }
    stored
}

/// The column names of a `PRIMARY KEY (…)` constraint: at each comma of its
/// list, the first token names the column.
fn key_columns(def: &[Tok<'_>]) -> Vec<String> {
    let Some(open) = def.iter().position(|x| *x == Tok::Sym(b'(')) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut d = 1usize;
    let mut first = true;
    for tok in &def[open + 1..] {
        match tok {
            Tok::Sym(b'(') => d += 1,
            Tok::Sym(b')') => {
                d -= 1;
                if d == 0 {
                    break;
                }
            }
            Tok::Sym(b',') if d == 1 => first = true,
            x if first && d == 1 => {
                if let Some(n) = name_of(x) {
                    out.push(n);
                }
                first = false;
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_read_as_the_format_defines() {
        assert_eq!(varint(&[0x7F]), Some((127, 1)));
        assert_eq!(varint(&[0x81, 0x00]), Some((128, 2)));
        assert_eq!(varint(&[0xFF; 9]), Some((u64::MAX, 9)));
        assert_eq!(varint(&[0x81]), None);
        assert_eq!(varint(&[]), None);
    }

    #[test]
    fn negative_and_small_integers_decode() {
        assert_eq!(int_value(1, &[0xFF]), Some(-1));
        assert_eq!(int_value(2, &[0x01, 0x00]), Some(256));
        assert_eq!(int_value(8, &[]), Some(0));
        assert_eq!(int_value(9, &[]), Some(1));
        assert_eq!(int_value(13, b"x"), None);
    }

    fn cols(sql: &str) -> Vec<String> {
        stored_columns(sql)
    }

    #[test]
    fn column_names_parse_from_ordinary_statements() {
        assert_eq!(
            cols("CREATE TABLE t(a TEXT, \"b c\" INT DEFAULT (1, 2), [d] , `e``f` CHECK(a > 1))"),
            ["a", "b c", "d", "e`f"]
        );
        assert_eq!(cols("CREATE TABLE \"a(b\"(x, y)"), ["x", "y"]);
        assert_eq!(
            cols("CREATE TABLE t(a -- comment, not a column\n, /* b, */ c)"),
            ["a", "c"]
        );
        assert_eq!(
            cols("CREATE TABLE t(a, PRIMARY KEY(a), UNIQUE(a), CHECK(a), FOREIGN KEY(a) REFERENCES u(a), CONSTRAINT n CHECK(a))"),
            ["a"]
        );
        assert_eq!(cols("CREATE TABLE t(primary_id, checked, uniq)").len(), 3);
    }

    #[test]
    fn generated_columns_are_stored_only_when_they_say_so() {
        assert_eq!(
            cols("CREATE TABLE t(a, v AS (a || 'x'), w TEXT GENERATED ALWAYS AS (a) VIRTUAL, s AS (a) STORED, z)"),
            ["a", "s", "z"]
        );
    }

    #[test]
    fn a_table_without_a_rowid_stores_its_key_first() {
        assert_eq!(
            cols("CREATE TABLE t(a, b, c, PRIMARY KEY(c, a)) WITHOUT ROWID"),
            ["c", "a", "b"]
        );
        assert_eq!(
            cols("CREATE TABLE t(a, b TEXT PRIMARY KEY, c) WITHOUT ROWID"),
            ["b", "a", "c"]
        );
        assert_eq!(
            cols("CREATE TABLE t(a, b, CONSTRAINT k PRIMARY KEY(B DESC, a COLLATE nocase)) without rowid"),
            ["b", "a"]
        );
        // With a rowid, the stored order is the declared one.
        assert_eq!(cols("CREATE TABLE t(a, b, PRIMARY KEY(b))"), ["a", "b"]);
    }

    #[test]
    fn statements_that_do_not_parse_give_no_names() {
        assert!(cols("not a statement").is_empty());
        assert!(cols("CREATE TABLE t(a, b").is_empty());
        assert!(cols("").is_empty());
        assert_eq!(column_name(&[], 2), "?3");
    }

    #[test]
    fn names_split_into_table_and_column() {
        assert_eq!(name_part("a/b%c"), "a%2Fb%25c");
    }

    #[test]
    fn logs_are_told_from_databases_by_their_magic() {
        assert!(is_log(WAL_MAGIC[0]));
        assert!(is_log(WAL_MAGIC[1]));
        assert!(is_log(JOURNAL_MAGIC));
        assert!(!is_log(MAGIC));
    }
}
