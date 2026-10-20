//! The `git pre-commit` and `git install-hook` commands.
//!
//! Staged paths are raw bytes end to end. They are converted to text only for
//! the scanner (lossily) and for display (lossily, with control characters
//! escaped so one finding stays on one line).

use crate::cli::{GitCommand, HookArgs, PreCommitArgs};
use crate::scan::{repo_root_git, EXIT_OK, EXIT_THRESHOLD};
use crate::CliError;
use riskgrep_core::config::{self, Action, GitConfig, Mode, Overrides};
use riskgrep_core::model::round1;
use riskgrep_core::{RiskGrep, TargetReport, TargetStatus};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::ops::RangeInclusive;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Blobs larger than this are reported as unscanned rather than read.
const BLOB_MAX: u64 = 128 << 20;
/// At most this many line numbers are listed per finding.
const MAX_LINES: usize = 5;
const HOOK_BODY: &str = "#!/bin/sh\nexec riskgrep git pre-commit \"$@\"\n";
const GITLINK_MODE: &[u8] = b"160000";

pub fn run(cmd: GitCommand) -> Result<i32, CliError> {
    match cmd {
        GitCommand::PreCommit(a) => pre_commit(a),
        GitCommand::InstallHook(a) => install_hook(a),
    }
}

/// A staged addition, copy, modification, or rename, by its new path.
#[derive(Debug, PartialEq, Eq)]
struct Staged {
    path: Vec<u8>,
    /// The source path of a rename or copy, used to diff against it.
    from: Option<Vec<u8>>,
    /// Newly added: every line is an added line, so no diff is needed.
    added: bool,
}

fn git(root: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(root).arg("--literal-pathspecs");
    c
}

fn git_output(mut c: Command) -> Result<Vec<u8>, CliError> {
    let out = c
        .stdin(Stdio::null())
        .output()
        .map_err(|e| CliError(format!("cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(CliError(format!(
            "git failed: {}",
            String::from_utf8_lossy(&out.stderr).trim_end()
        )));
    }
    Ok(out.stdout)
}

/// Parse `git diff --cached --raw -z` output.
fn parse_raw(out: &[u8]) -> Vec<Staged> {
    let mut fields = out.split(|b| *b == 0).filter(|f| !f.is_empty());
    let mut staged = Vec::new();
    while let Some(meta) = fields.next() {
        if meta.first() != Some(&b':') {
            continue;
        }
        let status = meta.rsplit(|b| *b == b' ').next().unwrap_or_default();
        let added = status.first() == Some(&b'A');
        let two = matches!(status.first(), Some(b'R' | b'C'));
        let Some(first) = fields.next() else { break };
        if two {
            let Some(second) = fields.next() else { break };
            staged.push(Staged {
                path: second.to_vec(),
                from: Some(first.to_vec()),
                added,
            });
        } else {
            staged.push(Staged {
                path: first.to_vec(),
                from: None,
                added,
            });
        }
    }
    staged
}

/// Added line ranges from the `@@ -a,b +c,d @@` headers of a zero-context
/// diff. A header adding no lines contributes nothing. `None` when git
/// reports a binary change: it has no line ranges, so the whole file counts.
fn parse_hunks(diff: &[u8]) -> Option<Vec<RangeInclusive<u32>>> {
    let mut ranges = Vec::new();
    for line in diff.split(|b| *b == b'\n') {
        if line.starts_with(b"Binary files ") {
            return None;
        }
        let Some(rest) = line.strip_prefix(b"@@ ") else {
            continue;
        };
        let Ok(rest) = std::str::from_utf8(rest) else {
            continue;
        };
        let Some(plus) = rest.split(' ').find(|t| t.starts_with('+')) else {
            continue;
        };
        let spec = &plus[1..];
        let (start, count) = match spec.split_once(',') {
            Some((s, c)) => (s.parse::<u32>(), c.parse::<u32>()),
            None => (spec.parse::<u32>(), Ok(1)),
        };
        if let (Ok(start), Ok(count)) = (start, count) {
            if count > 0 && start > 0 {
                ranges.push(start..=start.saturating_add(count - 1));
            }
        }
    }
    Some(ranges)
}

/// Stage-0 index entries by path: `(mode, hex object id)`.
fn parse_index(out: &[u8]) -> HashMap<Vec<u8>, (Vec<u8>, String)> {
    let mut map = HashMap::new();
    for rec in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let Some(tab) = rec.iter().position(|b| *b == b'\t') else {
            continue;
        };
        let mut meta = rec[..tab].split(|b| *b == b' ');
        let (Some(mode), Some(id), Some(stage)) = (meta.next(), meta.next(), meta.next()) else {
            continue;
        };
        if stage == b"0" {
            if let Ok(id) = std::str::from_utf8(id) {
                map.insert(rec[tab + 1..].to_vec(), (mode.to_vec(), id.to_string()));
            }
        }
    }
    map
}

fn hex_to_bytes(h: &str) -> Option<Vec<u8>> {
    if !h.len().is_multiple_of(2) {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok())
        .collect()
}

/// One long-lived `git cat-file --batch` process.
struct Batch {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

enum Blob {
    Bytes(Vec<u8>),
    Missing,
    TooLarge,
}

impl Batch {
    fn spawn(root: &Path) -> Result<Batch, CliError> {
        let mut child = git(root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| CliError(format!("cannot run git cat-file: {e}")))?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        Ok(Batch {
            child,
            stdin,
            stdout,
        })
    }

    fn read(&mut self, id: &str) -> Result<Blob, CliError> {
        writeln!(self.stdin, "{id}")?;
        self.stdin.flush()?;
        let mut header = String::new();
        if self.stdout.read_line(&mut header)? == 0 {
            return Err(CliError("git cat-file ended unexpectedly".into()));
        }
        let fields: Vec<&str> = header.trim_end().split(' ').collect();
        if fields.len() == 2 && fields[1] == "missing" {
            return Ok(Blob::Missing);
        }
        let size: u64 = match fields.as_slice() {
            [_, "blob", size] => size.parse().ok(),
            _ => None,
        }
        .ok_or_else(|| CliError(format!("unexpected git cat-file response `{header:?}`")))?;
        if size > BLOB_MAX {
            // Drain the body and its trailing newline so the stream stays in step.
            io::copy(&mut (&mut self.stdout).take(size + 1), &mut io::sink())?;
            return Ok(Blob::TooLarge);
        }
        let mut buf = vec![0u8; size as usize];
        self.stdout.read_exact(&mut buf)?;
        let mut nl = [0u8; 1];
        self.stdout.read_exact(&mut nl)?;
        Ok(Blob::Bytes(buf))
    }

    fn finish(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn staged_files(root: &Path) -> Result<Vec<Staged>, CliError> {
    let mut c = git(root);
    c.args([
        "diff",
        "--cached",
        "--raw",
        "-z",
        "--find-renames",
        "--no-ext-diff",
        "--diff-filter=ACMR",
    ]);
    Ok(parse_raw(&git_output(c)?))
}

/// Added line ranges for every non-added staged entry, from ONE zero-context
/// diff. The patch is split on `diff --git ` lines (a content line always
/// starts with `+`, `-`, space, `@`, or `\`; a path with a newline is
/// C-quoted, so a header is one line) and sections are matched to entries by
/// order, which is the same path order as the `--raw` listing. If the counts
/// disagree every entry falls back to whole-file scoring (`None`).
fn added_lines(
    root: &Path,
    staged: &[Staged],
) -> Result<Vec<Option<Vec<RangeInclusive<u32>>>>, CliError> {
    let modified: Vec<usize> = (0..staged.len()).filter(|&i| !staged[i].added).collect();
    let mut out: Vec<Option<Vec<RangeInclusive<u32>>>> = vec![None; staged.len()];
    if modified.is_empty() {
        return Ok(out);
    }
    let mut c = git(root);
    c.args([
        "diff",
        "--cached",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--find-renames",
        "--diff-filter=MRC",
    ]);
    let patch = git_output(c)?;
    let sections = split_sections(&patch);
    if sections.len() == modified.len() {
        for (i, sec) in modified.into_iter().zip(sections) {
            out[i] = parse_hunks(sec);
        }
    }
    Ok(out)
}

/// The slices of `patch` starting at each `diff --git ` line.
fn split_sections(patch: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut pos = 0;
    for line in patch.split_inclusive(|b| *b == b'\n') {
        if line.starts_with(b"diff --git ") {
            starts.push(pos);
        }
        pos += line.len();
    }
    starts.push(patch.len());
    starts.windows(2).map(|w| &patch[w[0]..w[1]]).collect()
}

/// Lossy path text with control characters escaped.
fn display(path: &[u8]) -> String {
    let mut s = String::new();
    for ch in String::from_utf8_lossy(path).chars() {
        if ch.is_control() {
            let _ = write!(s, "{}", ch.escape_default());
        } else {
            s.push(ch);
        }
    }
    s
}

/// One line per category at or above its `block_at`, or `None` when the
/// target is under every threshold.
fn offences(path: &str, t: &TargetReport, git_cfg: &GitConfig) -> Vec<String> {
    let mut lines = Vec::new();
    for (cat, limit) in &git_cfg.block_at {
        let Some(&score) = t.scores.get(cat) else {
            continue;
        };
        if score < *limit {
            continue;
        }
        let mut rules = BTreeSet::new();
        let mut at = BTreeSet::new();
        for e in t.evidence.iter().filter(|e| &e.category == cat) {
            rules.insert(e.rule.as_str());
            at.extend(e.locations.iter().map(|l| l.line_start));
        }
        let mut detail = rules.into_iter().collect::<Vec<_>>().join(", ");
        if !at.is_empty() {
            let shown: Vec<String> = at.iter().take(MAX_LINES).map(u32::to_string).collect();
            let more = if at.len() > MAX_LINES { ", …" } else { "" };
            let _ = write!(detail, ", line {}{more}", shown.join(", "));
        }
        lines.push(format!(
            "riskgrep: {path}: {} {:.1} ({detail})",
            cat.0,
            round1(score)
        ));
    }
    lines
}

fn blocks(action: Action) -> bool {
    matches!(action, Action::Block | Action::Deny)
}

fn unscanned_line(path: &str, status: &str, reason: &str) -> String {
    format!("riskgrep: {path}: {status} ({reason})")
}

fn pre_commit(a: PreCommitArgs) -> Result<i32, CliError> {
    let root = repo_root_git().ok_or_else(|| CliError("not in a git repository".into()))?;
    let cfg = config::load(Mode::Git, Some(&root), Overrides::default())?;
    let git_cfg = cfg.git.clone();
    let full_files = a.full_files || git_cfg.full_files;

    let staged = staged_files(&root)?;
    if staged.is_empty() {
        return Ok(EXIT_OK);
    }
    let index = {
        let mut c = git(&root);
        c.args(["ls-files", "-s", "-z"]);
        parse_index(&git_output(c)?)
    };

    let ranges = if full_files {
        vec![None; staged.len()]
    } else {
        added_lines(&root, &staged)?
    };
    let mut rg = RiskGrep::new(cfg, Some(&root))?;
    let mut batch = Batch::spawn(&root)?;
    let mut messages: Vec<String> = Vec::new();
    let mut offended = false;

    let result = (|| -> Result<(), CliError> {
        for (f, only) in staged.iter().zip(&ranges) {
            let shown = display(&f.path);
            let name = String::from_utf8_lossy(&f.path).into_owned();
            let Some((mode, id)) = index.get(&f.path) else {
                if blocks(git_cfg.on_error) {
                    messages.push(unscanned_line(&shown, "not scanned", "not in the index"));
                }
                continue;
            };
            if mode == GITLINK_MODE {
                continue;
            }
            let bytes = match batch.read(id)? {
                Blob::Bytes(b) => b,
                miss @ (Blob::Missing | Blob::TooLarge) => {
                    if blocks(git_cfg.on_error) {
                        let why = if matches!(miss, Blob::Missing) {
                            "staged blob missing".to_string()
                        } else {
                            format!("staged blob larger than {BLOB_MAX} bytes")
                        };
                        messages.push(unscanned_line(&shown, "not scanned", &why));
                    }
                    continue;
                }
            };
            let blob_id = hex_to_bytes(id)
                .ok_or_else(|| CliError(format!("invalid object id for `{shown}`")))?;
            let t = rg.scan_blob(&name, &blob_id, &bytes, only.as_deref());
            match &t.status {
                TargetStatus::Unscanned { reason } if blocks(git_cfg.on_error) => {
                    messages.push(unscanned_line(&shown, "not scanned", reason));
                }
                TargetStatus::Skipped { reason } if blocks(git_cfg.on_skipped) => {
                    messages.push(unscanned_line(&shown, "skipped", reason));
                }
                _ => {}
            }
            let lines = offences(&shown, &t, &git_cfg);
            offended |= !lines.is_empty();
            messages.extend(lines);
        }
        Ok(())
    })();
    batch.finish();
    result?;

    if messages.is_empty() {
        return Ok(EXIT_OK);
    }
    let mut err = io::stderr().lock();
    for m in &messages {
        writeln!(err, "{m}")?;
    }
    if offended {
        writeln!(
            err,
            "To accept a reviewed finding: riskgrep baseline <path>"
        )?;
        writeln!(
            err,
            "To ignore a path: add it to [ignore] in .riskgrep.toml"
        )?;
    }
    Ok(EXIT_THRESHOLD)
}

fn hooks_dir() -> Result<PathBuf, CliError> {
    let mut c = Command::new("git");
    c.args(["rev-parse", "--git-path", "hooks"]);
    let out = git_output(c).map_err(|_| CliError("not in a git repository".into()))?;
    let s = String::from_utf8_lossy(&out);
    let p = PathBuf::from(s.trim_end_matches('\n'));
    Ok(if p.is_absolute() {
        p
    } else {
        std::env::current_dir()?.join(p)
    })
}

fn install_hook(a: HookArgs) -> Result<i32, CliError> {
    let dir = hooks_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("pre-commit");
    if a.force {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                CliError(format!(
                    "{} already exists; use --force to replace it",
                    path.display()
                ))
            } else {
                e.into()
            }
        })?;
    f.write_all(HOOK_BODY.as_bytes())?;
    drop(f);
    // The creation mode is subject to the umask.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    outln!("installed {}", path.display())?;
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunks() {
        let d = b"diff --git a/x b/x\n@@ -1,2 +1,0 @@\n@@ -5 +4,3 @@ ctx\n@@ -9,0 +12 @@\n";
        assert_eq!(parse_hunks(d), Some(vec![4..=6, 12..=12]));
        assert_eq!(
            parse_hunks(b"diff --git a/x b/x\nBinary files a/x and b/x differ\n"),
            None
        );
    }

    #[test]
    fn raw_parse() {
        let out = b":100644 100644 aaa bbb M\0a b\0:100644 100644 aaa bbb R087\0old\0new\0\
:000000 100644 000 ccc A\0n\nl\0";
        let s = parse_raw(out);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].path, b"a b");
        assert_eq!(s[1].path, b"new");
        assert_eq!(s[1].from.as_deref(), Some(&b"old"[..]));
        assert_eq!(s[2].path, b"n\nl");
    }

    #[test]
    fn index_parse() {
        let out = b"100644 abc 0\tp q\x00100644 def 1\tconflict\x00";
        let m = parse_index(out);
        assert_eq!(m.len(), 1);
        assert_eq!(m[&b"p q".to_vec()].1, "abc");
    }

    #[test]
    fn display_escapes_controls() {
        assert_eq!(display(b"a\nb\xff"), "a\\nb\u{fffd}");
    }

    #[test]
    fn hex() {
        assert_eq!(hex_to_bytes("0aff"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex_to_bytes("0af"), None);
    }
}
