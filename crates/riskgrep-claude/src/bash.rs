//! Which files a `Bash` tool command would read.
//!
//! The command is parsed into simple commands; every argument and every input
//! redirection target that names an existing regular file is a target. The
//! answer is marked `unresolved` whenever the command could read something the
//! parse cannot name: a word built from an expansion, a substitution whose
//! output becomes an argument, an interpreter or executor running code, a
//! change of directory, a directory argument, a parse failure, or the time
//! budget running out.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Files a shell command would read, and whether the answer is incomplete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BashTargets {
    /// Canonical paths of existing regular files the command names, in the
    /// order first seen, without duplicates.
    pub files: Vec<PathBuf>,
    /// True when the command may read files that are not in `files`.
    pub unresolved: bool,
}

/// Time [`bash_targets`] may spend before it stops and reports unresolved.
pub const DEFAULT_BUDGET: Duration = Duration::from_millis(500);

/// Glob matches one command may yield before the walk stops (unresolved).
const WALK_LIMIT: usize = 10_000;
/// Nesting of `sh -c` payloads, executors and substitution bodies analysed
/// recursively.
const MAX_DEPTH: usize = 16;
/// Commands longer than this are not parsed: the first this-many bytes get
/// the whitespace-split catch-all and the result is unresolved.
const MAX_COMMAND_BYTES: usize = 64 * 1024;
/// Stack of the thread the analysis runs on.
const ANALYSIS_STACK_BYTES: usize = 64 << 20;
/// Estimated nesting (see [`nesting_estimate`]) beyond which a command is not
/// parsed. brush-parser recurses once per level; on a 64 MiB stack 2,000
/// nested `if` statements parsed in a debug build and 4,000 in a release
/// build (measured 2026-10-19), so 256 leaves a wide margin.
const MAX_NESTING: usize = 256;
/// Words a single brace expansion may produce.
const MAX_BRACE_WORDS: usize = 1_000;
/// Words all brace expansions in one parse may produce together.
const MAX_TOTAL_BRACE_WORDS: usize = 10_000;

/// Returns the files `command` would read when run in `cwd`, spending at most
/// [`DEFAULT_BUDGET`].
pub fn bash_targets(command: &str, cwd: &Path) -> BashTargets {
    bash_targets_within(command, cwd, DEFAULT_BUDGET)
}

/// Like [`bash_targets`], but stops and reports unresolved once `budget` has
/// elapsed. A single parse cannot be interrupted; it is bounded by the
/// command-size and nesting limits instead.
pub fn bash_targets_within(command: &str, cwd: &Path, budget: Duration) -> BashTargets {
    let deadline = Instant::now() + budget;
    let owned_command = command.to_string();
    let owned_cwd = cwd.to_path_buf();
    // A deep parse recurses; a dedicated thread gives it a known stack.
    let worker = std::thread::Builder::new()
        .name("riskgrep-bash".to_string())
        .stack_size(ANALYSIS_STACK_BYTES)
        .spawn(move || {
            let mut st = State::new(&owned_cwd, deadline);
            analyze(&owned_command, 0, &mut st);
            st.finish()
        });
    match worker.map(|handle| handle.join()) {
        Ok(Ok(targets)) => targets,
        // The thread could not start or panicked: whitespace split only.
        _ => {
            let mut st = State::new(cwd, deadline);
            st.fallback(command);
            st.finish()
        }
    }
}

// ---------------------------------------------------------------------------
// Intermediate form produced by the parser front-end (`front`).

/// One word after quote removal and brace expansion, before globbing.
#[derive(Debug)]
enum Word {
    /// The word's possible spellings (more than one after brace expansion).
    Resolved(Vec<Cand>),
    /// The word depends on an expansion; its value is unknown.
    Unresolved,
}

#[derive(Debug)]
struct Cand {
    /// The literal value.
    text: String,
    /// A `glob` pattern when the word holds unquoted glob characters; quoted
    /// parts are escaped in it.
    pattern: Option<String>,
}

#[derive(Debug, Default)]
struct Simple {
    /// False for word lists that are not a command line (`for` values).
    is_command: bool,
    words: Vec<Word>,
    /// Targets of `<`, `0<` and `<>`.
    reads: Vec<Word>,
}

#[derive(Debug, Default)]
struct Ir {
    cmds: Vec<Simple>,
    unresolved: bool,
    /// Substitution bodies to analyse as commands of their own.
    nested: Vec<String>,
}

/// Builds one candidate spelling piece by piece.
#[derive(Default)]
struct CandBuf {
    text: String,
    pattern: String,
    has_glob: bool,
}

impl CandBuf {
    fn quoted(&mut self, s: &str) {
        self.text.push_str(s);
        self.pattern.push_str(&glob::Pattern::escape(s));
    }

    fn unquoted(&mut self, s: &str) {
        self.text.push_str(s);
        for ch in s.chars() {
            match ch {
                '*' | '?' | '[' => {
                    self.has_glob = true;
                    self.pattern.push(ch);
                }
                ']' => self.pattern.push(ch),
                _ => self
                    .pattern
                    .push_str(&glob::Pattern::escape(&ch.to_string())),
            }
        }
    }

    fn finish(self) -> Cand {
        Cand {
            pattern: self.has_glob.then_some(self.pattern),
            text: self.text,
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis of the parsed form.

/// What a path turned out to be, cached per absolute path.
#[derive(Clone)]
enum Probe {
    File(PathBuf),
    Dir,
    Other,
}

struct State<'a> {
    cwd: &'a Path,
    deadline: Instant,
    files: Vec<PathBuf>,
    seen: HashSet<PathBuf>,
    probed: HashMap<PathBuf, Probe>,
    unresolved: bool,
    glob_budget: usize,
}

impl<'a> State<'a> {
    fn new(cwd: &'a Path, deadline: Instant) -> Self {
        State {
            cwd,
            deadline,
            files: Vec::new(),
            seen: HashSet::new(),
            probed: HashMap::new(),
            unresolved: false,
            glob_budget: WALK_LIMIT,
        }
    }

    fn finish(self) -> BashTargets {
        BashTargets {
            files: self.files,
            unresolved: self.unresolved,
        }
    }

    /// True (and the result unresolved) once the time budget is spent.
    fn out_of_time(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            self.unresolved = true;
            true
        } else {
            false
        }
    }

    /// The catch-all over a whitespace split of the first
    /// [`MAX_COMMAND_BYTES`] bytes, for commands that are not parsed.
    fn fallback(&mut self, src: &str) {
        self.unresolved = true;
        let mut end = src.len().min(MAX_COMMAND_BYTES);
        while !src.is_char_boundary(end) {
            end -= 1;
        }
        for word in src[..end].split_whitespace() {
            if self.out_of_time() {
                return;
            }
            self.add_literal(word, true);
        }
    }
}

fn analyze(src: &str, depth: usize, st: &mut State) {
    if depth > MAX_DEPTH || st.out_of_time() {
        st.unresolved = true;
        return;
    }
    let ir = if src.len() > MAX_COMMAND_BYTES || nesting_estimate(src) > MAX_NESTING {
        None
    } else {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| front::parse(src))).unwrap_or(None)
    };
    let Some(ir) = ir else {
        st.fallback(src);
        return;
    };
    st.unresolved |= ir.unresolved;
    for cmd in &ir.cmds {
        if st.out_of_time() {
            return;
        }
        handle_simple(cmd, depth, st);
    }
    for body in &ir.nested {
        analyze(body, depth + 1, st);
    }
}

/// An upper estimate of how deeply `src` nests, ignoring quoting. Brackets
/// count one level; `if`, `while`, `until`, `for`, `select` and `case` count
/// two (the construct and its `then`/`do` body). Used only to refuse input
/// that could exhaust the parser's stack.
fn nesting_estimate(src: &str) -> usize {
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let (mut depth, mut max) = (0usize, 0usize);
    let mut push = |stack: &mut Vec<(u8, usize)>, depth: &mut usize, kind: u8, weight: usize| {
        stack.push((kind, weight));
        *depth += weight;
        max = max.max(*depth);
    };
    let pop = |stack: &mut Vec<(u8, usize)>, depth: &mut usize, kind: u8| {
        if let Some(pos) = stack.iter().rposition(|(k, _)| *k == kind) {
            for (_, weight) in stack.drain(pos..) {
                *depth -= weight;
            }
        }
    };
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            match &src[start..i] {
                "if" => push(&mut stack, &mut depth, b'i', 2),
                "while" | "until" | "for" | "select" => push(&mut stack, &mut depth, b'l', 2),
                "case" => push(&mut stack, &mut depth, b'c', 2),
                "fi" => pop(&mut stack, &mut depth, b'i'),
                "done" => pop(&mut stack, &mut depth, b'l'),
                "esac" => pop(&mut stack, &mut depth, b'c'),
                _ => {}
            }
            continue;
        }
        match b {
            b'(' | b'[' => push(&mut stack, &mut depth, b'(', 1),
            b'{' => push(&mut stack, &mut depth, b'{', 1),
            b')' | b']' => pop(&mut stack, &mut depth, b'('),
            b'}' => pop(&mut stack, &mut depth, b'{'),
            _ => {}
        }
        i += 1;
    }
    max
}

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash"];
const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "ruby", "perl", "php", "deno", "bun", "npx", "tsx", "ts-node",
];
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "nice", "time", "command", "exec", "builtin", "stdbuf",
    "timeout",
];
/// Commands that change the directory later relative paths resolve against,
/// or read and run a file in the current shell.
const CONTEXT_CHANGERS: &[&str] = &["cd", "pushd", "popd", "source", "."];
/// `git` subcommands that print repository content not named as a path.
const GIT_READERS: &[&str] = &[
    "show", "cat-file", "archive", "grep", "blame", "diff", "log", "stash",
];

/// Commands whose first operand is a pattern, filter or script rather than
/// a path, so `jq . f` or `grep . f` is not a directory argument.
const PATTERN_FIRST: &[&str] = &[
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "jq", "yq", "sed", "awk", "gawk",
];

/// Index of a command's pattern operand, if it has one: the first word
/// after the name that is not an option, unless the pattern was given with
/// `-e`/`-f`.
fn pattern_position(words: &[Word]) -> Option<usize> {
    let name = literal(words.first())?;
    if !PATTERN_FIRST.contains(&base_name(&name)) {
        return None;
    }
    let mut position = None;
    for (i, w) in words.iter().enumerate().skip(1) {
        let text = literal(Some(w))?;
        if matches!(
            text.as_str(),
            "-e" | "-f" | "--regexp" | "--file" | "--expression"
        ) || text.starts_with("--regexp=")
            || text.starts_with("--file=")
            || text.starts_with("--expression=")
        {
            return None;
        }
        if position.is_none() && !text.starts_with('-') {
            position = Some(i);
        }
    }
    position
}

fn handle_simple(cmd: &Simple, depth: usize, st: &mut State) {
    let is_dd = cmd.is_command && literal(cmd.words.first()).as_deref() == Some("dd");
    let pattern_at = if cmd.is_command {
        pattern_position(&cmd.words)
    } else {
        None
    };
    for (i, word) in cmd.words.iter().enumerate() {
        // Neither the command name (`. file`) nor a pattern operand is a
        // directory argument.
        let not_a_path = cmd.is_command && i == 0 || pattern_at == Some(i);
        st.add_word(word, is_dd, !not_a_path);
    }
    for word in &cmd.reads {
        st.add_word(word, false, true);
    }
    if cmd.is_command {
        classify(&cmd.words, depth, st);
    }
}

/// The word's single literal spelling, if it has exactly one.
fn literal(word: Option<&Word>) -> Option<String> {
    match word? {
        Word::Resolved(cands) if cands.len() == 1 => Some(cands[0].text.clone()),
        _ => None,
    }
}

fn base_name(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// Joins literal words with spaces; any other word makes the result
/// unresolved and is left out.
fn join_literals(words: &[Word], st: &mut State) -> String {
    let mut line = String::new();
    for w in words {
        match literal(Some(w)) {
            Some(text) => {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(&text);
            }
            None => st.unresolved = true,
        }
    }
    line
}

/// Index of the first word after leading options, where `takes_value`
/// says which options consume the next word. `--` ends the options.
fn skip_options(words: &[Word], takes_value: impl Fn(&str) -> bool) -> usize {
    let mut i = 0;
    while let Some(arg) = literal(words.get(i)) {
        if arg == "--" {
            return i + 1;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        i += if takes_value(&arg) { 2 } else { 1 };
    }
    i.min(words.len())
}

/// Classifies one command line: recurses into commands it runs, and marks
/// the result unresolved for interpreters, executors and context changers.
fn classify(words: &[Word], depth: usize, st: &mut State) {
    if depth > MAX_DEPTH {
        st.unresolved = true;
        return;
    }
    let mut i = 0;
    let mut privileged = false;
    // Skip wrappers such as `sudo -u root` or `env X=1`.
    while let Some(name) = literal(words.get(i)) {
        let name = base_name(&name).to_string();
        if !WRAPPERS.contains(&name.as_str()) {
            break;
        }
        privileged |= name == "sudo" || name == "doas";
        i += 1;
        while let Some(arg) = literal(words.get(i)) {
            // `env -S STRING` splits STRING into the command line it runs.
            let split = if name == "env" && (arg == "-S" || arg == "--split-string") {
                Some((literal(words.get(i + 1)), i + 2))
            } else if name == "env" {
                arg.strip_prefix("--split-string=")
                    .map(|v| (Some(v.to_string()), i + 1))
            } else {
                None
            };
            if let Some((value, rest_at)) = split {
                let Some(value) = value else {
                    st.unresolved = true;
                    return;
                };
                let rest = join_literals(words.get(rest_at..).unwrap_or(&[]), st);
                analyze(&format!("{value} {rest}"), depth + 1, st);
                return;
            }
            let takes_value = matches!(
                (name.as_str(), arg.as_str()),
                (
                    "sudo" | "doas",
                    "-u" | "-g" | "-C" | "-D" | "-h" | "-p" | "-r" | "-t" | "-U"
                ) | ("nice", "-n")
                    | ("env", "-u" | "-C")
            );
            if arg.starts_with('-') && arg != "-" {
                i += if takes_value { 2 } else { 1 };
            } else if name == "env" && arg.contains('=') {
                i += 1;
            } else {
                break;
            }
        }
        if name == "timeout" && literal(words.get(i)).is_some() {
            i += 1; // the duration
        }
    }
    let Some(name) = literal(words.get(i)) else {
        return;
    };
    let name = base_name(&name).to_string();
    let rest = &words[i + 1..];
    match name.as_str() {
        n if SHELLS.contains(&n) => {
            if privileged {
                st.unresolved = true;
            }
            shell_invocation(rest, depth, st);
        }
        n if CONTEXT_CHANGERS.contains(&n) => st.unresolved = true,
        "eval" => {
            let line = join_literals(rest, st);
            analyze(&line, depth + 1, st);
        }
        "trap" => {
            st.unresolved = true;
            if let Some(action) = literal(rest.first()) {
                analyze(&action, depth + 1, st);
            }
        }
        "watch" => {
            // watch runs its arguments, joined, with `sh -c`.
            st.unresolved = true;
            let at = skip_options(rest, |o| {
                matches!(o, "-n" | "--interval" | "-q" | "--equexit")
            });
            let line = join_literals(&rest[at..], st);
            analyze(&line, depth + 1, st);
        }
        "xargs" | "parallel" => {
            st.unresolved = true;
            let at = skip_options(rest, |o| {
                matches!(
                    o,
                    "-a" | "-d"
                        | "-E"
                        | "-I"
                        | "-L"
                        | "-n"
                        | "-P"
                        | "-s"
                        | "-j"
                        | "--arg-file"
                        | "--delimiter"
                        | "--max-args"
                        | "--max-procs"
                        | "--max-lines"
                        | "--jobs"
                )
            });
            classify(&rest[at..], depth + 1, st);
        }
        "su" => {
            st.unresolved = true;
            let mut j = 0;
            while j < rest.len() {
                let arg = literal(rest.get(j)).unwrap_or_default();
                let payload = match arg.as_str() {
                    "-c" | "--command" => literal(rest.get(j + 1)),
                    _ => arg.strip_prefix("--command=").map(str::to_string),
                };
                if let Some(payload) = payload {
                    analyze(&payload, depth + 1, st);
                }
                j += 1;
            }
        }
        "find" => find_exec(rest, depth, st),
        "git" => {
            let at = skip_options(rest, |o| {
                matches!(o, "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace")
            });
            if literal(rest.get(at)).is_some_and(|sub| GIT_READERS.contains(&sub.as_str())) {
                st.unresolved = true;
            }
        }
        // These search the working directory when given no path.
        "rg" | "ag" | "ack" | "ugrep" => {
            if search_operands(rest, RG_VALUE_SHORT).is_none_or(|s| s.paths == 0) {
                st.unresolved = true;
            }
        }
        // grep reads stdin without a path unless it recurses.
        "grep" | "egrep" | "fgrep" => {
            if search_operands(rest, GREP_VALUE_SHORT).is_none_or(|s| s.recursive && s.paths == 0) {
                st.unresolved = true;
            }
        }
        n if n.starts_with("python")
            || INTERPRETERS.contains(&n)
            || (n == "uv" && literal(rest.first()).as_deref() == Some("run")) =>
        {
            st.unresolved = true;
        }
        _ => {}
    }
}

/// Short options that take a value, per search tool.
const GREP_VALUE_SHORT: &[char] = &['e', 'f', 'm', 'A', 'B', 'C', 'd', 'D'];
const RG_VALUE_SHORT: &[char] = &[
    'e', 'f', 'g', 't', 'T', 'm', 'A', 'B', 'C', 'j', 'M', 'E', 'r',
];
/// Long options that take a separate value (rg and grep).
const SEARCH_VALUE_LONG: &[&str] = &[
    "--regexp",
    "--file",
    "--glob",
    "--iglob",
    "--type",
    "--type-not",
    "--max-count",
    "--context",
    "--after-context",
    "--before-context",
    "--threads",
    "--replace",
    "--max-columns",
    "--encoding",
    "--sort",
    "--sortr",
    "--directories",
    "--devices",
];

struct SearchOperands {
    /// Path operands given (positionals other than the pattern).
    paths: usize,
    /// `-r`, `-R` or `--recursive` was given.
    recursive: bool,
}

/// Counts the path operands of a grep-like command; `None` when a word is
/// not literal.
fn search_operands(args: &[Word], value_short: &[char]) -> Option<SearchOperands> {
    let mut pattern_given = false;
    let mut recursive = false;
    let mut positionals = 0usize;
    let mut options_done = false;
    let mut j = 0;
    while j < args.len() {
        let arg = literal(args.get(j))?;
        j += 1;
        if options_done || !arg.starts_with('-') || arg == "-" {
            positionals += 1;
            continue;
        }
        if arg == "--" {
            options_done = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            recursive |= matches!(name, "recursive" | "dereference-recursive");
            pattern_given |= matches!(name, "regexp" | "file");
            if !long.contains('=') && SEARCH_VALUE_LONG.contains(&arg.as_str()) {
                j += 1;
            }
        } else {
            // A cluster such as `-rn`, `-e PATTERN` or `-ePATTERN`.
            for (k, ch) in arg[1..].char_indices() {
                if value_short.contains(&ch) {
                    pattern_given |= ch == 'e' || ch == 'f';
                    if k + ch.len_utf8() == arg.len() - 1 {
                        j += 1; // the value is the next word
                    }
                    break;
                }
                recursive |= ch == 'r' || ch == 'R';
            }
        }
    }
    let paths = if pattern_given {
        positionals
    } else {
        positionals.saturating_sub(1)
    };
    Some(SearchOperands { paths, recursive })
}

/// `find ... -exec CMD ;` runs CMD on files it finds: unresolved, and any
/// command line given literally is classified (`-exec sh -c '...' \;`).
fn find_exec(args: &[Word], depth: usize, st: &mut State) {
    let mut j = 0;
    while j < args.len() {
        let is_exec = literal(args.get(j))
            .is_some_and(|a| matches!(a.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"));
        j += 1;
        if !is_exec {
            continue;
        }
        st.unresolved = true;
        let start = j;
        while j < args.len() && !literal(args.get(j)).is_some_and(|a| a == ";" || a == "+") {
            j += 1;
        }
        classify(&args[start..j], depth + 1, st);
    }
}

/// `sh -c PAYLOAD` is analysed recursively; a shell running a script file or
/// reading its program from standard input is unresolved.
fn shell_invocation(args: &[Word], depth: usize, st: &mut State) {
    let mut c_flag = false;
    let mut j = 0;
    while j < args.len() {
        let Some(arg) = literal(args.get(j)) else {
            break;
        };
        if arg == "--" {
            j += 1;
            break;
        }
        let is_option = (arg.starts_with('-') || arg.starts_with('+')) && arg.len() > 1;
        if !is_option {
            break;
        }
        if !arg.starts_with("--") {
            let flags = &arg[1..];
            if flags.contains('c') {
                c_flag = true;
            }
            if flags.ends_with('o') || flags.ends_with('O') {
                j += 1; // `-o pipefail`
            }
        }
        j += 1;
    }
    match args.get(j) {
        Some(Word::Resolved(cands)) if c_flag && cands.len() == 1 => {
            analyze(&cands[0].text, depth + 1, st);
        }
        // A script file, or the program read from standard input (a
        // here-document, a pipe, the terminal): not analysed here.
        _ => st.unresolved = true,
    }
}

impl State<'_> {
    /// Adds the files a word names. With `dirs_unresolve`, a word naming a
    /// directory marks the result unresolved (directories are not walked).
    fn add_word(&mut self, word: &Word, is_dd: bool, dirs_unresolve: bool) {
        let Word::Resolved(cands) = word else {
            self.unresolved = true;
            return;
        };
        for cand in cands {
            match &cand.pattern {
                Some(pattern) => self.add_glob(pattern, &cand.text),
                None => {
                    self.add_literal(&cand.text, dirs_unresolve);
                    if cand.text.starts_with('-') || (is_dd && cand.text.starts_with("if=")) {
                        if let Some((_, value)) = cand.text.split_once('=') {
                            self.add_literal(value, dirs_unresolve);
                        }
                    }
                }
            }
        }
    }

    fn add_literal(&mut self, text: &str, dirs_unresolve: bool) {
        if text.is_empty() || text.contains('\0') {
            return;
        }
        let path = Path::new(text);
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        };
        self.add_path(full, dirs_unresolve);
    }

    fn add_path(&mut self, path: PathBuf, dirs_unresolve: bool) {
        let probe = match self.probed.get(&path) {
            Some(probe) => probe.clone(),
            None => {
                let probe = match std::fs::metadata(&path) {
                    Ok(meta) if meta.is_file() => {
                        Probe::File(std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone()))
                    }
                    Ok(meta) if meta.is_dir() => Probe::Dir,
                    _ => Probe::Other,
                };
                self.probed.insert(path, probe.clone());
                probe
            }
        };
        match probe {
            Probe::File(canon) => {
                if self.seen.insert(canon.clone()) {
                    self.files.push(canon);
                }
            }
            Probe::Dir if dirs_unresolve => self.unresolved = true,
            Probe::Dir | Probe::Other => {}
        }
    }

    fn add_glob(&mut self, pattern: &str, text: &str) {
        if pattern.contains("**") {
            // A recursive walk; not attempted.
            self.unresolved = true;
            return;
        }
        let full = if pattern.starts_with('/') {
            pattern.to_string()
        } else {
            let Some(cwd) = self.cwd.to_str() else {
                self.unresolved = true;
                return;
            };
            format!(
                "{}/{}",
                glob::Pattern::escape(cwd.trim_end_matches('/')),
                pattern
            )
        };
        let options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: true,
        };
        let Ok(paths) = glob::glob_with(&full, options) else {
            // Not a valid pattern: the shell passes it through literally.
            self.add_literal(text, true);
            return;
        };
        for entry in paths {
            if self.glob_budget == 0 || self.out_of_time() {
                self.unresolved = true;
                return;
            }
            self.glob_budget -= 1;
            if let Ok(path) = entry {
                self.add_path(path, true);
            }
        }
    }
}

/// `$HOME` for `~` expansion; `None` when unset or empty.
fn home_dir() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| !h.is_empty())
}

/// Removes backslash-newline pairs outside single quotes, as bash does
/// before tokenizing.
fn remove_line_continuations(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_single = false;
    while let Some(c) = chars.next() {
        if in_single {
            in_single = c != '\'';
            out.push(c);
        } else if c == '\'' {
            in_single = true;
            out.push(c);
        } else if c == '\\' {
            match chars.next() {
                Some('\n') => {}
                Some(e) => {
                    out.push(c);
                    out.push(e);
                }
                None => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Decodes the body of an ANSI-C quoted string (`$'...'`).
fn decode_ansi_c(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(e) = chars.next() else {
            out.push('\\');
            break;
        };
        let mut radix_digits = |radix: u32, max: usize, first: Option<char>| {
            let mut value = 0u32;
            let mut n = 0;
            if let Some(d) = first.and_then(|d| d.to_digit(radix)) {
                value = d;
                n = 1;
            }
            while n < max {
                match chars.peek().and_then(|d| d.to_digit(radix)) {
                    Some(d) => {
                        value = value * radix + d;
                        chars.next();
                        n += 1;
                    }
                    None => break,
                }
            }
            (value, n)
        };
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'e' | 'E' => out.push('\x1b'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            '\\' | '\'' | '"' | '?' => out.push(e),
            'x' => {
                let (v, n) = radix_digits(16, 2, None);
                if n == 0 {
                    out.push_str("\\x");
                } else if let Some(ch) = char::from_u32(v) {
                    out.push(ch);
                }
            }
            'u' | 'U' => {
                let (v, n) = radix_digits(16, if e == 'u' { 4 } else { 8 }, None);
                if n == 0 {
                    out.push('\\');
                    out.push(e);
                } else if let Some(ch) = char::from_u32(v) {
                    out.push(ch);
                }
            }
            '0'..='7' => {
                let (v, _) = radix_digits(8, 3, Some(e));
                if let Some(ch) = char::from_u32(v & 0xff) {
                    out.push(ch);
                }
            }
            'c' => {
                if let Some(ch) = chars.next() {
                    out.push(char::from((ch as u8) & 0x1f));
                }
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Front-end: brush-parser.

mod front {
    use super::{
        decode_ansi_c, home_dir, remove_line_continuations, CandBuf, Ir, Simple, Word,
        MAX_BRACE_WORDS, MAX_TOTAL_BRACE_WORDS,
    };
    use brush_parser::ast::{
        self, Command, CommandPrefixOrSuffixItem as Item, CompoundCommand, CompoundList,
        IoFileRedirectKind, IoFileRedirectTarget, IoRedirect,
    };
    use brush_parser::word::{
        self, BraceExpressionMember, BraceExpressionOrText, TildeExpr, WordPiece,
        WordPieceWithSource,
    };
    use brush_parser::{Parser, ParserOptions};

    /// Parses `src`; `None` on a parse error.
    pub(super) fn parse(src: &str) -> Option<Ir> {
        let options = ParserOptions::default();
        let mut source = src.to_string();
        let program = match Parser::new(source.as_bytes(), &options).parse_program() {
            Ok(program) => program,
            // brush-parser rejects a line continuation inside an operator
            // (`2>\<newline>&1`); bash removes those before tokenizing.
            Err(_) if src.contains("\\\n") => {
                source = remove_line_continuations(src);
                Parser::new(source.as_bytes(), &options)
                    .parse_program()
                    .ok()?
            }
            Err(_) => return None,
        };
        let mut w = Walker {
            ir: Ir::default(),
            options,
            source: source.chars().collect(),
            brace_budget: MAX_TOTAL_BRACE_WORDS,
        };
        for list in &program.complete_commands {
            w.list(list);
        }
        Some(w.ir)
    }

    struct Walker {
        ir: Ir,
        options: ParserOptions,
        /// The text that was parsed, by character, for checking source
        /// positions (brush-parser counts characters, not bytes).
        source: Vec<char>,
        /// Brace-expansion words this parse may still produce.
        brace_budget: usize,
    }

    /// How expansions inside a word affect the result.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        /// An argument: an expansion makes the result unresolved.
        Argument,
        /// An assignment value or here-document body: only substitution
        /// bodies matter (their commands run).
        BodiesOnly,
    }

    impl Walker {
        fn list(&mut self, list: &CompoundList) {
            for item in &list.0 {
                let and_or = &item.0;
                self.pipeline(&and_or.first);
                for next in &and_or.additional {
                    match next {
                        ast::AndOr::And(p) | ast::AndOr::Or(p) => self.pipeline(p),
                    }
                }
            }
        }

        fn pipeline(&mut self, p: &ast::Pipeline) {
            for cmd in &p.seq {
                self.command(cmd);
            }
        }

        fn command(&mut self, cmd: &Command) {
            match cmd {
                Command::Simple(s) => self.simple(s),
                Command::Compound(c, redirects) => {
                    self.compound(c);
                    self.redirect_list(redirects.as_ref());
                }
                Command::Function(f) => {
                    self.compound(&f.body.0);
                    self.redirect_list(f.body.1.as_ref());
                }
                Command::ExtendedTest(test, redirects) => {
                    self.extended_test(&test.expr);
                    self.redirect_list(redirects.as_ref());
                }
            }
        }

        /// Redirections on a compound command, recorded as a command of
        /// their own so `{ ...; } < file` still names `file`.
        fn redirect_list(&mut self, redirects: Option<&ast::RedirectList>) {
            if let Some(r) = redirects {
                let mut sink = Simple::default();
                for redirect in &r.0 {
                    self.redirect(redirect, &mut sink);
                }
                self.ir.cmds.push(sink);
            }
        }

        fn extended_test(&mut self, expr: &ast::ExtendedTestExpr) {
            use ast::ExtendedTestExpr as E;
            match expr {
                E::And(a, b) | E::Or(a, b) => {
                    self.extended_test(a);
                    self.extended_test(b);
                }
                E::Not(a) | E::Parenthesized(a) => self.extended_test(a),
                E::UnaryTest(_, w) => {
                    self.word(w, Mode::Argument);
                }
                E::BinaryTest(_, a, b) => {
                    self.word(a, Mode::Argument);
                    self.word(b, Mode::Argument);
                }
            }
        }

        fn compound(&mut self, c: &CompoundCommand) {
            match c {
                CompoundCommand::Arithmetic(a) => {
                    // brush-parser 0.4.0 also reads `( ( cmd ) )` (nested
                    // subshells, spaced) as an arithmetic command. Bash
                    // treats only an unbroken `((` as arithmetic, so a
                    // spaced one is analysed as the commands it holds.
                    let value = &a.expr.value;
                    self.arithmetic_substitutions(value);
                    let start = a.loc.start.index;
                    let unbroken = self.source.get(start..start + 2) == Some(&['(', '('][..]);
                    if !unbroken {
                        self.ir.nested.push(value.clone());
                    } else if !value.contains(['$', '`'])
                        && brush_parser::arithmetic::parse(value).is_err()
                    {
                        // `((cat x) )`: bash runs nested subshells, but
                        // brush-parser has dropped a parenthesis, so the
                        // structure is uncertain.
                        self.ir.unresolved = true;
                        self.ir.nested.push(value.clone());
                    }
                }
                CompoundCommand::ArithmeticForClause(f) => {
                    let parts = [&f.initializer, &f.condition, &f.updater];
                    for expr in parts.into_iter().flatten() {
                        self.arithmetic_substitutions(&expr.value);
                    }
                    self.list(&f.body.list);
                }
                CompoundCommand::BraceGroup(g) => self.list(&g.list),
                CompoundCommand::Subshell(s) => self.list(&s.list),
                CompoundCommand::ForClause(f) => {
                    if let Some(values) = &f.values {
                        let words = values
                            .iter()
                            .map(|v| self.word(v, Mode::Argument))
                            .collect();
                        self.ir.cmds.push(Simple {
                            words,
                            ..Simple::default()
                        });
                    }
                    self.list(&f.body.list);
                }
                CompoundCommand::CaseClause(c) => {
                    self.word(&c.value, Mode::Argument);
                    for item in &c.cases {
                        if let Some(cmd) = &item.cmd {
                            self.list(cmd);
                        }
                    }
                }
                CompoundCommand::IfClause(i) => {
                    self.list(&i.condition);
                    self.list(&i.then);
                    for e in i.elses.iter().flatten() {
                        if let Some(cond) = &e.condition {
                            self.list(cond);
                        }
                        self.list(&e.body);
                    }
                }
                CompoundCommand::WhileClause(w) | CompoundCommand::UntilClause(w) => {
                    self.list(&w.0);
                    self.list(&w.1.list);
                }
                CompoundCommand::Coprocess(c) => self.command(&c.body),
            }
        }

        fn simple(&mut self, s: &ast::SimpleCommand) {
            let mut out = Simple {
                is_command: true,
                ..Simple::default()
            };
            let prefix = s.prefix.iter().flat_map(|p| p.0.iter());
            for item in prefix {
                self.item(item, true, &mut out);
            }
            if let Some(name) = &s.word_or_name {
                let w = self.word(name, Mode::Argument);
                out.words.push(w);
            }
            for item in s.suffix.iter().flat_map(|p| p.0.iter()) {
                self.item(item, false, &mut out);
            }
            self.ir.cmds.push(out);
        }

        fn item(&mut self, item: &Item, in_prefix: bool, out: &mut Simple) {
            match item {
                Item::IoRedirect(r) => self.redirect(r, out),
                Item::Word(w) => {
                    let w = self.word(w, Mode::Argument);
                    out.words.push(w);
                }
                Item::AssignmentWord(_, w) if !in_prefix => {
                    // After the command name `name=value` is an ordinary
                    // argument (`dd if=disk.img`).
                    let w = self.word(w, Mode::Argument);
                    out.words.push(w);
                }
                Item::AssignmentWord(_, w) => {
                    // `X=value cmd`: the value is not an argument, but any
                    // substitution in it runs.
                    let value = w.value.split_once('=').map_or("", |(_, v)| v);
                    let value = ast::Word {
                        value: value.to_string(),
                        loc: None,
                    };
                    self.word(&value, Mode::BodiesOnly);
                }
                Item::ProcessSubstitution(_, sub) => {
                    self.ir.unresolved = true;
                    self.list(&sub.list);
                }
            }
        }

        fn redirect(&mut self, r: &IoRedirect, out: &mut Simple) {
            match r {
                IoRedirect::File(_, kind, target) => match target {
                    IoFileRedirectTarget::Filename(w) => {
                        let w = self.word(w, Mode::Argument);
                        if matches!(
                            kind,
                            IoFileRedirectKind::Read | IoFileRedirectKind::ReadAndWrite
                        ) {
                            out.reads.push(w);
                        }
                    }
                    IoFileRedirectTarget::ProcessSubstitution(_, sub) => {
                        self.ir.unresolved = true;
                        self.list(&sub.list);
                    }
                    IoFileRedirectTarget::Fd(_) | IoFileRedirectTarget::Duplicate(_) => {}
                },
                IoRedirect::HereDocument(_, doc) => {
                    // The body is text, not a file read; only substitutions
                    // in an unquoted body run.
                    if doc.requires_expansion {
                        if let Ok(pieces) = word::parse_heredoc(&doc.doc.value, &self.options) {
                            let mut buf = CandBuf::default();
                            self.pieces(&pieces, false, Mode::BodiesOnly, &mut buf);
                        }
                    }
                }
                IoRedirect::HereString(_, w) => {
                    self.word(w, Mode::Argument);
                }
                IoRedirect::OutputAndError(w, _) => {
                    self.word(w, Mode::Argument);
                }
            }
        }

        /// Converts a word, recording substitution bodies and, in argument
        /// mode, marking the result unresolved for any expansion.
        fn word(&mut self, w: &ast::Word, mode: Mode) -> Word {
            let raw_words = match self.brace_expand(&w.value) {
                Some(words) => words,
                None => {
                    self.ir.unresolved = true;
                    vec![w.value.clone()]
                }
            };
            let mut cands = Vec::new();
            let mut resolved = true;
            for raw in &raw_words {
                let Ok(pieces) = word::parse(raw, &self.options) else {
                    if mode == Mode::Argument {
                        self.ir.unresolved = true;
                    }
                    resolved = false;
                    continue;
                };
                let mut buf = CandBuf::default();
                if self.pieces(&pieces, false, mode, &mut buf) {
                    cands.push(buf.finish());
                } else {
                    resolved = false;
                }
            }
            if resolved {
                Word::Resolved(cands)
            } else {
                Word::Unresolved
            }
        }

        /// Appends pieces to `buf`; false when the value cannot be known.
        fn pieces(
            &mut self,
            pieces: &[WordPieceWithSource],
            quoted: bool,
            mode: Mode,
            buf: &mut CandBuf,
        ) -> bool {
            let mut known = true;
            for p in pieces {
                match &p.piece {
                    WordPiece::Text(s) => {
                        if quoted {
                            buf.quoted(s);
                        } else {
                            buf.unquoted(s);
                        }
                    }
                    WordPiece::SingleQuotedText(s) => buf.quoted(s),
                    WordPiece::AnsiCQuotedText(s) => buf.quoted(&decode_ansi_c(s)),
                    WordPiece::DoubleQuotedSequence(inner)
                    | WordPiece::GettextDoubleQuotedSequence(inner) => {
                        known &= self.pieces(inner, true, mode, buf);
                    }
                    WordPiece::EscapeSequence(s) => {
                        let rest = s.strip_prefix('\\').unwrap_or(s);
                        if rest != "\n" {
                            buf.quoted(rest);
                        }
                    }
                    WordPiece::TildeExpansion(TildeExpr::Home) => match home_dir() {
                        Some(home) => buf.quoted(&home),
                        None => known = false,
                    },
                    WordPiece::TildeExpansion(_) | WordPiece::ParameterExpansion(_) => {
                        known = false
                    }
                    WordPiece::ArithmeticExpression(expr) => {
                        self.arithmetic_substitutions(&expr.value);
                        known = false;
                    }
                    WordPiece::CommandSubstitution(body) => {
                        self.ir.nested.push(body.clone());
                        known = false;
                    }
                    WordPiece::BackquotedCommandSubstitution(body) => {
                        self.ir.nested.push(unescape_backquoted(body));
                        known = false;
                    }
                }
            }
            if !known && mode == Mode::Argument {
                self.ir.unresolved = true;
            }
            known
        }

        /// The raw words produced by brace expansion of `raw`; `None` when
        /// the expansion is too large.
        fn brace_expand(&mut self, raw: &str) -> Option<Vec<String>> {
            if !raw.contains('{') {
                return Some(vec![raw.to_string()]);
            }
            match word::parse_brace_expansions(raw, &self.options) {
                Ok(Some(pieces)) => {
                    let limit = MAX_BRACE_WORDS.min(self.brace_budget);
                    let words = expand_brace_pieces(&pieces, limit)?;
                    self.brace_budget -= words.len();
                    Some(words)
                }
                Ok(None) | Err(_) => Some(vec![raw.to_string()]),
            }
        }

        /// Records the bodies of `$(...)` and backquote substitutions inside
        /// an arithmetic expression (they run), marking the result
        /// unresolved when there are any.
        fn arithmetic_substitutions(&mut self, expr: &str) {
            if !expr.contains("$(") && !expr.contains('`') {
                return;
            }
            let before = self.ir.nested.len();
            match word::parse_heredoc(expr, &self.options) {
                Ok(pieces) => {
                    let mut buf = CandBuf::default();
                    self.pieces(&pieces, false, Mode::BodiesOnly, &mut buf);
                }
                Err(_) => self.ir.unresolved = true,
            }
            if self.ir.nested.len() > before {
                self.ir.unresolved = true;
            }
        }
    }

    /// Expands parsed brace pieces; `None` once more than `limit` words
    /// would be produced (checked before each allocation).
    fn expand_brace_pieces(pieces: &[BraceExpressionOrText], limit: usize) -> Option<Vec<String>> {
        let mut acc = vec![String::new()];
        for piece in pieces {
            let alternatives: Vec<String> = match piece {
                BraceExpressionOrText::Text(t) => vec![t.clone()],
                BraceExpressionOrText::Expr(members) => {
                    let mut alts = Vec::new();
                    for m in members {
                        let room = limit.checked_sub(alts.len())?;
                        match m {
                            BraceExpressionMember::NumberSequence {
                                start,
                                end,
                                increment,
                            } => {
                                let step = increment.unsigned_abs().max(1);
                                let (lo, hi) = (*start.min(end), *start.max(end));
                                let count = (hi.abs_diff(lo) / step).saturating_add(1);
                                if count > room as u64 {
                                    return None;
                                }
                                let mut v: Vec<String> = (0..count)
                                    .map(|k| (lo + (k * step) as i64).to_string())
                                    .collect();
                                if start > end {
                                    v.reverse();
                                }
                                alts.extend(v);
                            }
                            BraceExpressionMember::CharSequence {
                                start,
                                end,
                                increment,
                            } => {
                                let step = increment.unsigned_abs().max(1);
                                let (lo, hi) =
                                    ((*start).min(*end) as u32, (*start).max(*end) as u32);
                                if u64::from(hi - lo) / step + 1 > room as u64 {
                                    return None;
                                }
                                let mut v: Vec<String> = (lo..=hi)
                                    .step_by(step as usize)
                                    .filter_map(char::from_u32)
                                    .map(String::from)
                                    .collect();
                                if start > end {
                                    v.reverse();
                                }
                                alts.extend(v);
                            }
                            BraceExpressionMember::Child(children) => {
                                alts.extend(expand_brace_pieces(children, room)?);
                            }
                        }
                    }
                    alts
                }
            };
            if acc.len().saturating_mul(alternatives.len()) > limit {
                return None;
            }
            acc = acc
                .iter()
                .flat_map(|prefix| alternatives.iter().map(move |alt| format!("{prefix}{alt}")))
                .collect();
        }
        Some(acc)
    }

    /// Inside backquotes, `\\`, `` \` `` and `\$` stand for the bare character.
    fn unescape_backquoted(body: &str) -> String {
        let mut out = String::with_capacity(body.len());
        let mut chars = body.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' && matches!(chars.peek(), Some('\\' | '`' | '$')) {
                out.push(chars.next().unwrap_or('\\'));
            } else {
                out.push(c);
            }
        }
        out
    }
}
