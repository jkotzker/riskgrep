//! Which files a `Bash` tool command would read.
//!
//! The command is parsed into simple commands; every argument and every input
//! redirection target that names an existing regular file is a target. The
//! answer is marked `unresolved` whenever the command could read something the
//! parse cannot name: a word built from an expansion, a substitution whose
//! output becomes an argument, an interpreter running code, or a parse failure.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Files a shell command would read, and whether the answer is incomplete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BashTargets {
    /// Canonical paths of existing regular files the command names, in the
    /// order first seen, without duplicates.
    pub files: Vec<PathBuf>,
    /// True when the command may read files that are not in `files`.
    pub unresolved: bool,
}

/// Glob matches one command may yield before the walk stops (unresolved).
const WALK_LIMIT: usize = 10_000;
/// Nesting of `sh -c` payloads and substitution bodies analysed recursively.
const MAX_DEPTH: usize = 16;
/// Commands longer than this are not parsed (whitespace split only).
const MAX_COMMAND_BYTES: usize = 1 << 20;
/// Bracket nesting beyond which a command is not parsed, so a recursive
/// parser cannot exhaust the stack.
const MAX_BRACKET_NESTING: usize = 64;
/// Words a single brace expansion may produce.
const MAX_BRACE_WORDS: usize = 1_000;

/// Returns the files `command` would read when run in `cwd`.
pub fn bash_targets(command: &str, cwd: &Path) -> BashTargets {
    let mut st = State {
        cwd,
        files: Vec::new(),
        seen: HashSet::new(),
        unresolved: false,
        glob_budget: WALK_LIMIT,
    };
    analyze(command, 0, &mut st);
    BashTargets {
        files: st.files,
        unresolved: st.unresolved,
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

struct State<'a> {
    cwd: &'a Path,
    files: Vec<PathBuf>,
    seen: HashSet<PathBuf>,
    unresolved: bool,
    glob_budget: usize,
}

fn analyze(src: &str, depth: usize, st: &mut State) {
    if depth > MAX_DEPTH {
        st.unresolved = true;
        return;
    }
    let ir = if src.len() > MAX_COMMAND_BYTES || bracket_nesting(src) > MAX_BRACKET_NESTING {
        None
    } else {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| front::parse(src))).unwrap_or(None)
    };
    let Some(ir) = ir else {
        st.unresolved = true;
        for word in src.split_whitespace() {
            st.add_literal(word);
        }
        return;
    };
    st.unresolved |= ir.unresolved;
    for cmd in &ir.cmds {
        handle_simple(cmd, depth, st);
    }
    for body in &ir.nested {
        analyze(body, depth + 1, st);
    }
}

/// Deepest nesting of `(`, `{` and `[`, ignoring quoting; a cheap bound used
/// only to refuse pathological input.
fn bracket_nesting(src: &str) -> usize {
    let (mut depth, mut max) = (0usize, 0usize);
    for b in src.bytes() {
        match b {
            b'(' | b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
            }
            b')' | b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
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

fn handle_simple(cmd: &Simple, depth: usize, st: &mut State) {
    let is_dd = cmd.is_command && literal(cmd.words.first()).as_deref() == Some("dd");
    for word in cmd.words.iter().chain(cmd.reads.iter()) {
        st.add_word(word, is_dd);
    }
    if cmd.is_command {
        classify(cmd, depth, st);
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

/// Marks the result unresolved for interpreters and recurses into `sh -c`.
fn classify(cmd: &Simple, depth: usize, st: &mut State) {
    let words = &cmd.words;
    let mut i = 0;
    // Skip wrappers such as `sudo -u root` or `env X=1`.
    while let Some(name) = literal(words.get(i)) {
        let name = base_name(&name).to_string();
        if !WRAPPERS.contains(&name.as_str()) {
            break;
        }
        i += 1;
        while let Some(arg) = literal(words.get(i)) {
            let takes_value = matches!(
                (name.as_str(), arg.as_str()),
                (
                    "sudo",
                    "-u" | "-g" | "-C" | "-D" | "-h" | "-p" | "-r" | "-t" | "-U"
                ) | ("nice", "-n")
                    | ("env", "-u" | "-C" | "-S")
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
    let name = base_name(&name);
    let rest = &words[i + 1..];
    if SHELLS.contains(&name) {
        shell_invocation(rest, depth, st);
    } else if name.starts_with("python")
        || INTERPRETERS.contains(&name)
        || (name == "uv" && literal(rest.first()).as_deref() == Some("run"))
    {
        st.unresolved = true;
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
    fn add_word(&mut self, word: &Word, is_dd: bool) {
        let Word::Resolved(cands) = word else {
            self.unresolved = true;
            return;
        };
        for cand in cands {
            match &cand.pattern {
                Some(pattern) => self.add_glob(pattern, &cand.text),
                None => {
                    self.add_literal(&cand.text);
                    if cand.text.starts_with('-') || (is_dd && cand.text.starts_with("if=")) {
                        if let Some((_, value)) = cand.text.split_once('=') {
                            self.add_literal(value);
                        }
                    }
                }
            }
        }
    }

    fn add_literal(&mut self, text: &str) {
        if text.is_empty() || text.contains('\0') {
            return;
        }
        let path = Path::new(text);
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        };
        self.add_path(&full);
    }

    fn add_path(&mut self, path: &Path) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if !meta.is_file() {
            return;
        }
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.seen.insert(canon.clone()) {
            self.files.push(canon);
        }
    }

    fn add_glob(&mut self, pattern: &str, text: &str) {
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
            self.add_literal(text);
            return;
        };
        for entry in paths {
            if self.glob_budget == 0 {
                self.unresolved = true;
                return;
            }
            self.glob_budget -= 1;
            if let Ok(path) = entry {
                self.add_path(&path);
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
        MAX_BRACE_WORDS,
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
            source,
        };
        for list in &program.complete_commands {
            w.list(list);
        }
        Some(w.ir)
    }

    struct Walker {
        ir: Ir,
        options: ParserOptions,
        /// The text that was parsed, for checking source positions.
        source: String,
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
                    let opens: String = self
                        .source
                        .chars()
                        .skip(a.loc.start.index)
                        .take(2)
                        .collect();
                    if opens != "((" {
                        self.ir.nested.push(a.expr.value.clone());
                    }
                }
                CompoundCommand::ArithmeticForClause(f) => self.list(&f.body.list),
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
                    WordPiece::TildeExpansion(_)
                    | WordPiece::ParameterExpansion(_)
                    | WordPiece::ArithmeticExpression(_) => known = false,
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
        fn brace_expand(&self, raw: &str) -> Option<Vec<String>> {
            if !raw.contains('{') {
                return Some(vec![raw.to_string()]);
            }
            match word::parse_brace_expansions(raw, &self.options) {
                Ok(Some(pieces)) => expand_brace_pieces(&pieces),
                Ok(None) | Err(_) => Some(vec![raw.to_string()]),
            }
        }
    }

    fn expand_brace_pieces(pieces: &[BraceExpressionOrText]) -> Option<Vec<String>> {
        let mut acc = vec![String::new()];
        for piece in pieces {
            let alternatives: Vec<String> = match piece {
                BraceExpressionOrText::Text(t) => vec![t.clone()],
                BraceExpressionOrText::Expr(members) => {
                    let mut alts = Vec::new();
                    for m in members {
                        match m {
                            BraceExpressionMember::NumberSequence {
                                start,
                                end,
                                increment,
                            } => {
                                let step = increment.unsigned_abs().max(1);
                                let (lo, hi) = (*start.min(end), *start.max(end));
                                let count = (hi.abs_diff(lo) / step).saturating_add(1);
                                if count > MAX_BRACE_WORDS as u64 {
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
                                let step = increment.unsigned_abs().max(1) as u32;
                                let (lo, hi) =
                                    ((*start).min(*end) as u32, (*start).max(*end) as u32);
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
                                alts.extend(expand_brace_pieces(children)?);
                            }
                        }
                    }
                    alts
                }
            };
            if acc.len().saturating_mul(alternatives.len()) > MAX_BRACE_WORDS {
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
