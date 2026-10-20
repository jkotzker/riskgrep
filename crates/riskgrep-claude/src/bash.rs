//! Which files a `Bash` tool command would read.
//!
//! The command is parsed into simple commands; every argument and every input
//! redirection target that names an existing regular file is a target. The
//! answer is marked `unresolved` whenever the command could read something the
//! parse cannot name: a word built from an expansion, a substitution whose
//! output becomes an argument, an interpreter or executor running code, an
//! option this module does not know, a change of directory, a directory
//! argument, a parse failure, or a spent time or walk budget.

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

/// Directory entries glob expansion may visit for one command before it
/// stops (unresolved).
const WALK_LIMIT: usize = 10_000;
/// Nesting of `sh -c` payloads, executors and substitution bodies analysed
/// recursively.
const MAX_DEPTH: usize = 16;
/// Commands longer than this are not parsed: the first this-many bytes get
/// the whitespace-split catch-all and the result is unresolved.
const MAX_COMMAND_BYTES: usize = 64 * 1024;
/// Stack of the thread the analysis runs on. It is reserved, not committed:
/// pages are touched only as deep as a parse actually recurses. The ignored
/// test `stress::worst_case_nesting_at_twice_the_cap` parses the worst
/// nesting shapes at twice [`MAX_COMMAND_BYTES`] on this stack.
const ANALYSIS_STACK_BYTES: usize = 1 << 30;
/// Estimated nesting (see [`nesting_estimate`]) above which a command is
/// reported unresolved without parsing. A shortcut for obviously
/// pathological input; the stack above is what makes deep input safe.
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

/// Like [`bash_targets`], but bounded by `budget` of wall-clock time.
///
/// The analysis runs on a worker thread; this function waits for it for at
/// most `budget`. If the worker has not answered by then, the result is the
/// whitespace-split catch-all over the raw command (at most
/// [`FALLBACK_TIME`] more), marked unresolved, and the worker is abandoned.
/// A hook process exits right after, so that costs nothing there; a caller
/// in a long-lived process may keep a runaway worker (and its reserved
/// stack) until it finishes on its own.
pub fn bash_targets_within(command: &str, cwd: &Path, budget: Duration) -> BashTargets {
    run_isolated(command, cwd, budget, true)
}

/// Time the catch-all fallback may take after the budget is spent.
const FALLBACK_TIME: Duration = Duration::from_millis(30);

/// Runs the analysis on a thread with [`ANALYSIS_STACK_BYTES`] of stack and
/// waits at most `budget` for it. `shortcut` enables the size and nesting
/// shortcuts (disabled only by the stress test, which must reach the
/// parser).
fn run_isolated(command: &str, cwd: &Path, budget: Duration, shortcut: bool) -> BashTargets {
    let start = Instant::now();
    // The worker stops itself a little before the wait ends, so a worker
    // that stops cooperatively still delivers its partial result.
    let margin = (budget / 10).min(Duration::from_millis(20));
    let deadline = start + budget - margin;
    let owned_command = command.to_string();
    let owned_cwd = cwd.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("riskgrep-bash".to_string())
        .stack_size(ANALYSIS_STACK_BYTES)
        .spawn(move || {
            let mut st = State::new(&owned_cwd, deadline);
            st.shortcut = shortcut;
            analyze(&owned_command, 0, &mut st);
            // The receiver may have given up; nothing to do then.
            let _ = tx.send(st.finish());
        });
    if spawned.is_ok() {
        // A worker that panics drops its sender, which ends the wait early.
        if let Ok(targets) = rx.recv_timeout(budget.saturating_sub(start.elapsed())) {
            return targets;
        }
    }
    // No thread, a panic, or out of time: whitespace split only.
    let mut st = State::new(cwd, Instant::now() + FALLBACK_TIME);
    st.fallback(command);
    st.finish()
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
    /// Apply the size and nesting shortcuts before parsing.
    shortcut: bool,
    files: Vec<PathBuf>,
    seen: HashSet<PathBuf>,
    probed: HashMap<PathBuf, Probe>,
    unresolved: bool,
    /// Directory entries glob expansion may still visit.
    walk_budget: usize,
}

impl<'a> State<'a> {
    fn new(cwd: &'a Path, deadline: Instant) -> Self {
        State {
            cwd,
            deadline,
            shortcut: true,
            files: Vec::new(),
            seen: HashSet::new(),
            probed: HashMap::new(),
            unresolved: false,
            walk_budget: WALK_LIMIT,
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
    let refused =
        st.shortcut && (src.len() > MAX_COMMAND_BYTES || nesting_estimate(src) > MAX_NESTING);
    let ir = if refused {
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

/// A rough estimate of how deeply `src` nests, ignoring quoting and
/// comments. Brackets count one level; `if`, `while`, `until`, `for`,
/// `select` and `case` count two (the construct and its `then`/`do` body).
/// Linear: it returns as soon as the estimate passes [`MAX_NESTING`].
fn nesting_estimate(src: &str) -> usize {
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let mut depth = 0usize;
    let pop = |stack: &mut Vec<(u8, usize)>, depth: &mut usize, kind: u8| {
        // The stack never holds more than MAX_NESTING + 1 entries.
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
        let opened = if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            match &src[start..i] {
                "if" => Some((b'i', 2)),
                "while" | "until" | "for" | "select" => Some((b'l', 2)),
                "case" => Some((b'c', 2)),
                "fi" => {
                    pop(&mut stack, &mut depth, b'i');
                    None
                }
                "done" => {
                    pop(&mut stack, &mut depth, b'l');
                    None
                }
                "esac" => {
                    pop(&mut stack, &mut depth, b'c');
                    None
                }
                _ => None,
            }
        } else {
            i += 1;
            match b {
                b'(' | b'[' => Some((b'(', 1)),
                b'{' => Some((b'{', 1)),
                b')' | b']' => {
                    pop(&mut stack, &mut depth, b'(');
                    None
                }
                b'}' => {
                    pop(&mut stack, &mut depth, b'{');
                    None
                }
                _ => None,
            }
        };
        if let Some((kind, weight)) = opened {
            stack.push((kind, weight));
            depth += weight;
            if depth > MAX_NESTING {
                return depth;
            }
        }
    }
    depth.min(MAX_NESTING)
}

// ---------------------------------------------------------------------------
// Command classification.

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash"];
const INTERPRETERS: &[&str] = &[
    "node",
    "nodejs",
    "ruby",
    "perl",
    "php",
    "deno",
    "bun",
    "npx",
    "tsx",
    "ts-node",
    // Interpreters whose inline code (`-e`, `-Command`) or script file can
    // open any file, and programs that run commands from a script, a
    // queue, or standard input.
    "osascript",
    "lua",
    "luajit",
    "Rscript",
    "R",
    "pwsh",
    "powershell",
    "tclsh",
    "julia",
    "groovy",
    "at",
    "batch",
    "ed",
    "ex",
    "vi",
    "vim",
    "nvim",
    "view",
];
/// Commands that change the directory later relative paths resolve against,
/// or read and run a file in the current shell.
const CONTEXT_CHANGERS: &[&str] = &["cd", "pushd", "popd", "source", "."];
/// `git` subcommands that print repository content not named as a path.
const GIT_READERS: &[&str] = &[
    "show",
    "cat-file",
    "archive",
    "grep",
    "blame",
    "annotate",
    "diff",
    "log",
    "whatchanged",
    "stash",
    "format-patch",
    "bundle",
];

/// The options a command accepts.
struct OptSpec {
    /// Short options without a value.
    short_flags: &'static str,
    /// Short options with a value, attached (`-uroot`) or the next word.
    short_values: &'static str,
    /// Short options whose value, if any, must be attached (`xargs -i{}`).
    short_optional: &'static str,
    /// Long options without a value, or with an optional `=value`.
    long_flags: &'static [&'static str],
    /// Long options with a value (`--name=value` or `--name value`).
    long_values: &'static [&'static str],
    /// `-NUM` is accepted (`nice -5`, `grep -3`).
    numeric: bool,
}

const NO_OPTIONS: OptSpec = OptSpec {
    short_flags: "",
    short_values: "",
    short_optional: "",
    long_flags: &[],
    long_values: &[],
    numeric: false,
};

const ENV_OPTS: OptSpec = OptSpec {
    short_flags: "i0v",
    short_values: "uCSP",
    long_flags: &[
        "--ignore-environment",
        "--null",
        "--debug",
        "--default-signal",
        "--ignore-signal",
        "--block-signal",
        "--list-signal-handling",
    ],
    long_values: &["--unset", "--chdir", "--split-string"],
    ..NO_OPTIONS
};
const SUDO_OPTS: OptSpec = OptSpec {
    short_flags: "AbBEeHiKklNnPSsVv",
    short_values: "ugCDhprtTUR",
    long_flags: &[
        "--askpass",
        "--background",
        "--bell",
        "--preserve-env",
        "--edit",
        "--set-home",
        "--login",
        "--remove-timestamp",
        "--reset-timestamp",
        "--list",
        "--non-interactive",
        "--preserve-groups",
        "--stdin",
        "--shell",
        "--validate",
    ],
    long_values: &[
        "--user",
        "--group",
        "--close-from",
        "--chdir",
        "--host",
        "--prompt",
        "--role",
        "--type",
        "--command-timeout",
        "--other-user",
        "--chroot",
    ],
    ..NO_OPTIONS
};
const DOAS_OPTS: OptSpec = OptSpec {
    short_flags: "nsL",
    short_values: "uaC",
    ..NO_OPTIONS
};
const NICE_OPTS: OptSpec = OptSpec {
    short_values: "n",
    long_values: &["--adjustment"],
    numeric: true,
    ..NO_OPTIONS
};
const TIMEOUT_OPTS: OptSpec = OptSpec {
    short_flags: "v",
    short_values: "sk",
    long_flags: &["--preserve-status", "--foreground", "--verbose"],
    long_values: &["--signal", "--kill-after"],
    ..NO_OPTIONS
};
const EXEC_OPTS: OptSpec = OptSpec {
    short_flags: "cl",
    short_values: "a",
    ..NO_OPTIONS
};
const COMMAND_OPTS: OptSpec = OptSpec {
    short_flags: "pvV",
    ..NO_OPTIONS
};
const STDBUF_OPTS: OptSpec = OptSpec {
    short_values: "ioe",
    long_values: &["--input", "--output", "--error"],
    ..NO_OPTIONS
};
const TIME_OPTS: OptSpec = OptSpec {
    short_flags: "apvq",
    short_values: "of",
    long_flags: &["--append", "--verbose", "--portability", "--quiet"],
    long_values: &["--output", "--format"],
    ..NO_OPTIONS
};
const CAFFEINATE_OPTS: OptSpec = OptSpec {
    short_flags: "dimsu",
    short_values: "tw",
    ..NO_OPTIONS
};
const XARGS_OPTS: OptSpec = OptSpec {
    short_flags: "0rtpxo",
    short_values: "adEILnPsJR",
    short_optional: "iel",
    long_flags: &[
        "--null",
        "--no-run-if-empty",
        "--verbose",
        "--interactive",
        "--exit",
        "--open-tty",
        "--show-limits",
        "--replace",
        "--eof",
        "--max-lines",
    ],
    long_values: &[
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-procs",
        "--max-chars",
        "--process-slot-var",
    ],
    ..NO_OPTIONS
};
const GREP_OPTS: OptSpec = OptSpec {
    // GNU grep and macOS (BSD) grep. BSD `-J`/`-M`/`-X`/`-Z` decompress
    // in-process (it links libbz2, liblzma and libz); neither grep runs
    // another program on the files it searches.
    short_flags: "EFGPiyvwxcLloqsbHhnTZzaIrRUuVJMXO",
    short_values: "efmABCdD",
    long_flags: &[
        "--extended-regexp",
        "--fixed-strings",
        "--basic-regexp",
        "--perl-regexp",
        "--ignore-case",
        "--no-ignore-case",
        "--invert-match",
        "--word-regexp",
        "--line-regexp",
        "--count",
        "--color",
        "--colour",
        "--files-without-match",
        "--files-with-matches",
        "--only-matching",
        "--quiet",
        "--silent",
        "--no-messages",
        "--byte-offset",
        "--with-filename",
        "--no-filename",
        "--line-number",
        "--initial-tab",
        "--null",
        "--null-data",
        "--text",
        "--recursive",
        "--dereference-recursive",
        "--line-buffered",
        "--binary",
        "--decompress",
        "--bz2decompress",
        "--xz",
        "--lzma",
        "--mmap",
    ],
    long_values: &[
        "--regexp",
        "--file",
        "--max-count",
        "--after-context",
        "--before-context",
        "--context",
        "--directories",
        "--devices",
        "--label",
        "--include",
        "--exclude",
        "--exclude-dir",
        "--exclude-from",
        "--binary-files",
    ],
    numeric: true,
    ..NO_OPTIONS
};
const RG_OPTS: OptSpec = OptSpec {
    short_flags: "abcFHhiIlLnNopqsSuUvwxzP0V.",
    short_values: "efgtTmABCjMErd",
    long_flags: &[
        "--hidden",
        "--no-ignore",
        "--files",
        "--count",
        "--count-matches",
        "--files-with-matches",
        "--files-without-match",
        "--ignore-case",
        "--smart-case",
        "--case-sensitive",
        "--fixed-strings",
        "--word-regexp",
        "--line-regexp",
        "--invert-match",
        "--line-number",
        "--no-line-number",
        "--heading",
        "--no-heading",
        "--with-filename",
        "--no-filename",
        "--only-matching",
        "--json",
        "--vimgrep",
        "--pcre2",
        "--multiline",
        "--follow",
        "--null",
        "--text",
        "--unrestricted",
        "--quiet",
        "--color",
        "--column",
        "--no-column",
        "--stats",
        "--trim",
        "--search-zip",
        "--no-messages",
        "--byte-offset",
        "--passthru",
    ],
    long_values: &[
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
        "--max-depth",
        "--max-filesize",
        "--type-add",
        "--colors",
        "--path-separator",
        "--pre",
        "--pre-glob",
        "--ignore-file",
        "--engine",
    ],
    numeric: false,
    ..NO_OPTIONS
};

const SETSID_OPTS: OptSpec = OptSpec {
    short_flags: "cfw",
    long_flags: &["--ctty", "--fork", "--wait"],
    ..NO_OPTIONS
};
const FLOCK_OPTS: OptSpec = OptSpec {
    short_flags: "sxeunoFv",
    short_values: "wEc",
    long_flags: &[
        "--shared",
        "--exclusive",
        "--unlock",
        "--nonblock",
        "--close",
        "--no-fork",
        "--verbose",
    ],
    long_values: &["--timeout", "--conflict-exit-code", "--command"],
    ..NO_OPTIONS
};
const SCRIPT_OPTS: OptSpec = OptSpec {
    short_flags: "adeFfkpqr",
    short_values: "tTcE",
    long_flags: &["--append", "--flush", "--quiet", "--return", "--force"],
    long_values: &[
        "--command",
        "--echo",
        "--log-out",
        "--log-in",
        "--log-io",
        "--log-timing",
    ],
    ..NO_OPTIONS
};
const CHROOT_OPTS: OptSpec = OptSpec {
    long_flags: &["--skip-chdir"],
    long_values: &["--userspec", "--groups"],
    ..NO_OPTIONS
};
const UNSHARE_OPTS: OptSpec = OptSpec {
    short_flags: "muinpUCTrfc",
    short_values: "RwSG",
    long_flags: &[
        "--mount",
        "--uts",
        "--ipc",
        "--net",
        "--pid",
        "--user",
        "--cgroup",
        "--time",
        "--fork",
        "--map-root-user",
        "--map-current-user",
        "--mount-proc",
        "--kill-child",
    ],
    long_values: &[
        "--propagation",
        "--setgroups",
        "--root",
        "--wd",
        "--setuid",
        "--setgid",
    ],
    ..NO_OPTIONS
};
const IONICE_OPTS: OptSpec = OptSpec {
    short_flags: "t",
    short_values: "cnpPu",
    long_flags: &["--ignore"],
    long_values: &["--class", "--classdata", "--pid", "--pgid", "--uid"],
    ..NO_OPTIONS
};
const TASKSET_OPTS: OptSpec = OptSpec {
    short_flags: "acp",
    long_flags: &["--all-tasks", "--cpu-list", "--pid"],
    ..NO_OPTIONS
};
const CHRT_OPTS: OptSpec = OptSpec {
    short_flags: "abdfiorRpmv",
    short_values: "TPD",
    long_flags: &[
        "--all-tasks",
        "--batch",
        "--deadline",
        "--fifo",
        "--idle",
        "--other",
        "--rr",
        "--reset-on-fork",
        "--pid",
        "--max",
        "--verbose",
    ],
    long_values: &["--sched-runtime", "--sched-period", "--sched-deadline"],
    ..NO_OPTIONS
};
const SYSTEMD_RUN_OPTS: OptSpec = OptSpec {
    short_flags: "tPGqSr",
    short_values: "uMpEH",
    long_flags: &[
        "--user",
        "--system",
        "--scope",
        "--pty",
        "--pipe",
        "--wait",
        "--collect",
        "--quiet",
        "--remain-after-exit",
        "--no-block",
        "--same-dir",
        "--shell",
        "--send-sighup",
    ],
    long_values: &[
        "--unit",
        "--property",
        "--description",
        "--slice",
        "--setenv",
        "--working-directory",
        "--machine",
        "--host",
        "--uid",
        "--gid",
        "--nice",
        "--service-type",
        "--on-calendar",
    ],
    ..NO_OPTIONS
};
const RUNUSER_OPTS: OptSpec = OptSpec {
    short_flags: "lmpfP",
    short_values: "ugGswc",
    long_flags: &["--login", "--preserve-environment", "--pty"],
    long_values: &[
        "--user",
        "--group",
        "--supp-group",
        "--shell",
        "--command",
        "--whitelist-environment",
    ],
    ..NO_OPTIONS
};

/// How a wrapper command finds the command it runs.
struct Wrapper {
    opts: &'static OptSpec,
    /// Operands between the options and the command (`flock FILE cmd`,
    /// `taskset MASK cmd`).
    skip_operands: usize,
    /// Options whose value is a shell command line (`flock -c CMD`).
    payload: &'static [&'static str],
    /// The command runs in a context the analysis cannot follow (another
    /// root, another user's environment, a service manager).
    always_unresolved: bool,
}

const fn wrapper(opts: &'static OptSpec) -> Wrapper {
    Wrapper {
        opts,
        skip_operands: 0,
        payload: &[],
        always_unresolved: false,
    }
}

/// Wrapper commands that run the command named after their options.
fn wrapper_spec(name: &str) -> Option<Wrapper> {
    Some(match name {
        "env" => wrapper(&ENV_OPTS),
        "sudo" => wrapper(&SUDO_OPTS),
        "doas" => wrapper(&DOAS_OPTS),
        "nice" => wrapper(&NICE_OPTS),
        "timeout" => wrapper(&TIMEOUT_OPTS),
        "exec" => wrapper(&EXEC_OPTS),
        "command" => wrapper(&COMMAND_OPTS),
        "builtin" | "nohup" | "busybox" => wrapper(&NO_OPTIONS),
        "stdbuf" => wrapper(&STDBUF_OPTS),
        "time" => wrapper(&TIME_OPTS),
        "caffeinate" => wrapper(&CAFFEINATE_OPTS),
        "xargs" => wrapper(&XARGS_OPTS),
        "setsid" => wrapper(&SETSID_OPTS),
        "ionice" => wrapper(&IONICE_OPTS),
        "flock" => Wrapper {
            skip_operands: 1,
            payload: &["-c", "--command"],
            ..wrapper(&FLOCK_OPTS)
        },
        "script" => Wrapper {
            skip_operands: 1,
            payload: &["-c", "--command"],
            ..wrapper(&SCRIPT_OPTS)
        },
        "taskset" => Wrapper {
            skip_operands: 1,
            ..wrapper(&TASKSET_OPTS)
        },
        "chrt" => Wrapper {
            skip_operands: 1,
            ..wrapper(&CHRT_OPTS)
        },
        "chroot" => Wrapper {
            skip_operands: 1,
            always_unresolved: true,
            ..wrapper(&CHROOT_OPTS)
        },
        "unshare" => Wrapper {
            always_unresolved: true,
            ..wrapper(&UNSHARE_OPTS)
        },
        "systemd-run" => Wrapper {
            always_unresolved: true,
            ..wrapper(&SYSTEMD_RUN_OPTS)
        },
        "runuser" => Wrapper {
            payload: &["-c", "--command"],
            always_unresolved: true,
            ..wrapper(&RUNUSER_OPTS)
        },
        _ => return None,
    })
}

/// `arch` options are whole words (`-arm64`, `-arch x86_64`). Returns the
/// index after them, or `None` for an option it does not know.
fn skip_arch_options(words: &[Word]) -> Option<usize> {
    let mut i = 0;
    while let Some(arg) = literal(words.get(i)) {
        match arg.as_str() {
            "-arm64" | "-arm64e" | "-x86_64" | "-x86_64h" | "-i386" | "-32" | "-64" | "-c"
            | "-h" => i += 1,
            "-arch" | "-d" | "-e" => i += 2,
            a if a.starts_with('-') => return None,
            _ => break,
        }
    }
    Some(i.min(words.len()))
}

/// Commands known to run nothing else, so the class rule in [`classify`]
/// (shell names and `-c` anywhere in the arguments) does not apply:
/// `head -c 1 f` and `echo sh` stay resolved.
const PLAIN: &[&str] = &[
    "cat", "head", "tail", "wc", "cut", "ls", "du", "echo", "printf", "stat", "file", "cp", "mv",
    "rm", "mkdir", "touch", "chmod", "ln", "tee", "cmp", "diff", "basename", "dirname", "realpath",
    "readlink", "true", "false", "test", "[",
];

/// Programs with their own scripting language that can read any file.
const SCRIPTED: &[&str] = &["sed", "gsed", "awk", "gawk", "mawk", "nawk", "perl"];

fn is_interpreter(name: &str) -> bool {
    name.starts_with("python") || INTERPRETERS.contains(&name) || SCRIPTED.contains(&name)
}

/// The class rule for a command this module does not otherwise know: a
/// shell name among its arguments, or `-c`/`--command` followed by a word,
/// is a command line it may run (analysed, unresolved); an interpreter name
/// among its arguments is unresolved.
fn executor_scan(args: &[Word], depth: usize, st: &mut State) {
    for (k, word) in args.iter().enumerate() {
        let Some(text) = literal(Some(word)) else {
            continue;
        };
        let name = base_name(&text);
        let payload = match text.as_str() {
            "-c" | "--command" => literal(args.get(k + 1)),
            _ => text.strip_prefix("--command=").map(str::to_string),
        };
        if let Some(payload) = payload {
            st.unresolved = true;
            analyze(&payload, depth + 1, st);
        } else if SHELLS.contains(&name) {
            st.unresolved = true;
            shell_invocation(&args[k + 1..], depth, st);
        } else if is_interpreter(name) {
            st.unresolved = true;
        }
    }
}

/// Options found by [`parse_options`].
struct Parsed {
    /// `(key, value)`, keys spelled `-x` or `--name`.
    opts: Vec<(String, Option<String>)>,
    /// Indices of operands (with `permute`; otherwise empty).
    operands: Vec<usize>,
    /// Index of the first word after the options (without `permute`).
    next: usize,
}

/// Parses leading options of `words` against `spec`. Without `permute` it
/// stops at the first operand; with it, options may follow operands (GNU
/// style) and operands are collected. `None` when a word is not literal or
/// an option is not in `spec`.
fn parse_options(words: &[Word], spec: &OptSpec, permute: bool) -> Option<Parsed> {
    let mut parsed = Parsed {
        opts: Vec::new(),
        operands: Vec::new(),
        next: words.len(),
    };
    let mut i = 0;
    let mut options_done = false;
    while i < words.len() {
        let arg = literal(words.get(i))?;
        let is_option = !options_done && arg.starts_with('-') && arg != "-";
        if !is_option {
            if !permute {
                parsed.next = i;
                return Some(parsed);
            }
            parsed.operands.push(i);
            i += 1;
            continue;
        }
        i += 1;
        if arg == "--" {
            if !permute {
                parsed.next = i;
                return Some(parsed);
            }
            options_done = true;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_string())),
                None => (arg.clone(), None),
            };
            if spec.long_values.contains(&name.as_str()) {
                let value = match attached {
                    Some(v) => v,
                    None => {
                        let v = literal(words.get(i))?;
                        i += 1;
                        v
                    }
                };
                parsed.opts.push((name, Some(value)));
            } else if spec.long_flags.contains(&name.as_str()) {
                parsed.opts.push((name, attached));
            } else {
                return None;
            }
            continue;
        }
        let cluster = &arg[1..];
        if spec.numeric && cluster.bytes().all(|b| b.is_ascii_digit()) {
            parsed.opts.push((arg.clone(), None));
            continue;
        }
        for (k, ch) in cluster.char_indices() {
            let rest = &cluster[k + ch.len_utf8()..];
            let key = format!("-{ch}");
            if spec.short_values.contains(ch) {
                let value = if rest.is_empty() {
                    let v = literal(words.get(i))?;
                    i += 1;
                    v
                } else {
                    rest.to_string()
                };
                parsed.opts.push((key, Some(value)));
                break;
            } else if spec.short_optional.contains(ch) {
                parsed
                    .opts
                    .push((key, (!rest.is_empty()).then(|| rest.to_string())));
                break;
            } else if spec.short_flags.contains(ch) {
                parsed.opts.push((key, None));
            } else {
                return None;
            }
        }
    }
    Some(parsed)
}

const JQ_OPTS: OptSpec = OptSpec {
    short_flags: "rcnsejaCMSRhVt",
    long_flags: &[
        "--raw-output",
        "--compact-output",
        "--null-input",
        "--slurp",
        "--exit-status",
        "--join-output",
        "--ascii-output",
        "--color-output",
        "--monochrome-output",
        "--sort-keys",
        "--raw-input",
        "--tab",
        "--seq",
        "--stream",
    ],
    long_values: &["--indent"],
    ..NO_OPTIONS
};

/// Index (in `words`) of the operand that is a pattern or filter rather
/// than a path (`grep . f`, `jq . f`), derived from the command's option
/// table. `None` when the pattern came from `-e`/`-f`, the command has no
/// such operand, or its options cannot be parsed; every operand is then
/// treated as a possible path.
fn pattern_operand(words: &[Word]) -> Option<usize> {
    let name = literal(words.first())?;
    let spec = match base_name(&name) {
        "grep" | "egrep" | "fgrep" => &GREP_OPTS,
        "rg" => &RG_OPTS,
        "ag" | "ack" | "ugrep" => &NO_OPTIONS,
        "jq" | "yq" => &JQ_OPTS,
        _ => return None,
    };
    let parsed = parse_options(&words[1..], spec, true)?;
    let is_jq = std::ptr::eq(spec, &JQ_OPTS);
    let pattern_by_option = !is_jq
        && parsed
            .opts
            .iter()
            .any(|(k, _)| matches!(k.as_str(), "-e" | "-f" | "--regexp" | "--file"));
    if pattern_by_option {
        return None;
    }
    parsed.operands.first().map(|i| i + 1)
}

fn handle_simple(cmd: &Simple, depth: usize, st: &mut State) {
    let is_dd = cmd.is_command && literal(cmd.words.first()).as_deref() == Some("dd");
    let pattern_at = if cmd.is_command {
        pattern_operand(&cmd.words)
    } else {
        None
    };
    for (i, word) in cmd.words.iter().enumerate() {
        if st.out_of_time() {
            return;
        }
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
/// the result unresolved for interpreters, executors, context changers and
/// options it does not know.
fn classify(words: &[Word], depth: usize, st: &mut State) {
    if depth > MAX_DEPTH {
        st.unresolved = true;
        return;
    }
    let mut i = 0;
    let mut privileged = false;
    // Wrappers: `sudo -u root`, `env -i X=1`, `timeout -s KILL 5`, ...
    loop {
        let Some(name) = literal(words.get(i)) else {
            return;
        };
        let name = base_name(&name).to_string();
        if name == "arch" {
            match skip_arch_options(&words[i + 1..]) {
                Some(n) => {
                    i += 1 + n;
                    continue;
                }
                None => {
                    st.unresolved = true;
                    executor_scan(&words[i + 1..], depth, st);
                    return;
                }
            }
        }
        let Some(spec) = wrapper_spec(&name) else {
            break;
        };
        let Some(parsed) = parse_options(&words[i + 1..], spec.opts, false) else {
            // An option not in the table: the command word is unknown.
            st.unresolved = true;
            executor_scan(&words[i + 1..], depth, st);
            return;
        };
        let mut next = i + 1 + parsed.next;
        for (key, value) in &parsed.opts {
            if spec.payload.contains(&key.as_str()) {
                st.unresolved = true;
                if let Some(value) = value {
                    analyze(value, depth + 1, st);
                }
            }
        }
        if spec.always_unresolved {
            st.unresolved = true;
            executor_scan(&words[next..], depth, st);
        }
        if spec.skip_operands > 0 {
            for _ in 0..spec.skip_operands {
                if literal(words.get(next)).is_some() {
                    next += 1;
                }
            }
            // Options may also follow the operand (`flock FILE -c CMD`).
            let Some(after) = parse_options(&words[next..], spec.opts, false) else {
                st.unresolved = true;
                executor_scan(&words[next..], depth, st);
                return;
            };
            for (key, value) in &after.opts {
                if spec.payload.contains(&key.as_str()) {
                    st.unresolved = true;
                    if let Some(value) = value {
                        analyze(value, depth + 1, st);
                    }
                }
            }
            next += after.next;
        }
        match name.as_str() {
            "env" => {
                for (key, value) in &parsed.opts {
                    match key.as_str() {
                        "-S" | "--split-string" => {
                            // The string is split into the command line run.
                            let Some(value) = value else {
                                st.unresolved = true;
                                return;
                            };
                            let tail = join_literals(&words[next..], st);
                            analyze(&format!("{value} {tail}"), depth + 1, st);
                            return;
                        }
                        "-C" | "--chdir" | "-P" => st.unresolved = true,
                        _ => {}
                    }
                }
                while literal(words.get(next)).is_some_and(|w| w == "-" || w.contains('=')) {
                    next += 1;
                }
            }
            "sudo" | "doas" => {
                privileged = true;
                let runs_other = parsed.opts.iter().any(|(k, _)| {
                    matches!(
                        k.as_str(),
                        "-e" | "-i"
                            | "-s"
                            | "-l"
                            | "-D"
                            | "-R"
                            | "--edit"
                            | "--login"
                            | "--shell"
                            | "--list"
                            | "--chdir"
                            | "--chroot"
                    )
                });
                if runs_other {
                    st.unresolved = true;
                }
            }
            "timeout" => {
                if literal(words.get(next)).is_some() {
                    next += 1; // the duration
                }
            }
            "xargs" => {
                // Runs the command on words read from its input.
                st.unresolved = true;
                classify(&words[next..], depth + 1, st);
                return;
            }
            _ => {}
        }
        i = next;
    }
    let Some(name) = literal(words.get(i)) else {
        return;
    };
    let name = base_name(&name).to_string();
    let rest = &words[i + 1..];
    // `--files0-from=FILE` makes the command read the names of the files to
    // process from FILE, which is not scanned for those names.
    if rest
        .iter()
        .any(|w| literal(Some(w)).is_some_and(|t| t.starts_with("--files0-from")))
    {
        st.unresolved = true;
    }
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
        "parallel" => {
            st.unresolved = true;
            let at = skip_options(rest, |o| matches!(o, "-j" | "--jobs" | "-a" | "--arg-file"));
            classify(&rest[at..], depth + 1, st);
        }
        "su" => {
            st.unresolved = true;
            for j in 0..rest.len() {
                let arg = literal(rest.get(j)).unwrap_or_default();
                let payload = match arg.as_str() {
                    "-c" | "--command" => literal(rest.get(j + 1)),
                    _ => arg.strip_prefix("--command=").map(str::to_string),
                };
                if let Some(payload) = payload {
                    analyze(&payload, depth + 1, st);
                }
            }
        }
        "find" => find_exec(rest, depth, st),
        "git" => {
            let at = skip_options(rest, |o| {
                matches!(o, "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace")
            });
            for k in 0..at {
                let option = literal(rest.get(k)).unwrap_or_default();
                if option == "-c" {
                    // A config override can define aliases, pagers, hooks
                    // and helpers that run programs.
                    st.unresolved = true;
                    let setting = literal(rest.get(k + 1)).unwrap_or_default();
                    if let Some((_, command)) = setting.split_once("=!") {
                        analyze(command, depth + 1, st);
                    }
                } else if option.starts_with("--exec-path") || option.starts_with("--config-env") {
                    st.unresolved = true;
                }
            }
            if literal(rest.get(at)).is_some_and(|sub| GIT_READERS.contains(&sub.as_str())) {
                st.unresolved = true;
            }
        }
        "grep" | "egrep" | "fgrep" => {
            // grep reads stdin without a path unless it recurses.
            match search_operands(rest, &GREP_OPTS) {
                Some(s) => {
                    st.add_option_files(&s.option_files);
                    if s.recursive && s.paths == 0 {
                        st.unresolved = true;
                    }
                }
                None => st.unresolved = true,
            }
        }
        "rg" => {
            // rg searches the working directory when given no path.
            match search_operands(rest, &RG_OPTS) {
                Some(s) => {
                    st.add_option_files(&s.option_files);
                    if s.paths == 0 || s.runs_programs {
                        st.unresolved = true;
                    }
                }
                None => st.unresolved = true,
            }
        }
        "ag" | "ack" | "ugrep" => {
            // No option table: any option, or no path, is unresolved.
            match search_operands(rest, &NO_OPTIONS) {
                Some(s) if s.paths > 0 => {}
                _ => st.unresolved = true,
            }
        }
        n if is_interpreter(n)
            || (n == "uv" && literal(rest.first()).as_deref() == Some("run")) =>
        {
            st.unresolved = true;
        }
        n if PLAIN.contains(&n) => {}
        _ => executor_scan(rest, depth, st),
    }
}

struct SearchOperands {
    /// Path operands given (operands other than the pattern).
    paths: usize,
    /// Files named by option values that the command reads: `-f`/`--file`
    /// pattern files and rg `--pre` programs.
    option_files: Vec<String>,
    /// rg `--pre`, `--pre-glob`, `-z`/`--search-zip`: other programs run
    /// on the searched files.
    runs_programs: bool,
    /// `-r`, `-R`, `--recursive`, `-d recurse` or `--directories=recurse`.
    recursive: bool,
}

/// Counts the path operands of a grep-like command; `None` when a word is
/// not literal or an option is not in `spec`.
fn search_operands(args: &[Word], spec: &OptSpec) -> Option<SearchOperands> {
    let parsed = parse_options(args, spec, true)?;
    let mut pattern_given = false;
    let mut recursive = false;
    let mut option_files = Vec::new();
    let mut runs_programs = false;
    for (key, value) in &parsed.opts {
        match key.as_str() {
            "-e" | "--regexp" => pattern_given = true,
            "-f" | "--file" => {
                pattern_given = true;
                option_files.extend(value.clone());
            }
            "--pre" => {
                runs_programs = true;
                option_files.extend(value.clone());
            }
            "--pre-glob" | "-z" | "--search-zip" => runs_programs = true,
            "-r" | "-R" | "--recursive" | "--dereference-recursive" => recursive = true,
            "-d" | "--directories" => recursive |= value.as_deref() == Some("recurse"),
            _ => {}
        }
    }
    let operands = parsed.operands.len();
    let paths = if pattern_given {
        operands
    } else {
        operands.saturating_sub(1)
    };
    Some(SearchOperands {
        paths,
        option_files,
        runs_programs,
        recursive,
    })
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

// ---------------------------------------------------------------------------
// Words to files.

impl State<'_> {
    /// Adds the files a word names. With `dirs_unresolve`, a word naming a
    /// directory marks the result unresolved (directories are not walked).
    fn add_word(&mut self, word: &Word, is_dd: bool, dirs_unresolve: bool) {
        let Word::Resolved(cands) = word else {
            self.unresolved = true;
            return;
        };
        for cand in cands {
            if self.out_of_time() {
                return;
            }
            if let Some(pattern) = &cand.pattern {
                self.add_glob(pattern, &cand.text);
                continue;
            }
            let text = cand.text.as_str();
            self.add_literal(text, dirs_unresolve);
            if text.starts_with('-') || (is_dd && text.starts_with("if=")) {
                // `--file=path`, `-f=path`, `if=path`.
                if let Some((_, value)) = text.split_once('=') {
                    self.add_literal(value, dirs_unresolve);
                }
            }
            if text.starts_with('-') && !text.starts_with("--") {
                // An attached short-option value: `-fsecret.env`.
                if let Some((at, _)) = text.char_indices().nth(2) {
                    self.add_literal(&text[at..], dirs_unresolve);
                }
            }
        }
    }

    fn add_option_files(&mut self, files: &[String]) {
        for file in files {
            self.add_literal(file, true);
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

    /// Expands a glob one path component at a time, reading each directory
    /// with `read_dir` and counting every entry visited against
    /// [`WALK_LIMIT`] and the deadline. `**` is not walked.
    fn add_glob(&mut self, pattern: &str, text: &str) {
        if pattern.contains("**") {
            self.unresolved = true;
            return;
        }
        let (root, relative) = match pattern.strip_prefix('/') {
            Some(rest) => (PathBuf::from("/"), rest),
            None => (self.cwd.to_path_buf(), pattern),
        };
        let mut components = Vec::new();
        for part in relative.split('/').filter(|p| !p.is_empty()) {
            if part.contains(['*', '?', '[']) {
                match glob::Pattern::new(part) {
                    Ok(p) => components.push((part, Some(p))),
                    Err(_) => {
                        // Not a valid pattern: the shell passes it through.
                        self.add_literal(text, true);
                        return;
                    }
                }
            } else {
                components.push((part, None));
            }
        }
        let options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: true,
        };
        let mut current = vec![root];
        for (index, (part, matcher)) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            let mut next = Vec::new();
            for base in &current {
                let Some(matcher) = matcher else {
                    next.push(base.join(part));
                    continue;
                };
                let Ok(entries) = std::fs::read_dir(base) else {
                    continue;
                };
                let mut names = Vec::new();
                for entry in entries {
                    if self.walk_budget == 0 || self.out_of_time() {
                        self.unresolved = true;
                        return;
                    }
                    self.walk_budget -= 1;
                    let Ok(entry) = entry else {
                        continue;
                    };
                    let name = entry.file_name();
                    if let Some(name) = name.to_str() {
                        if matcher.matches_with(name, options) {
                            names.push(name.to_string());
                        }
                    }
                }
                names.sort();
                next.extend(names.into_iter().map(|n| base.join(n)));
            }
            if !last {
                next.retain(|p| p.is_dir());
            }
            current = next;
        }
        for path in current {
            if self.out_of_time() {
                return;
            }
            self.add_path(path, true);
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

/// Bodies of the `$(...)` and backquote substitutions in `text`, found by a
/// linear scan; `$((` arithmetic is scanned through. `None` when one is not
/// closed. Nested substitutions stay inside their body and are found when
/// the body is analysed.
fn substitution_bodies(text: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut bodies = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '`' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '`' {
                    j += if chars[j] == '\\' { 2 } else { 1 };
                }
                if j >= chars.len() {
                    return None;
                }
                let body: String = chars[i + 1..j].iter().collect();
                bodies.push(unescape_backquoted(&body));
                i = j + 1;
            }
            '$' if chars.get(i + 1) == Some(&'(') && chars.get(i + 2) != Some(&'(') => {
                let end = closing_paren(&chars, i + 2)?;
                bodies.push(chars[i + 2..end].iter().collect());
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    Some(bodies)
}

/// Index of the `)` that closes a command substitution whose body starts at
/// `start`, counting parentheses and skipping escapes, quoted text and
/// comments. `None` when it is not closed.
fn closing_paren(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = start;
    let mut word_start = true;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                i += 2;
                word_start = false;
                continue;
            }
            '\'' | '"' => {
                i += 1;
                while i < chars.len() && chars[i] != c {
                    i += if c == '"' && chars[i] == '\\' { 2 } else { 1 };
                }
                if i >= chars.len() {
                    return None;
                }
            }
            '#' if word_start => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        word_start = c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(');
        i += 1;
    }
    None
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

// ---------------------------------------------------------------------------
// Front-end: brush-parser.

mod front {
    use super::{
        decode_ansi_c, home_dir, remove_line_continuations, substitution_bodies,
        unescape_backquoted, CandBuf, Ir, Simple, Word, MAX_BRACE_WORDS, MAX_TOTAL_BRACE_WORDS,
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
                    self.embedded_substitutions(&a.expr.value);
                    // Bash reads `((` as arithmetic only when the command
                    // also closes with an unbroken `))`; `((cat x) )` and
                    // `( ( cat x ) )` are nested subshells. brush-parser
                    // 0.4.0 reports all of these as arithmetic, so the
                    // original text decides.
                    let (start, end) = (a.loc.start.index, a.loc.end.index);
                    let src = &self.source;
                    let spans = start + 4 <= end && end <= src.len();
                    let arithmetic = spans
                        && src[start..start + 2] == ['(', '(']
                        && src[end - 2..end] == [')', ')'];
                    if !arithmetic {
                        self.ir.unresolved = true;
                        let inner = if spans {
                            src[start + 1..end - 1].iter().collect()
                        } else {
                            a.expr.value.clone()
                        };
                        self.ir.nested.push(inner);
                    }
                }
                CompoundCommand::ArithmeticForClause(f) => {
                    let parts = [&f.initializer, &f.condition, &f.updater];
                    for expr in parts.into_iter().flatten() {
                        self.embedded_substitutions(&expr.value);
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
                        self.embedded_substitutions(&doc.doc.value);
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
                        self.embedded_substitutions(&expr.value);
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

        /// Records the bodies of `$(...)` and backquote substitutions in
        /// text that is expanded but not split into words (an unquoted
        /// here-document body, an arithmetic expression), and marks the
        /// result unresolved when there are any. A linear scan
        /// ([`substitution_bodies`]) rather than brush-parser's word parser,
        /// which is exponential on unclosed `$(`.
        fn embedded_substitutions(&mut self, text: &str) {
            if !text.contains("$(") && !text.contains('`') {
                return;
            }
            self.ir.unresolved = true;
            if let Some(bodies) = substitution_bodies(text) {
                self.ir.nested.extend(bodies);
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
}

#[cfg(test)]
mod stress {
    //! Proof that stack exhaustion cannot abort the process within the
    //! command-size cap: the worst nesting shapes, parsed with the size and
    //! nesting shortcuts disabled, at the cap and at twice the cap. Run in
    //! release:
    //! `cargo test --release -p riskgrep-claude --lib -- --ignored --nocapture`.

    use super::{run_isolated, MAX_COMMAND_BYTES};
    use std::time::{Duration, Instant};

    /// Repeats `open` and `close` around `cat x` to fill `bytes`.
    fn nest(open: &str, close: &str, bytes: usize) -> String {
        let n = (bytes - 5) / (open.len() + close.len());
        format!("{}cat x{}", open.repeat(n), close.repeat(n))
    }

    fn shapes(bytes: usize) -> Vec<(&'static str, String)> {
        vec![
            ("(]; nesting", nest("(];", ")", bytes)),
            ("(#)\\n nesting", nest("(#)\n", ")", bytes)),
            (
                "unary ! arithmetic",
                format!("(({}1))", "!".repeat(bytes - 5)),
            ),
            ("nested if", nest("if true; then ", "; fi", bytes)),
            ("nested while", nest("while true; do ", "; done", bytes)),
            ("$( nesting", nest("echo $(", ")", bytes)),
            ("{ nesting", nest("{ ", "; }", bytes)),
            ("( nesting", nest("( ", " )", bytes)),
        ]
    }

    #[test]
    #[ignore]
    fn worst_case_nesting_at_twice_the_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for bytes in [MAX_COMMAND_BYTES, 2 * MAX_COMMAND_BYTES] {
            for (name, command) in shapes(bytes) {
                assert!(command.len() <= bytes);
                let start = Instant::now();
                let got = run_isolated(&command, tmp.path(), Duration::from_secs(600), false);
                println!(
                    "{bytes:>7} B  {name:<20} {:>8.1} ms  unresolved={}",
                    start.elapsed().as_secs_f64() * 1e3,
                    got.unresolved
                );
            }
        }
    }
}
