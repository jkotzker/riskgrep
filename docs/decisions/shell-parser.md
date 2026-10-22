# Shell parser for Bash target extraction

Decided 2026-10-19 (Task 15). `riskgrep-claude` must find the files a `Bash` tool command would read before it runs. That needs a real bash parser: quoting, here-documents, comments, substitutions, and redirections all change which words are file names.

## Candidates

| | brush-parser | tree-sitter + tree-sitter-bash |
|---|---|---|
| Version evaluated | 0.4.0 (2026-05-03) | tree-sitter 0.27.1 (2026-10-08), tree-sitter-bash 0.25.1 (2025-12-02) |
| Previous release | 0.3.0 (2025-11-17) | tree-sitter-bash 0.25.0 (2025-06-04) |
| Downloads (crates.io, all time / last 90 days) | 780,234 / 499,546 | tree-sitter-bash 17,647,980 / 9,930,426 |
| Licence | MIT | MIT / MIT |
| Implementation | Pure Rust, PEG parser; part of the brush shell | C parser and scanner compiled by `build.rs`, Rust bindings |
| Words | Parsed into pieces (quoted text, ANSI-C text, expansions, substitutions); brace expansion parser included | Syntax nodes; quote removal and escapes left to the caller; no brace-list expansion |

Download figures were read from the crates.io API on 2026-10-19.

## Method

Both front-ends were implemented behind cargo features against one shared back-end (filesystem checks, globbing, interpreter rules), so they differed only in how the command was parsed. Each was run against the 131 cases then in `crates/riskgrep-claude/tests/fixtures/bash_cases.json` (73 translated from sensitive-canary, 58 written for RiskGrep). After the first run, each front-end was adapted to the quirks its parser showed, and the set was run again.

Timing is the median over the 131 commands on an Apple M4 Max, release profile. "Parse only" is the first (uncached) parse of each command, measured with a temporary harness; "end to end" is `bash_targets` including the filesystem checks, best of 20 per command (`timing_median_over_cases` in `tests/bash.rs`, ignored by default). Binary size is a release build of `riskgrep-claude` whose `main` calls `bash_targets`, against the stub `main` that links nothing from the library (373,984 bytes); the delta includes the shared back-end and the `glob` crate in both columns.

## Results

| | brush-parser | tree-sitter-bash |
|---|---|---|
| Cases passing, first run | 128 / 131 | 120 / 131 |
| Cases passing, after adapting | **131 / 131** | 129 / 131 |
| Parse only, median (max) | 5.1–5.3 µs (~150 µs) | 6.3–7.6 µs (256–317 µs) |
| End to end, median | 15.6–16.4 µs | 15.8–18.2 µs |
| Release binary size | 785,808 bytes (+411,824) | 1,947,424 bytes (+1,573,440) |

Ranges are over three runs.

What each needed after the first run:

- **brush-parser:** it rejects a line continuation inside an operator (`cat 2>\` newline `&1 .env`), so a failed parse of a command containing backslash-newline is retried with continuations removed outside single quotes. After the command name it reports `name=value` as an assignment, so `dd if=disk.img` lost its operand; suffix assignments are now treated as arguments.
- **tree-sitter-bash:** it files every word after a redirection under that redirection as a further destination (`cat 2>&1 .env` puts `.env` under `2>&1`); only the first destination is now taken as the target. It needed the same line-continuation retry. Two cases still fail: `{a,b}` is split into separate words with no brace-expansion node, so brace lists are reported unresolved instead of expanded; and a partly quoted here-document delimiter (`<<E"O"F`) produces an `ERROR` node, so the whole command falls back to unresolved.

## Choice

**brush-parser.** It passes every case, parses faster, and adds about a quarter of the binary size of tree-sitter (411,824 against 1,573,440 bytes). The tree-sitter front-end, its feature, and its dependencies were removed.

Costs accepted with this choice:

- brush-parser is pre-1.0, so a minor release may change its API under semver.
- It declares `insta`, `bon`, `cached`, and `peg` as normal dependencies, which lengthens the build.
- After the choice, further cases showed brush-parser 0.4.0 reporting nested subshells as arithmetic commands: `( ( cat x ) )` and `((cat x) )` both come back as `((cat x))`. Bash reads `((` as arithmetic only when the command also closes with an unbroken `))`. The analysis therefore checks the original text at the arithmetic command's source span; anything else is analysed as a subshell command list and marked unresolved. Substitutions inside real arithmetic (`(( $(cat f) ))`, `for ((i=$(cat f); …))`, `$(( … ))`) are analysed as commands and also mark the result unresolved.
- It is a recursive PEG parser, and a stack overflow aborts the process (it cannot be caught as a panic). Analysis therefore runs on a dedicated thread with a 1 GiB stack, which is reserved address space; pages are committed only as deep as a parse recurses. Commands over 64 KiB are not parsed: the first 64 KiB get the whitespace-split catch-all and the result is unresolved. The ignored release test `stress::worst_case_nesting_at_twice_the_cap` in `src/bash.rs` parses the worst shapes found in review with the shortcuts disabled, at 64 KiB and at 128 KiB (twice the cap). The shapes are nested `(];`, `(#)` followed by a newline, unary `!` arithmetic, `if`, `while`, `$(`, `{` and `(`. All return; the slowest is `$(` nesting at 1,105 ms for 128 KiB and 241 ms for 64 KiB (measured 2026-10-19). A nesting estimate, linear and stopping once past 256, reports obviously deep input as unresolved without parsing it; it is a shortcut, not the safety mechanism.
- Time is bounded by the wall clock, not by cooperation. `bash_targets_within(command, cwd, budget)` waits for the worker thread for at most `budget` (default 500 ms). Without an answer by then, it returns the whitespace-split catch-all over the raw command, unresolved, and abandons the worker; a hook process exits right after, while a long-lived caller may keep a runaway worker until it finishes. Inside the worker the deadline is also checked between commands, words, brace candidates and every directory entry a glob visits, so most slow inputs still return a partial answer. Globs are expanded by a walker in this module: `read_dir` per path component and `glob::Pattern` per name, capped at 10,000 entries visited per command. `**` is not walked.
- brush-parser's here-document word parser is exponential on unclosed `$(` (a 55-byte command took 9.9 s), so it is not used. Unquoted here-document bodies and arithmetic expressions are scanned linearly for `$(…)` and backquote substitutions. The scanner is quote- and comment-aware, and each body found is analysed as commands. Any substitution there marks the result unresolved; an unclosed one is not analysed.
- `brush-parser` is pinned to `=0.4.0` because the line-continuation retry and the arithmetic-command handling depend on how 0.4.0 parses.

## Known limits

Bash target extraction is best-effort, as the design states. After three review rounds the following is accepted:

- The result is a static reading of one command line. Variables, functions, and aliases defined elsewhere, files a program decides to open at run time, and anything a script or interpreter does are outside it. A word built from an unknown variable is `unresolved`, as are the interpreters and executors in the tables, but a function, an alias, or a program outside the tables is resolved as reading only the files it names as arguments: files it opens at run time are not seen, and the result is not marked `unresolved`. The user-facing entry is "The Bash analysis is a best-effort static reading, and unresolved commands get no decision by default" in [`docs/known-limitations.md`](../known-limitations.md).
- `$HOME`, `${HOME}`, a leading `~` or `~/`, `$PWD`, and `${PWD}` are resolved from the hook's `HOME` and the command's working directory. A word using one stays `unresolved` when the command line names that variable anywhere other than as such a reference (an assignment, `export`, `unset`, `read`, a `for` variable), mentions `IFS`, changes directory (`cd`, `pushd`, `popd`, also later in the line, since loops and functions run later text first), runs code in the current shell (`eval`, `source`, `.`, `trap`), has a command name that is not literal, or passes a non-literal argument to an assigning builtin; and in a command line run through `env`, `sudo`, `doas`, `su`, `runuser`, `chroot`, `unshare`, or `systemd-run`. An unquoted expansion whose value contains whitespace, `*`, `?`, `[`, or `\` stays `unresolved`. Indirection built to evade these checks (assembling the name `HOME` from pieces) is outside the cooperative-agent threat model.
- Classification is by command name and option tables. A command that runs other programs but is not in a table, and whose arguments neither name a shell or interpreter nor contain `-c`/`--command`, is not detected as an executor.
- Option tables are hand-written from GNU, BSD and ripgrep documentation. A valid option missing from a table makes the result unresolved. Under the default `on_unresolved = "allow"`, unresolved means no decision rather than a block, but the files the command names are still scanned and can still ask or deny (measured with `riskgrep-claude` on a generated private-key file `a.txt`: `cat --zzz a.txt` returns `ask`, while `cat $ZZZ` returns no output). A gap therefore costs coverage of files the command reads without naming, and only `on_unresolved = "ask"` or `"deny"` turns unresolved into a prompt or a block.
- Commands in `PLAIN` (such as `head`, `cut` and `ls`) are exempt from the shell and `-c` class rule, so `head -c 1 f` stays resolved.
- An unparseable, oversized (over 64 KiB), too deeply nested, or too slow command falls back to the whitespace-split catch-all and is unresolved.
