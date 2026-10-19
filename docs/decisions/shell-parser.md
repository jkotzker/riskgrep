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

- brush-parser is pre-1.0, so a minor release may change its API under semver; the dependency is `0.4.0` (any 0.4.x).
- It declares `insta`, `bon`, `cached`, and `peg` as normal dependencies, which lengthens the build.
- After the choice, a further case showed brush-parser 0.4.0 reading spaced nested subshells, `( ( cat x ) )`, as the arithmetic command `((cat x))`; bash runs them as subshells. An arithmetic command whose source does not begin with an unbroken `((` is therefore analysed as the commands it contains (fixture `spaced nested subshells are not arithmetic`).
- It is a recursive PEG parser. `bash_targets` refuses to parse commands over 1 MiB or with bracket nesting deeper than 64 (whitespace-split fallback, unresolved), and catches panics from the parser, so hostile input cannot exhaust the stack or abort the hook.
