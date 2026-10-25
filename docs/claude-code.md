# Claude Code hook

`riskgrep-claude` is a Claude Code `PreToolUse` hook. For `Read`, `NotebookRead`, `Grep`, `Bash`, and MCP tool calls it finds the files the call would read, scans them, and asks or denies when a category score reaches its threshold. For `Glob`, and for MCP tools that list directories, it judges the file names the call would reveal by the path rules alone. Any other tool, and any call that crosses no threshold, produces no output and exit status 0. The hook never emits `allow`.

## Threat model

v1 protects against accidental exposure by a cooperative agent, which is what happened in the motivating incident. It does not resist an agent actively working around it: an agent with shell access running as the same user can edit the user config, write cache rows, or replace the compiled rules bundle.

## Installation

`riskgrep-claude print-config` prints a `settings.json` fragment (a hook entry and a permission rule) on stdout and a one-line instruction on stderr. Merge it into `~/.claude/settings.json` by hand. The hook entry uses matcher `^(Read|NotebookRead|Grep|Glob|Bash|mcp__.*)$` and timeout 5 (seconds). Claude Code evaluates a matcher holding characters other than letters, digits, `_`, `-`, spaces, `,`, and `|` as an unanchored JavaScript regular expression, so the matcher is anchored to keep it to these tool names; `mcp__.*` sends every MCP tool call to the hook. An installation made with the earlier matcher `Read|NotebookRead|Grep|Bash` gates neither `Glob` nor MCP tools until the matcher is updated.

## Behaviour

| Tool | Files scanned |
| --- | --- |
| `Read`, `NotebookRead` | `tool_input.file_path` (`notebook_path` first for `NotebookRead`). A path that does not exist, or that names a directory, is ignored: the tool fails on it and reads nothing. |
| `Grep` | `tool_input.path` (default: the hook input's `cwd`), trimmed, with a leading `~` or `~/` expanded from `HOME` (Claude Code passes `Grep` paths unexpanded). A file is scanned directly. A directory is walked the way Claude Code 2.1.301 runs ripgrep for `Grep`: hidden files included, the directories `.git`, `.svn`, `.hg`, `.bzr`, `.jj`, and `.sl` excluded, `.gitignore` honoured, symlinks not followed, filtered by `type` and by `glob`. A `glob` is split as Claude Code splits it: on whitespace, then each piece on commas unless the piece contains both `{` and `}` (`*.md,*.env` and `*.md *.env` are two globs, `*.{md,env}` is one). The walk stops at `limits.walk_files`; the remainder is treated as an error (`on_error`, reason `walk limit`). |
| `Bash` | The files `bash_targets_within` names for `tool_input.command` run in `cwd` (see `src/bash.rs`). `$HOME`, `${HOME}`, and a leading `~` or `~/` are expanded from the hook's `HOME`, and `$PWD` and `${PWD}` from `cwd`, unless the same command line assigns, exports, or unsets that variable, changes directory, or runs code in the current shell (`eval`, `source`). `on_unresolved` applies when the command may read files that cannot be named; its default is `allow`, so such commands get no decision unless the configuration says otherwise. |

| `Glob` | No content is read. The names under `tool_input.path` (default `cwd`; `~` expanded as for `Grep`) that match `tool_input.pattern` are walked (hidden entries included, ignore files not honoured, the version-control directories above skipped, symlinks not followed, at most `limits.walk_files` names), and each name, relative to `cwd`, is scanned as an empty file of that name, so only rules that need no content match: `pkcs12_file` (`.p12`, `.pfx`; secret 90, which asks by default) and `path_biometric_name` (`voiceprint`, `embedding`, `speaker`, `enroll`, `faceprint`; biometric 30, below the default thresholds). An absolute `pattern` is searched from the directory before its first segment with a glob character. A name that cannot be scanned gets no decision, nor does a walk that reaches the limit, and the reason offers no reading guidance: `RiskGrep: file name <path> scored <category> <score> (<rule ids>). Threshold: <ask|deny> at <n>.` |
| MCP tools (`mcp__<server>__<tool>`) | The paths in the input fields that `claude_code.mcp_tools` names for the tool (see [MCP tools](#mcp-tools)), each a string or a list of strings, resolved like `Read` paths: relative to `cwd`, with a leading `~` or `~/` expanded. Kind `read` scans each path that is a file, `walk` scans the files under each path (walked as for `Glob`, at most `limits.walk_files`; the remainder is treated as an error, as for `Grep`), `names` judges the names of each path and the entries under it as `Glob` does (to `max_depth` levels when set), and `none` reads nothing. A tool with no entry, or whose fields are all absent or hold anything but a string or a list of strings, is unresolved: `on_unresolved` applies (default `allow`, so no decision) with reason `RiskGrep: could not determine the files <tool> reads`. |

Decision rules (`src/decide.rs`): every finding is graded `ask` or `deny`: a category score at or above its `ask` or `deny` threshold (defaults: `biometric` ask at 50 and deny at 75, `secret` ask at 80 and deny at 95), an unscanned target (`on_error`, default `ask`), a skipped target (`on_skipped`, default `allow`), or an unresolved Bash command (`on_unresolved`, default `allow`). The highest grade over all findings wins, so a lower-scoring `ask` finding does not hide an unscanned target whose `on_error` is `deny`. Only findings of the winning grade appear in the reason. `block` is treated as `deny`; `allow` produces no output.

Reason text never contains file content or line text:

`RiskGrep: <path> scored <category> <score> (<rule ids>) on lines <ranges>. Threshold: <ask|deny> at <n>. <guidance>`

With several findings the top three by score are listed, followed by `, and N more.` A finding names at most five rule ids, then `and N more`. The line ranges and the guidance are described under [Partial reads](#partial-reads). Other reasons: `RiskGrep: could not scan <path> (<reason>)`, `RiskGrep: command reads files that could not be determined`, `RiskGrep: scan exceeded time budget`, `RiskGrep: unreadable hook input`, and `RiskGrep: configuration error (invalid config <path> at line <l>, column <c>)`, which names the position of a configuration error but quotes none of the file.

Failures apply `on_error` (default `ask`) and the exit status is always 0. How Claude Code treats a hook that exits with another status and no JSON decision depends on the Claude Code version (documented as a non-blocking error that lets the call proceed), so a failure asks or denies only through a JSON decision. This covers malformed hook input, a configuration error (always `ask`), a panic (the default panic message is suppressed), and a scan that exceeds the time budget.

Repository: the root is the nearest ancestor of the hook input's `cwd` (itself included) that holds a `.git` entry, a directory or a file (worktrees and submodules). The walk (shared with the command line, `riskgrep_core::repo`) stops at `/`, before the parent of `$HOME`, and at `GIT_CEILING_DIRECTORIES`; a `cwd` inside a `.git` directory has no repository, and a root (or its `.git`) not owned by the effective user is not a root. Git is not spawned. A repository's `.riskgrep.toml` is read only if the user config lists the repository in `trusted_repos`.

Time budget: one budget (`claude_code.time_budget_ms`, default 2000, capped at one hour) covers the whole call. Bash analysis gets at most 25% of it (at least 50 ms). The scan runs on a worker thread; the main thread waits for the remainder.

## MCP tools

`claude_code.mcp_tools` maps an MCP tool name to the input fields that hold its paths and to what the tool does with them. Built-in entries cover the official filesystem server (field names from `src/filesystem/server.ts` in `modelcontextprotocol/servers`) under the server name `filesystem`, and Desktop Commander (field names from the input schemas its server reports) under `desktop-commander` and under its plugin name `plugin_desktop-commander_desktop-commander`:

| Server | `read` | `walk` | `names` | `none` |
| --- | --- | --- | --- | --- |
| filesystem | `read_file`, `read_text_file`, `read_media_file` (`path`), `read_multiple_files` (`paths`) | | `list_directory`, `list_directory_with_sizes` (`path`, depth 1), `directory_tree`, `search_files` (`path`) | `get_file_info`, `list_allowed_directories`, `write_file`, `edit_file`, `create_directory`, `move_file` |
| Desktop Commander | `read_file` (`path`), `read_multiple_files` (`paths`) | `start_search` (`path`) | `list_directory` (`path`) | `get_file_info` |

Desktop Commander's `start_search` is treated as a content search whatever its `searchType`, so a file-name search under a directory holding a flagged file is judged by that file's content, as `Grep` is. Desktop Commander's other tools (its shell and process tools among them) have no entry and are unresolved.

To add a server, or a server registered under another name, add an entry to the user config (`~/.config/riskgrep/config.toml`) per tool, keyed by the full tool name as Claude Code shows it:

```toml
[claude_code.mcp_tools."mcp__notes__open_note"]
paths = ["file", "files"]   # input fields holding a path or a list of paths
kind = "read"               # read (default), walk, names, or none

[claude_code.mcp_tools."mcp__notes__*"]
kind = "none"               # every other tool of this server reads no file
```

A user entry replaces a built-in entry of the same name. A key may contain `*`, which matches any run of characters; an exact key wins over a pattern, and among patterns the first in key order that matches wins. `max_depth` limits a `names` entry to that many levels below each path (1: a directory's own entries). A key that does not start with `mcp__`, a `read`, `walk`, or `names` entry without `paths`, and an unknown kind or field are configuration errors. Set `on_unresolved = "ask"` to be asked about every MCP tool without an entry. Covered by `cargo test -p riskgrep-core --test config mcp_` and `cargo test -p riskgrep-claude --test hook` (`mcp_*`, `glob_*`, `unmapped_mcp_tool_follows_on_unresolved`, `user_added_mcp_entry_is_used`).

## Partial reads

Partial reads are offered only for findings from rules marked `line_complete`: rules whose every match gets its own location and cannot span more lines than that location. The gitleaks converter marks a rule when no part of its `span_regex` can match a line feed: any literal or class that admits one rejects the rule, including `\s`, `\W`, `\D`, negated classes such as `[^"]`, `[\s\S]`, dot-all `.`, `[[:space:]]`, and `\n` or `\x0a`; in the shipped `secrets-core` ruleset that is 59 of the 222 converted rules (`cargo xtask convert-gitleaks` output; for example `aws_access_token`, `github_pat`, `gitlab_pat`, and the `slack_*` tokens). `private_key`, `kubernetes_secret_yaml`, `generic_api_key`, and every rule whose regex ends with a delimiter class that includes `\s` are not marked, nor are the hand-written key-store rules or any biometric rule (path and tensor rules have no text lines, and the printed-float rules are not proven to cover every float of an array).

A reason for a category finding names the lines its evidence covers, as numbers only (`on line 10`, `on lines 3–7, 20`; adjacent and overlapping ranges are merged, and after 50 ranges the rest are counted as `and N more`), and ends with what the agent may do instead. For one file whose flagged lines are known:

`Do not read this file by other means (Bash, Grep, scripts). To use the rest of it, Read it with offset and limit ranges that exclude the lines above, or ask the user.`

When no partial read is possible (below), no lines are named and the reason ends:

`Do not read this file by other means (Bash, Grep, scripts). No partial read is available for this file; ask the user.`

A `Grep` or `Bash` reason that lists several files uses the plural forms (`these files`, `Read each with offset and limit ranges`), or, when only some of the files have known lines, `Read a file with listed lines using offset and limit ranges that exclude them; no partial read is available for the others; ask the user.` The `deny` reason reaches the model; the `ask` reason is shown to the user in the permission prompt.

A `Read` call with `offset`, `limit`, or both asks for lines `offset` through `offset + limit - 1` (`offset` defaults to 1, and without `limit` the range runs to the end of the file). The hook widens that range by one line on each side, so a difference of one in line numbering can only make it stricter. A category whose flagged lines the widened range does not touch is dropped from the decision; every other finding still applies, including `on_error` for a target that could not be scanned. A `Read` with neither field is judged on the whole file, as is one whose `offset` or `limit` is not a positive integer (0, negative, fractional, a string, or null). `Grep`, `Bash`, and `NotebookRead` are always judged on whole files, whatever their input holds. The flagged lines come from the evidence already in the report, so a cached file is not scanned again.

No partial read is possible, and the whole file is judged, when any of these holds for a file with a finding at or above a threshold:

- the file was not read whole: `partial` (a text file over 8 MiB, scanned at its ends), `unscanned`, or `skipped`;
- the file is not text: a key store or a tensor file, read by its structure;
- some evidence in a category at or above a threshold comes from a rule not marked `line_complete` (a PEM block's `private_key`, a Kubernetes `Secret`, a generic assignment, a printed float array), has no location (path rules such as `pkcs12_file`), an unknown line (0: evidence in the tail of a sampled file), or structural facts (tensor shapes);
- the file name ends in `.ipynb` (any case): Claude Code 2.1.301 ignores `offset` and `limit` for notebooks and returns every cell.

Evidence in a category below every threshold does not count. Only findings of the winning grade are listed, so a `deny` reason does not name the lines of an `ask` finding in the same file; a partial read that avoids the denied lines but touches the others gets the `ask`, with those lines named. Covered by `cargo test -p riskgrep-claude` (`src/decide.rs` unit tests and the `read_range_*`, `no_partial_read_*`, and `cached_runs_decide_as_uncached_runs` tests in `tests/hook.rs`). The rule marks are checked by `cargo test -p xtask --test convert line_complete` and `cargo test -p riskgrep-core --test ruleset_secrets line_complete_rules`.

## Cold rules cache

The first scan after install (or after any rules change) compiles the rules bundle and stores it in the cache directory. In a release build a cold call takes 0.58-0.9 s, inside the default 2 s budget, so the cache warms itself. A debug build took 13.5 s on the development machine, and a slow machine may also exceed the budget; the hook exits at the budget, so a compile that cannot finish is never cached and every call asks (`scan exceeded time budget`). In that case run `riskgrep rules compile` once with the same HOME before enabling the hook: it compiles the enabled rulesets and writes the bundle and its metadata to the cache. On macOS the cache is `~/Library/Caches/riskgrep` and `XDG_CACHE_HOME` is ignored.

## Verified against Claude Code 2.1.301

Documentation read through context7 (`/websites/code_claude`, pages `code.claude.com/docs/en/hooks`, `hooks-guide`, `permissions`, `tools-reference`, and the Agent SDK tool reference):

- Matchers: `*`, empty, or omitted match everything; a value of only letters, digits, `_`, `-`, spaces, `,`, and `|` is an exact name or a list of exact names; any other value is an unanchored JavaScript regular expression (`^Notebook`, `mcp__memory__.*`). MCP tools are named `mcp__<server>__<tool>`, and tools of a plugin-bundled server use a scoped server segment (`mcp__plugin_<plugin>_<server>__<tool>`).
- `Glob` input: `pattern` (required) and `path` (optional, default the working directory). Its result lists at most 100 file paths (`truncated` marks a cut list).
- PreToolUse input carries `tool_name`, `tool_input`, and `hook_event_name`; the decision goes in `hookSpecificOutput` with `hookEventName: "PreToolUse"`, `permissionDecision`, and `permissionDecisionReason`.
- `permissionDecision` values: `allow`, `deny`, `ask`, `defer`. For `ask` the reason is shown in the permission prompt; in a `-p` run no one can answer, the call is denied, and Claude reads the reason in the tool result. For `deny` the reason is shown to Claude. Precedence across hooks: `deny` > `defer` > `ask` > `allow`.
- `NotebookRead` does not appear in the current tool documentation. Notebooks are read with `Read` (`file_path`, `.ipynb`). The only notebook tool documented with a path field is `NotebookEdit` (`notebook_path`). The hook accepts `notebook_path` and falls back to `file_path` for `NotebookRead`, which keeps the matcher valid if the tool exists, and `Read` covers notebooks.
- Permission rules: Claude Code checks file permissions against `Edit(path)` and `Read(path)` rules only. A `Write(path)` rule is accepted but never consulted, and a startup warning says so. `Edit` rules apply to `Write` as well. `print-config` emits both `Edit(~/.config/riskgrep/**)` and `Write(~/.config/riskgrep/**)` as specified; the `Write` entry is redundant per the documentation.

`Read` line selection, read from the JavaScript embedded in the installed binary (`/opt/homebrew/Caskroom/claude-code@latest/2.1.301/claude`, found by searching it for the `offset` schema text `The line number to start reading from`):

- The input schema declares `offset` a non-negative integer and `limit` a positive integer (`offset:eM(E().int().nonnegative().optional())`, `limit:eM(E().int().positive().optional())`), with `offset` defaulting to 1 and `limit` to none.
- The reader starts at the 0-based line `y===0?0:y-1` (`y` is `offset`), so `offset` is 1-based and 0 also starts at the first line, and returns `limit` lines from there, or every remaining line without `limit`.
- Lines are split on LF (`indexOf("\n")`); one CR at the end of each line is removed, a lone CR does not end a line, and a leading byte order mark is dropped. The whole-file and streaming readers split the same way. RiskGrep numbers lines by counting LF bytes, which gives the same numbers (`read_range_counts_crlf_lines_as_claude_code_does` in `tests/hook.rs`).
- For a path whose extension is `.ipynb` (compared in lower case), `offset` and `limit` are reset before reading (`if(ER(ot))n=1,r=void 0`, where `ER` tests the extension and `n`, `r` are `offset`, `limit`), so a notebook is always read whole.

Headless check (2026-10-19, `claude --version` = `2.1.301 (Claude Code)`, model `haiku`, temporary working directory, synthetic `emb.safetensors` with a `speaker_embedding` F32 [1,192] tensor, hook command `env HOME=<temp> XDG_CACHE_HOME=<temp> <repo>/target/debug/riskgrep-claude`, rules cache pre-warmed):

- The model chose `Bash` (`cd "$(pwd -P)" && ls -la emb.safetensors ...`), not `Read`, for the prompt `Read the file emb.safetensors and tell me its size.`
- (This transcript predates the rename and split of the safetensors rules; today the same file reports `safetensors_embedding_tensor`, `safetensors_float_tensor`, and `safetensors_named_embedding`.)
- The transcript's tool result for that call was `PreToolUse:Bash hook error: RiskGrep: <temp>/work/emb.safetensors scored biometric 85.0 (safetensors_float_tensor, safetensors_named_embedding). Threshold: deny at 75.` The final answer relayed the score and threshold and declined to work around it.
- The `Read` path was not exercised by this run (one run was allowed). It is covered by the binary tests in `crates/riskgrep-claude/tests/hook.rs`.
- The `env HOME=...` prefix is a deviation from a bare absolute path: on macOS the cache lives under `HOME`, so `XDG_CACHE_HOME` alone does not isolate it, and the real HOME was needed only for Claude's own authentication.
