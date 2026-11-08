# Claude Code hook

`riskgrep-claude` is a Claude Code `PreToolUse` hook. For `Read`, `NotebookRead`, `Grep`, `Bash`, and MCP tool calls it finds the files the call would read, scans them, and asks or denies when a category score reaches its threshold. For `Glob`, and for MCP tools that list directories, it judges the file names the call would reveal by the path rules alone. Any other tool, and any call that crosses no threshold, produces no output and exit status 0. The hook never emits `allow`.

## Threat model

v1 protects against accidental exposure by a cooperative agent, which is what happened in the motivating incident. It does not resist an agent actively working around it: an agent with shell access running as the same user can edit the user config, write cache rows, or replace the compiled rules bundle.

## Installation

`riskgrep-claude print-config` prints a `settings.json` fragment (a hook entry and a permission rule) on stdout and a one-line instruction on stderr. Merge it into `~/.claude/settings.json` by hand. The hook entry uses matcher `^(Read|NotebookRead|Grep|Glob|Bash|mcp__.*)$` and timeout 5 (seconds). Claude Code evaluates a matcher holding characters other than letters, digits, `_`, `-`, spaces, `,`, and `|` as an unanchored JavaScript regular expression, so the matcher is anchored to keep it to these tool names; `mcp__.*` sends every MCP tool call to the hook. An installation made with the earlier matcher `Read|NotebookRead|Grep|Bash` gates neither `Glob` nor MCP tools until the matcher is updated. The hook entry also sets `"onFailure": "block"`: Claude Code 2.1.295 or later then treats a hook that cannot start, exits with a status other than 0 or 2, times out, or prints invalid output as a blocking error (as exit status 2 does) instead of letting the call proceed. `riskgrep-claude print-config --no-block-on-failure` prints the entry without it, for a Claude Code that does not accept the field or for a user who prefers calls to proceed when the hook fails.

## Behaviour

| Tool | Files scanned |
| --- | --- |
| `Read`, `NotebookRead` | `tool_input.file_path` (`notebook_path` first for `NotebookRead`). A path that does not exist, or that names a directory, is ignored: the tool fails on it and reads nothing. |
| `Grep` | `tool_input.path` (default: the hook input's `cwd`), trimmed, with a leading `~` or `~/` expanded from `HOME` (Claude Code passes `Grep` paths unexpanded). A file is scanned directly. A directory is walked the way Claude Code 2.1.301 runs ripgrep for `Grep`: hidden files included, the directories `.git`, `.svn`, `.hg`, `.bzr`, `.jj`, and `.sl` excluded, `.gitignore` honoured, symlinks not followed, filtered by `type` and by `glob`. A `glob` is split as Claude Code splits it: on whitespace, then each piece on commas unless the piece contains both `{` and `}` (`*.md,*.env` and `*.md *.env` are two globs, `*.{md,env}` is one). The walk stops at `limits.walk_files`; the remainder is treated as an error (`on_error`, reason `walk limit`). |
| `Bash` | The files `bash_targets_within` names for `tool_input.command` run in `cwd` (see `src/bash.rs`). `$HOME`, `${HOME}`, and a leading `~` or `~/` are expanded from the hook's `HOME`, and `$PWD` and `${PWD}` from `cwd`, unless the same command line assigns, exports, or unsets that variable, changes directory, or runs code in the current shell (`eval`, `source`). `on_unresolved` applies when the command may read files that cannot be named; its default is `allow`, so such commands get no decision unless the configuration says otherwise. |

| `Glob` | No content is read. The names under `tool_input.path` (default `cwd`; `~` expanded as for `Grep`) that match `tool_input.pattern` are walked (hidden entries included, ignore files not honoured, the version-control directories above skipped, symlinks below the search root not followed, at most `limits.walk_files` names), and each name, relative to `cwd`, is scanned as an empty file of that name, so only rules that need no content match: `pkcs12_file` (`.p12`, `.pfx`; secret 90, which asks by default), the key-file and credential-file name rules of `secrets-core/paths.yar` (`id_rsa`, `id_dsa`, `id_ecdsa`, and `id_ed25519` without `.pub`; `.env`, `.env.local`, `.env.production`, and the other dotenv variants with values; `.aws/credentials`, `.netrc`, `.pgpass`, `.git-credentials`, `.htpasswd`, `.jks`, `.keystore`, `.ppk`, and GnuPG secret keyrings; secret 80, which asks by default; `.pem` files and a bare `credentials` file score 40, below the default thresholds), and `path_biometric_name` (`voiceprint`, `embedding`, `speaker`, `enroll`, `faceprint`; biometric 30, below the default thresholds). An absolute `pattern` is searched from the directory before its first segment with a glob character, and leading `./` and `../` segments of a relative pattern move into the search root (`../` as its parent). A root that is a symlink to a directory is walked. A name that cannot be scanned (the rules did not load) follows `on_error`; a walk that reaches the limit gets no decision for the names past it. The reason offers no reading guidance: `RiskGrep: file name <path> scored <category> <score> (<rule ids>). Threshold: <ask|deny> at <n>.` |
| MCP tools (`mcp__<server>__<tool>`) | The paths in the input fields that the tool's MCP entry names (see [MCP tools](#mcp-tools)), each a string or a list of strings, resolved like `Read` paths: relative to `cwd`, with a leading `~` or `~/` expanded, and not trimmed. Kind `read` scans each path that is a file, `walk` scans the regular files under each path (walked as for `Glob`; a symlink below the path is neither followed nor scanned; at most `limits.walk_files`; the remainder is treated as an error, as for `Grep`), `names` judges the names of each path and the entries under it as `Glob` does (to `max_depth` levels when set), and `none` reads nothing. A tool with no entry, or whose fields are all absent or hold anything but a string or a list of strings, is unresolved: the MCP `on_unresolved` applies (default `allow`, so no decision; see [Unresolved MCP tools and decisions](#unresolved-mcp-tools-and-decisions)) with reason `RiskGrep: could not determine the files <tool> reads`. An entry with `decision` gets that decision on every call, with reason `RiskGrep: the MCP configuration asks before <tool>` or `RiskGrep: the MCP configuration denies <tool>`. |

Decision rules (`src/decide.rs`): every finding is graded `ask` or `deny`: a category score at or above its `ask` or `deny` threshold (defaults: `biometric` ask at 50 and deny at 75, `secret` ask at 80 and deny at 95), an unscanned target (`on_error`, default `ask`), a skipped target (`on_skipped`, default `allow`), or an unresolved Bash command (`on_unresolved`, default `allow`). The highest grade over all findings wins, so a lower-scoring `ask` finding does not hide an unscanned target whose `on_error` is `deny`. Only findings of the winning grade appear in the reason. `block` is treated as `deny`; `allow` produces no output.

Reason text never contains file content or line text:

`RiskGrep: <path> scored <category> <score> (<rule ids>) on lines <ranges>. Threshold: <ask|deny> at <n>. <guidance>`

With several findings the top three by score are listed, followed by `, and N more.` A finding names at most five rule ids, then `and N more`. The line ranges and the guidance are described under [Partial reads](#partial-reads). Other reasons: `RiskGrep: could not scan <path> (<reason>)`, `RiskGrep: could not scan <n> of <m> members of <path> (<what was not read>)`, `RiskGrep: read only part of <k> of <m> members of <path> (<what was not read>)`, `RiskGrep: could not scan <n> and read only part of <k> of <m> members of <path> (<what was not read>)`, `RiskGrep: read only part of <path> (<what was not read>)` for a file past a read limit, and `RiskGrep: could not scan part of <path> (<what was not read>)` for a file with a part that could not be read (which follow `on_partial`), `RiskGrep: command reads files that could not be determined`, `RiskGrep: scan exceeded time budget`, `RiskGrep: unreadable hook input`, and `RiskGrep: configuration error (invalid config <path> at line <l>, column <c>)`, which names the position of a configuration error but quotes none of the file. When a reason holds several of these, a period separates them and whatever follows.

Failures apply `on_error` (default `ask`) and the exit status is always 0. How Claude Code treats a hook that exits with another status and no JSON decision depends on the Claude Code version (documented as a non-blocking error that lets the call proceed), so a failure asks or denies only through a JSON decision. This covers malformed hook input, a configuration error (always `ask`), a panic (the default panic message is suppressed), and a scan that exceeds the time budget.

Repository: the root is the nearest ancestor of the hook input's `cwd` (itself included) that holds a `.git` entry, a directory or a file (worktrees and submodules). The walk (shared with the command line, `riskgrep_core::repo`) stops at `/`, before the parent of `$HOME`, and at `GIT_CEILING_DIRECTORIES`; a `cwd` inside a `.git` directory has no repository, and a root (or its `.git`) not owned by the effective user is not a root. Git is not spawned. A repository's `.riskgrep.toml` is read only if the user config lists the repository in `trusted_repos`.

Time budget: one budget (`claude_code.time_budget_ms`, default 2000, capped at one hour) covers the whole call. Bash analysis gets at most 25% of it (at least 50 ms). The scan runs on a worker thread; the main thread waits for the remainder.

## MCP tools

MCP entries are shared by every agent integration and keyed by server and tool name under `[mcp]`; each integration maps its own tool names onto a server and a tool. Claude Code names an MCP tool `mcp__<server>__<tool>`; the hook splits the name as Claude Code 2.1.318 does: the server is the text between `mcp__` and the next `__`, and the tool everything after it (which may itself hold `__`). That rule was read from the JavaScript embedded in the installed binary (`/opt/homebrew/Caskroom/claude-code@latest/2.1.318/claude`), found by searching it for `split("__"),[r,t,...s]=n`, the start of the function that returns `serverName` (`t`) and `toolName` (`s.join("__")`). An entry names the input fields that hold the tool's paths and what the tool does with them. Built-in entries cover the official filesystem server (field names from `src/filesystem/server.ts` in `modelcontextprotocol/servers`) under the server name `filesystem`, and Desktop Commander (field names from the input schemas its server reports) under `desktop-commander` and under `plugin_desktop-commander_desktop-commander`, the server name of its Claude Code plugin:

| Server | `read` | `walk` | `names` | `none` |
| --- | --- | --- | --- | --- |
| filesystem | `read_file`, `read_text_file`, `read_media_file` (`path`), `read_multiple_files` (`paths`) | | `list_directory`, `list_directory_with_sizes` (`path`, depth 1), `directory_tree`, `search_files` (`path`) | `get_file_info`, `list_allowed_directories`, `write_file`, `edit_file`, `create_directory`, `move_file` |
| Desktop Commander | `read_file` (`path`), `read_multiple_files` (`paths`) | | `start_search`, `list_directory` (`path`) | `get_file_info` |

Desktop Commander's `start_search` is judged by the file names under its `path`, whatever its `searchType`: the content of the files a content search reads is not scanned, because scanning every file under the search path would not fit the hook's time budget on large trees. No built-in entry has kind `walk`; it is available for user entries. Desktop Commander's other tools (its shell and process tools among them) have no entry and are unresolved.

To add a server, or a server registered under another name, add an entry per tool to the user config (`~/.config/riskgrep/config.toml`), keyed by the server name and the tool name:

```toml
[mcp.servers.notes.tools.open_note]
paths = ["file", "files"]   # input fields holding a path or a list of paths
kind = "read"               # read (default), walk, names, or none

[mcp.servers.notes.tools."*"]
kind = "none"               # every other tool of this server reads no file
```

An entry replaces a built-in entry, or one from an earlier file, with the same server and tool key. A server or tool key may contain `*`, which matches any run of characters within the server name or within the tool name. When several entries match, an exact server key wins over a pattern, then an exact tool key over a pattern, and among entries equally specific the first in key order (server key, then tool key) wins. `max_depth` limits a `names` entry to that many levels below each path (1: a directory's own entries). An empty server or tool key, a `read`, `walk`, or `names` entry without `paths`, and an unknown kind or field are configuration errors.

`claude_code.mcp_tools`, the form earlier releases used, still works and applies to Claude Code only. It is keyed by the full tool name as Claude Code shows it (`[claude_code.mcp_tools."mcp__notes__open_note"]`), which the hook splits into a server and a tool as above; a key with no `__` after its server part, such as `mcp__*`, covers every tool of the servers it matches. For the same server and tool, a `claude_code.mcp_tools` entry wins over an `[mcp]` entry, in whichever file either is set. A key that does not start with `mcp__` is a configuration error. Unlike earlier releases, a `*` in such a key no longer matches across the `__` between the server and the tool, and an exact server name now wins over a server pattern whatever their key order.

### Unresolved MCP tools and decisions

A call whose files cannot be determined (a tool with no entry, or whose fields are absent or malformed) gets the MCP `on_unresolved` action: `claude_code.mcp.on_unresolved` when set, else `mcp.on_unresolved`, else `claude_code.on_unresolved`, which covered MCP tools as well as shell commands in earlier releases; all default to `allow`. So `claude_code.on_unresolved = "ask"` alone still asks about both, and adding `mcp.on_unresolved = "allow"` keeps it to shell commands. An entry can instead carry a fixed `decision` (`allow`, `ask`, `deny`, or `block`, which is treated as `deny`), given to every call whatever its input; such an entry takes no `paths`, `kind`, or `max_depth`. Under a server's `"*"` tool key it is a default for that server's tools without an entry of their own, while their own and built-in entries still apply:

```toml
[mcp]
on_unresolved = "allow"     # MCP tools with no entry (default)

[mcp.servers.desktop-commander.tools."*"]
decision = "ask"            # its shell and process tools, which read files no field names

[mcp.servers.plugin_desktop-commander_desktop-commander.tools."*"]
decision = "ask"            # the same server installed as a Claude Code plugin
```

`[claude_code.mcp]` takes the same keys as `[mcp]` and applies to Claude Code only: its `on_unresolved` wins over `mcp.on_unresolved`, and its entry for a server and tool replaces the `[mcp]` entry with the same keys. A `claude_code.mcp_tools` entry, which may also carry `decision`, wins over both. The `kind = "none"` and `decision = "allow"` forms both keep a server's tools quiet when `on_unresolved` asks.

Covered by `cargo test -p riskgrep-core --test mcp`, `cargo test -p riskgrep-core --test config mcp_`, `cargo test -p riskgrep-claude --lib mcp`, and `cargo test -p riskgrep-claude --test hook` (`mcp_*`, `glob_*`, `unmapped_mcp_tool_follows_on_unresolved`, `user_added_mcp_entry_is_used`, `shared_mcp_entry_is_used`, `claude_code_mcp_tools_entry_wins_over_shared_entry`, `agent_section_decision_overrides_shared_entry`).

## Partial reads

Partial reads are offered only for findings from rules marked `line_complete`: rules whose every match gets its own location and stays on the line of that location. The gitleaks converter marks a rule when, in its `span_regex`, nothing up to the end of the capture group holding the secret can match a line feed and the rest is either unable to match one or a single element whose alternatives that can are at most one byte long, such as gitleaks' trailing delimiter `(?:[\x60'"\s;]|\\[nr]|$)`; when the secret is the whole match or the first non-empty group, no part of the regex may match a line feed. Any literal or class that admits one counts, including `\s`, `\W`, `\D`, negated classes such as `[^"]`, `[\s\S]`, dot-all `.`, `[[:space:]]`, and `\n` or `\x0a`. A line feed can then only be the last byte of a match, so each match ends on its secret's line. In the shipped `secrets-core` ruleset that is 211 of the 222 converted rules (`grep -c 'line_complete = true' crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`; also stated in `crates/riskgrep-core/rulesets/secrets-core/UPSTREAM.md`; for example `aws_access_token`, `github_pat`, `openai_api_key`, `anthropic_api_key`, `stripe_access_token`, and the `slack_*` tokens, `generic_api_key`, and the provider-context rules such as `adafruit_api_key`), and `cargo test -p riskgrep-core --test ruleset_secrets every_line_complete_rule_locates_every_secret` checks each with generated secrets: several on one line, on adjacent lines, with CRLF line endings, with each line ending right after its secret, and the last one at the end of a file without a final line feed. `private_key`, `kubernetes_secret_yaml`, and `atlassian_api_token` are not marked, nor are the hand-written rules: `pkcs12_keystore` and `der_key_file` locate only the DER header of a binary file, the path and tensor rules have no text lines, and the printed-float rules do not locate runs shorter than 64 floats or arrays of lengths other than common embedding widths.

A reason for a category finding names the lines its evidence covers, as numbers only (`on line 10`, `on lines 3–7, 20`; adjacent and overlapping ranges are merged, and after 50 ranges the rest are counted as `and N more`), and ends with what the agent may do instead. For one file whose flagged lines are known:

`Do not read this file by other means (Bash, Grep, scripts). To use the rest of it, Read it with offset and limit ranges that exclude the lines above, or ask the user.`

When no partial read is possible (below), no lines are named and the reason ends:

`Do not read this file by other means (Bash, Grep, scripts). No partial read is available for this file; ask the user.`

When the file can be shown masked, the reason also offers that, between the two sentences (see [Masked view](#masked-view)):

``Do not read this file by other means (Bash, Grep, scripts). For a view with every match masked, run `/path/to/riskgrep show /path/to/app.env`. No partial read is available for this file; ask the user.``

A `Grep` or `Bash` reason that lists several files uses the plural forms (`these files`, `Read each with offset and limit ranges`), or, when only some of the files have known lines, `Read a file with listed lines using offset and limit ranges that exclude them; no partial read is available for the others; ask the user.` The `deny` reason reaches the model; the `ask` reason is shown to the user in the permission prompt.

A `Read` call with `offset`, `limit`, or both asks for lines `offset` through `offset + limit - 1` (`offset` defaults to 1, and without `limit` the range runs to the end of the file). The hook widens that range by one line on each side, so a difference of one in line numbering can only make it stricter. A category whose flagged lines the widened range does not touch is dropped from the decision; every other finding still applies, including `on_error` for a target that could not be scanned and `on_partial` for a target read in part, whatever range the call asks for. A `Read` with neither field is judged on the whole file, as is one whose `offset` or `limit` is not a positive integer (0, negative, fractional, a string, or null). `Grep`, `Bash`, and `NotebookRead` are always judged on whole files, whatever their input holds. The flagged lines come from the evidence already in the report, so a cached file is not scanned again.

No partial read is possible, and the whole file is judged, when any of these holds for a file with a finding at or above a threshold:

- the file was not read whole: `partial` (a text file over 8 MiB, scanned at its ends, or any other [file read in part](known-limitations.md#files-read-in-part)), `unscanned`, or `skipped`;
- the file is not text: a key store or a tensor file, read by its structure;
- some evidence in a category at or above a threshold comes from a rule not marked `line_complete` (a PEM block's `private_key`, a Kubernetes `Secret`, a printed float array), has no location (path rules such as `pkcs12_file`), an unknown line (0: evidence in the tail of a sampled file), or structural facts (tensor shapes);
- the file name ends in `.ipynb` (any case): Claude Code 2.1.301 ignores `offset` and `limit` for notebooks and returns every cell.

Evidence in a category below every threshold does not count. Only findings of the winning grade are listed, so a `deny` reason does not name the lines of an `ask` finding in the same file; a partial read that avoids the denied lines but touches the others gets the `ask`, with those lines named. Covered by `cargo test -p riskgrep-claude` (`src/decide.rs` unit tests and the `read_range_*`, `no_partial_read_*`, and `cached_runs_decide_as_uncached_runs` tests in `tests/hook.rs`). The rule marks are checked by `cargo test -p xtask --test convert line_complete` and `cargo test -p riskgrep-core --test ruleset_secrets line_complete`.

## Masked view

`riskgrep show FILE` prints the file with every match of every rule masked, or a structural summary of a file that is not text (see the [README](../README.md#command-line)). Running it on a flagged file is safe only when the command really runs the `riskgrep` binary with nothing else attached, so the hook recognises one command shape and analyses anything else as usual, which flags the file it names:

```text
TRUSTED show [--rule-ids] [--lines FIRST:LAST] [--] FILE
```

- `TRUSTED` is the path of the regular file named `riskgrep` in the directory of the hook's own executable (where `cargo install` puts both binaries), after links to the hook are followed; the `riskgrep` file itself must not be a link, which could point outside that directory. Without one, nothing is offered or let through. A relative name found through `PATH`, another binary named `riskgrep`, a link to the trusted one, or a wrapper (`command`, `env`, `exec`, an assignment such as `HOME=…`) is not the trusted path. Whoever can replace that file can replace the hook itself.
- The command is one line of words separated by spaces or tabs. Each word is plain (letters, digits, and `_ . / - + , @ % :`) or wholly single-quoted with no control character inside, so there is no second command, pipe, redirect, substitution, expansion, glob, or comment.
- The options are `--rule-ids` and `--lines FIRST:LAST`, each at most once and in any order, then an optional `--`, then exactly one file, which must not start with `-` unless it follows `--`. Options that would change what is scanned do not exist on `show`.
- The command itself cannot bring a shell function that runs instead of the trusted path: no definition can come before it in a single simple command, and shell functions, aliases, and exported variables defined in one Claude Code `Bash` call were absent from the next (measured with Claude Code 2.1.318 by two consecutive `Bash` calls: `function /usr/bin/true { echo SHADOWED; }; export PROBE=1; shopt -s expand_aliases; alias probe='echo ALIASED'; /usr/bin/true` printed `SHADOWED`, and the next call, `/usr/bin/true && echo plain; echo "${PROBE:-unset}"; type probe`, printed `plain`, `unset`, and `probe: not found`). A function of that name defined in a shell startup file can run instead of it, because bash and zsh both accept a name holding slashes and look functions up before running a path (measured with `BASH_ENV=FILE bash -c /usr/bin/true` and `ZDOTDIR=DIR zsh -c /usr/bin/true`, where `FILE` and `DIR/.zshenv` define `/usr/bin/true() { echo SHADOWED; }`: each printed `SHADOWED`). The exemption does not cover a shell whose startup files are not the user's own.

The hook gives that command no decision and does not scan the file. A reason offers the command for each listed file that was read as text (whole or in part, since the command reads up to 64 MiB whole), is not an archive, and has no evidence with structural facts, when its path can be written as a word of that shape (a path holding a single quote or a control character is not offered); with several such files it names the form `TRUSTED show FILE`. The command still refuses whatever it cannot mask. Covered by `cargo test -p riskgrep-claude` (`src/show.rs` and `src/decide.rs` unit tests, and `the_offered_masked_view_is_let_through_and_nothing_else` in `tests/hook.rs`).

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
