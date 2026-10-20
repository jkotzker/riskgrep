# Claude Code hook

`riskgrep-claude` is a Claude Code `PreToolUse` hook. For `Read`, `NotebookRead`, `Grep`, and `Bash` calls it finds the files the call would read, scans them, and asks or denies when a category score reaches its threshold. Any other tool, and any call that crosses no threshold, produces no output and exit status 0. The hook never emits `allow`.

## Threat model

v1 protects against accidental exposure by a cooperative agent, which is what happened in the motivating incident. It does not resist an agent actively working around it: an agent with shell access running as the same user can edit the user config, write cache rows, or replace the compiled rules bundle.

## Installation

`riskgrep-claude print-config` prints a `settings.json` fragment (a hook entry and a permission rule) on stdout and a one-line instruction on stderr. Merge it into `~/.claude/settings.json` by hand. The hook entry uses matcher `Read|NotebookRead|Grep|Bash` and timeout 5 (seconds).

## Behaviour

| Tool | Files scanned |
| --- | --- |
| `Read`, `NotebookRead` | `tool_input.file_path` (`notebook_path` first for `NotebookRead`). A path that does not exist is ignored: the tool fails on it and reads nothing. |
| `Grep` | `tool_input.path` (default: the hook input's `cwd`). A file is scanned directly. A directory is walked as ripgrep walks it: hidden entries skipped, `.gitignore` honoured, symlinks not followed, filtered by `glob` and `type`. The walk stops at `limits.walk_files`; the remainder is treated as an error (`on_error`, reason `walk limit`). |
| `Bash` | The files `bash_targets_within` names for `tool_input.command` run in `cwd` (see `src/bash.rs`). `on_unresolved` applies when the command may read files that cannot be named. |

Decision rules (`src/decide.rs`): every finding is graded `ask` or `deny`: a category score at or above its `ask` or `deny` threshold, an unscanned target (`on_error`), a skipped target (`on_skipped`), or an unresolved Bash command (`on_unresolved`). The highest grade over all findings wins, so a lower-scoring `ask` finding does not hide an unscanned target whose `on_error` is `deny`. Only findings of the winning grade appear in the reason. `block` is treated as `deny`; `allow` produces no output.

Reason text never contains file content or line text:

`RiskGrep: <path> scored <category> <score> (<rule ids>). Threshold: <ask|deny> at <n>.`

With several findings the top three by score are listed, followed by `, and N more.` A finding names at most five rule ids, then `and N more`. Other reasons: `RiskGrep: could not scan <path> (<reason>)`, `RiskGrep: command reads files that could not be determined`, `RiskGrep: scan exceeded time budget`, `RiskGrep: unreadable hook input`.

Failures apply `on_error` (default `ask`) and the exit status is always 0. An exit other than 0 or 2 without a JSON decision is a non-blocking error that lets the tool call proceed (fail-open), so a failure can only ask or deny through a JSON decision. This covers malformed hook input, a configuration error (always `ask`), a panic (the default panic message is suppressed), and a scan that exceeds the time budget.

Repository: the root is the nearest ancestor of the hook input's `cwd` (itself included) that holds a `.git` entry, a directory or a file (worktrees and submodules). The walk stops at `/` and before the parent of `$HOME`; git is not spawned. A repository's `.riskgrep.toml` is read only if the user config lists the repository in `trusted_repos`.

Time budget: one budget (`claude_code.time_budget_ms`, default 2000, capped at one hour) covers the whole call. Bash analysis gets at most 25% of it (at least 50 ms). The scan runs on a worker thread; the main thread waits for the remainder.

## Cold rules cache

The first scan after install (or after any rules change) compiles the rules bundle and stores it in the cache directory. In a release build a cold call takes 0.58-0.9 s, inside the default 2 s budget, so the cache warms itself. A debug build took 13.5 s on the development machine, and a slow machine may also exceed the budget; the hook exits at the budget, so a compile that cannot finish is never cached and every call asks (`scan exceeded time budget`). In that case run `riskgrep scan <any file>` once with the same HOME before enabling the hook (`riskgrep rules compile` validates the rules but compiles without the cache, so it does not warm it). On macOS the cache is `~/Library/Caches/riskgrep` and `XDG_CACHE_HOME` is ignored.

## Verified against Claude Code 2.1.301

Documentation read through context7 (`/websites/code_claude`, pages `code.claude.com/docs/en/hooks`, `permissions`, `tools-reference`):

- PreToolUse input carries `tool_name`, `tool_input`, and `hook_event_name`; the decision goes in `hookSpecificOutput` with `hookEventName: "PreToolUse"`, `permissionDecision`, and `permissionDecisionReason`.
- `permissionDecision` values: `allow`, `deny`, `ask`, `defer`. For `ask` the reason is shown in the permission prompt; in a `-p` run no one can answer, the call is denied, and Claude reads the reason in the tool result. For `deny` the reason is shown to Claude. Precedence across hooks: `deny` > `defer` > `ask` > `allow`.
- `NotebookRead` does not appear in the current tool documentation. Notebooks are read with `Read` (`file_path`, `.ipynb`). The only notebook tool documented with a path field is `NotebookEdit` (`notebook_path`). The hook accepts `notebook_path` and falls back to `file_path` for `NotebookRead`, which keeps the matcher valid if the tool exists, and `Read` covers notebooks.
- Permission rules: Claude Code checks file permissions against `Edit(path)` and `Read(path)` rules only. A `Write(path)` rule is accepted but never consulted, and a startup warning says so. `Edit` rules apply to `Write` as well. `print-config` emits both `Edit(~/.config/riskgrep/**)` and `Write(~/.config/riskgrep/**)` as specified; the `Write` entry is redundant per the documentation.

Headless check (2026-10-19, `claude --version` = `2.1.301 (Claude Code)`, model `haiku`, temporary working directory, synthetic `emb.safetensors` with a `speaker_embedding` F32 [1,192] tensor, hook command `env HOME=<temp> XDG_CACHE_HOME=<temp> <repo>/target/debug/riskgrep-claude`, rules cache pre-warmed):

- The model chose `Bash` (`cd "$(pwd -P)" && ls -la emb.safetensors ...`), not `Read`, for the prompt `Read the file emb.safetensors and tell me its size.`
- The transcript's tool result for that call was `PreToolUse:Bash hook error: RiskGrep: <temp>/work/emb.safetensors scored biometric 85.0 (safetensors_float_tensor, safetensors_named_embedding). Threshold: deny at 75.` The final answer relayed the score and threshold and declined to work around it.
- The `Read` path was not exercised by this run (one run was allowed). It is covered by the binary tests in `crates/riskgrep-claude/tests/hook.rs`.
- The `env HOME=...` prefix is a deviation from a bare absolute path: on macOS the cache lives under `HOME`, so `XDG_CACHE_HOME` alone does not isolate it, and the real HOME was needed only for Claude's own authentication.
