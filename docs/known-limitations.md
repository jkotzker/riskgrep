# Known limitations

RiskGrep scores files with rules and simple structural checks, not with a model of what the data means. This page lists the main things it does not detect, what it may flag wrongly, and why, so you can judge how much to rely on a score. Each entry says what is not covered, why, and how it shows up. The measurements behind the detection entries are in [`eval/README.md`](../eval/README.md). Open work and newly found gaps are tracked in [GitHub Issues](https://github.com/jkotzker/riskgrep/issues).

- [Scope and threat model](#scope-and-threat-model)
- [Biometric embeddings](#biometric-embeddings)
- [Secrets](#secrets)
- [File handling](#file-handling)
- [Claude Code hook](#claude-code-hook)
- [Git hook](#git-hook)
- [Cache](#cache)

## Scope and threat model

### Accidental exposure by a cooperative agent, not an adversary

- **Not covered:** an agent or user who works around the checks on purpose. An agent with shell access running as the same user can edit the user configuration, write cache rows, replace the compiled rules bundle, or read a file through a path RiskGrep does not see.
- **Why:** RiskGrep protects against accidental exposure. Ownership and mode checks on the cache directory keep other users out, but nothing stops a process with the same user's rights. A keyed integrity check on the bundle was considered and not adopted: a same-user attacker can read any key stored where the hook can read it.
- **How it shows up:** nothing is reported; the protection is absent by design.

### Files are checked, command output is not

- **Not covered:** the output of a command or program (a database client, `env`, a script that prints a credential), and data that never passes through a file the hook can name. Tools other than `Read`, `NotebookRead`, `Grep`, and `Bash` (other MCP tools, web fetches) are not checked at all.
- **Why:** the hook runs before a tool call and reasons about the files the call would read.
- **How it shows up:** the hook produces no decision and the call proceeds.

### Scores are heuristic

- **Not covered:** a score is not a verdict. A matching rule shows a pattern, not that the data is sensitive, and the absence of a match does not show the absence of sensitive data.
- **Why:** detection is rule- and structure-based. The evaluation corpus is public repositories plus generated files, and recall on the generated positives is circular by construction (see [`eval/README.md`](../eval/README.md)).
- **How it shows up:** false positives and false negatives, at the rates the evaluation reports.

## Biometric embeddings

### Only `.npy`, `.npz`, safetensors, and printed float arrays are inspected

- **Not covered:** embeddings and voiceprints in other containers: PyTorch pickles (`.pt`, `.pth`), ONNX, HDF5, Parquet, SQLite and vector databases, and biometric data inside an archive. Raw audio and face images are not inspected (images are skipped).
- **Why:** only the formats whose headers state shape and type are parsed.
- **How it shows up:** such files score at most 30 from the file-name rule (`voiceprint`, `embedding`, `speaker`, `enroll`, or `faceprint` in the path), or nothing.

### How embeddings are recognised

- **What is caught:** a float tensor or printed float array whose last dimension is in `embedding_dims` (`128, 192, 256, 384, 512, 640, 768, 1024, 1536, 2048, 3072, 4096`) with at most two dimensions before it scores 70 (`.npy`, `.npz`, unnamed safetensors tensors) or 60 (printed arrays); a safetensors tensor named like an embedding (`speaker_embedding`) scores 85 at any width; a bank of 3 or more tensors of one embedding shape with flat names, making up more than half of the file's float tensors, scores 85 to 97.
- **What is missed:** banks stored under hierarchical names (`model.speakers.0.vec`, `model_p225`) or alongside at least as many other float tensors as bank vectors; banks of two vectors (70, not 94); several embeddings of different widths in one file (70, not a bank); widths outside the list (for example 100, 300, or 1000) and arrays with three or more leading dimensions (25 to 40, not flagged); and single tensors whose names contain a parameter word as a token (`weight`, `bias`, `kernel`, `scale`, `gamma`, `beta`, and others), a layer segment (`encoder`, `layers`, `blocks`), or an index segment (`encoder.0.out`, `spk_12_emb`), which score 25 (safetensors) or 30 (`.npz`). A name holding both an embedding word and a parameter word (`speaker_embedding.weight`) is not flagged by name.
- **Why:** shape and names are the only signals in a header. Any width would match ordinary scientific data, and the name exclusions keep model checkpoints out.
- **How it shows up:** a missed file scores below every default threshold. In the other direction, ordinary arrays of an embedding width are flagged: a Gaussian mixture's `means` [8, 192] or a flat MLP's biases score 70 (ask in Claude Code; below the git hook's block threshold of 75), a test that prints an expected float array of an embedding width scores 60, and a checkpoint whose flat parameter names are not on the exclusion lists can be taken for a bank (a GPT-2 style checkpoint with names `h0_ln_1_g` and `h0_ln_1_b`, all [768], scores 86 as an `.npz` and 85 as safetensors). In the evaluation's 55,877 scanned public-repository files, 5 such files were flagged.

## Secrets

### Coverage is gitleaks v8.30.1 plus local key-store rules

- **Not covered:** credential formats gitleaks does not define or that were added after v8.30.1, internal token formats of your own services, and secrets that are encoded, split across lines, built at run time, or stored encrypted. A small share of matches differ from gitleaks: of 5,206 generated matches for the 217 converted rules that have a regex and no path condition, 5,203 agree, 3 are missed (2 for `contentful_delivery_api_token`, 1 for `discord_client_secret`, where YARA-X keeps a different one of a regex's overlapping alternatives), and 1 is reported that gitleaks drops (a `curl_auth_header` value whose entropy equals the threshold).
- **Why:** the 222 rules converted from one pinned gitleaks release (`crates/riskgrep-core/rulesets/secrets-core/UPSTREAM.md`) and two hand-written key-store rules are the only credential rules. The local changes to upstream are listed in `UPSTREAM.md`.
- **How it shows up:** no evidence for such a credential unless the generic rule happens to match.

### Generic-secret limits

- **Not covered:** generic `name = "value"` credentials whose key name does not end in a credential noun (`secret`, `password`, `token`, `credential(s)`, `creds`, `auth`, an `…_key` form such as `api_key` or `access_key`, or an uppercase `[A-Z0-9_]+_KEY`), for example `consumer_key` or `master_key`; values made only of letters, `_`, `.`, or `-` (gitleaks' identifier allowlist, kept by the converter); and values containing `false` (or starting with `true`, or ending with `null`), which gitleaks' global allowlist drops for every converted rule because its expression `(?:(?i)^true|false|null$)` binds the anchors to the outer alternatives only.
- **Why:** these rules are converted from gitleaks with a stricter key name; broader names flagged too many ordinary files.
- **How it shows up (false negatives):** no evidence for such a line; provider-specific rules still find credentials in a provider's own format.
- **How it shows up (false positives):** credential-named assignments with placeholder or test values in test code, test configuration, and documentation score 80, the generic rule's weight. That blocks a commit in the git hook (threshold 80) and asks in Claude Code, whose default `secret` ask threshold is 80 (only provider-specific formats and private keys, at 95, reach `deny`). In the evaluation's 55,877 scanned public-repository files, 21 such files were flagged, most of the 25 secret false positives (0.45 per 1,000). Raise `claude_code.thresholds.secret.ask` above 80 to stop prompting on them, at the cost of reading real generic credentials without a prompt.

### gitleaks' global path allowlist skips lockfiles, `node_modules`, and similar

- **Not covered:** secrets in files whose path matches gitleaks' global path allowlist, which every converted rule skips (the hand-written key-store rules still apply): any path containing `gitleaks.toml`; `node_modules/`, `bower_components/`, `vendor/` Go module directories, and Ruby and Python library directories; lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `gradle.lockfile`); `gradlew` and `mvnw` wrappers; and files ending in `.bin`, `.pdf`, `.docx`, `.xlsx`, `.exe`, `.pdb`, and font and image extensions. The list is `gitleaks_global_path_allowlist` in `crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`.
- **Why:** it is converted unchanged from gitleaks, whose defaults assume that vendored and generated files hold no first-party secrets.
- **How it shows up:** no evidence from the converted rules for a secret in such a path, including a real one in a file named like a lockfile or inside `node_modules/`.

### Binary private keys are recognised only as DER in `.der` and `.key` files of up to 1 MiB

- **Not covered:** encrypted PKCS#8 keys, binary key formats that are not DER (OpenSSH's binary format, JKS key stores), DER keys under other file names (`id_ec`, `server.pem` holding DER), DER keys in a `.der` or `.key` file larger than 1 MiB, and DER keys whose length uses three or more bytes (`30 83` and above).
- **Why:** a `.der` or `.key` file of at most 1 MiB that starts with a DER SEQUENCE header (`30` and a short-form length, `81`, or `82`) is read as a key store, and the `der_key_file` rule reports SEC1, PKCS#1, PKCS#8, and RFC 5958 version 2 private keys in it; other files are classified by content, and DER is binary.
- **How it shows up:** a non-DER binary key or a DER key under another name is skipped as a binary of unknown format (`on_skipped` applies: allow by default). An encrypted PKCS#8 key in a `.der` or `.key` file is read and scores 0. PEM-encoded keys are found by `private_key` under any name.

## File handling

### Large text files are scanned only at their ends

- **Not covered:** the middle of a text file above 8 MiB. Only the first and last 1 MiB are read, and the report says `partial`. Findings in the last MiB carry their true byte offsets but no line numbers.
- **Why:** bounds scan time and memory; both limits (`limits.text_max`, `limits.sample`) are configurable.
- **How it shows up:** a `partial` status with the unread byte range; a secret inside that range is not found. Text output and git pre-commit messages show `line unknown` for findings in the last MiB; JSON output keeps `line_start` and `line_end` at 0 for them. For a partly read staged file the git hook scores every finding in the sample, not only those on added lines.

### Archives, PDFs, SQLite, images, UTF-16 text, and unknown binaries are not scanned

- **Not covered:** the contents of archives and containers recognised by header (zip other than `.npz`, gzip, tar, 7z, PDF, SQLite), images, binary files of unknown format, and text whose first 8 KiB contains a NUL byte, which includes UTF-16 and UTF-32 text. Only `.npy`, `.npz`, safetensors, and key-store files (PKCS#12, DER) are read as binaries, so a secret inside a compiled binary or a database file is not found.
- **Why:** unpacking archives adds decompression risk and time, and a NUL byte in the sniff window marks a file as binary.
- **How it shows up:** archives are reported `unscanned` (so `on_error` applies: ask in the Claude Code hook, block in the git hook); images, unknown binaries, and UTF-16 text are reported `skipped` (so `on_skipped` applies: allow by default). Measured with the release build: a UTF-16 file holding a generated AWS key is skipped, while its ASCII form scores secret 95.

### The time budget can leave a file unscanned

- **Not covered:** the content of a file whose scan takes longer than `limits.time_budget_ms` (2,000 ms by default), in the command line and the git hook, and `claude_code.time_budget_ms` in the Claude Code hook, which also covers the first call after a rules change when the rules bundle has not been compiled yet.
- **Why:** a bound on time per call. Dense hexadecimal text is the slowest ordinary input: measured on an Apple M4 Max with the release binary and `--no-cache` (whole command, including compiling the rules), 8 MB of 40-character hex lines took 1.36 s.
- **How it shows up:** the file is reported `unscanned` with reason `timeout` (so `on_error` applies), and the Claude Code hook asks with `scan exceeded time budget`. Run `riskgrep rules compile` once after installing or changing rules to compile the bundle ahead of the first call.

## Claude Code hook

### The Bash analysis is a best-effort static reading, and unresolved commands get no decision by default

- **Not covered:** variables, functions, and aliases defined elsewhere; files a program opens at run time; anything a script or interpreter does. A program outside the analysis tables is resolved as reading only the files it names as arguments. A command whose files the analysis cannot determine (a recursive search without a named file, an interpreter, a git subcommand that prints repository content, a word built from a variable other than `HOME` and `PWD`) is `unresolved`, and with the default `claude_code.on_unresolved = "allow"` it gets no decision unless a file it does name crosses a threshold.
- **Why:** the parser (brush-parser 0.4.0, pinned) sees syntax only, and classification is by command name and hand-written tables, so an executor missing from them is invisible. The default keeps routine commands (`grep -rn`, `git diff`, `python3 script.py`) from prompting on every call.
- **How it shows up:** the command runs without a prompt. Measured with the release `riskgrep-claude`, an isolated HOME, and `a.txt` holding a generated AWS key that scores secret 95:

| Command | Default (`allow`) | `on_unresolved = "deny"` |
|---|---|---|
| `cat "$PWD/a.txt"`, `cat ~/proj/a.txt` | deny (secret 95.0) | deny (secret 95.0) |
| `cat $F`, `cd h && cat $PWD/a.txt` | no decision | deny (unresolved) |
| `grep -rn aws .`, `rg aws` | no decision | deny (unresolved) |
| `python3 x.py`, `git diff`, `bash -c "$X"` | no decision | deny (unresolved) |
| `tmux new -d "cat a.txt"` | no decision | no decision |

Setting `on_unresolved = "ask"` or `"deny"` under `[claude_code]` prompts or blocks on unresolved commands, at the cost of prompting on routine ones. It does not cover programs outside the tables (the last row), which are not marked unresolved.

### Partial reads are conservative

- **Not covered:** a partial `Read` of a file with a finding from a rule not marked `line_complete`. Of the 222 converted gitleaks rules, 59 are marked; the others include `private_key`, `kubernetes_secret_yaml`, `generic_api_key`, `anthropic_api_key`, and `openai_api_key`. No hand-written or biometric rule is marked, and binary, sampled (`partial`), and structural findings never allow a partial read.
- **Why:** a rule is marked only when its regex cannot match a line feed, so that every match lies on the lines its location names. Many gitleaks regexes can include a line feed through a trailing delimiter or whitespace even when the secret sits on one line.
- **How it shows up:** the reason ends with `No partial read is available for this file; ask the user.`, and every `Read` of the file, with or without `offset` and `limit`, gets the decision.

### Files can change between the check and the read

- **Not covered:** a file whose content changes after the hook scans it and before the tool reads it, including a file the same command writes before reading it.
- **Why:** the hook runs before the tool call and cannot lock the file.
- **How it shows up:** the earlier content is the one that was scored. For a `Read` with `offset` and `limit`, lines inserted or removed in between can also move a flagged line into the requested range after the hook allowed it.

### Grep handling mirrors Claude Code 2.1.301

- **Not covered:** files that Claude Code's `Grep` would search but the hook does not walk, if a later Claude Code version changes how `Grep` runs ripgrep, and a later version whose `Read` numbers lines differently for partial reads. The hook mirrors version 2.1.301: hidden files are searched, the directories `.git`, `.svn`, `.hg`, `.bzr`, `.jj`, and `.sl` are excluded, `.gitignore` is honoured, symlinks are not followed, the `glob` field is split on whitespace and then on commas, and a leading `~` or `~/` in `path` is expanded from `HOME`.
- **Why:** the hook predicts which files the tool will read; it does not run the search itself.
- **How it shows up:** after a Claude Code update that changes these defaults, a `Grep` call may read files the hook did not scan, and no decision is given for them. Exclusions that Claude Code derives from permission rules are not mirrored, so the hook may scan more files than `Grep` reads.

## Git hook

### Diff mode checks added lines, except renamed, copied, and binary files, which are checked whole

- **Not covered:** limiting a renamed or copied file, or a binary file (key store or tensor file), to the lines a commit adds. A secret already in such a file blocks the commit that renames, copies, or edits it.
- **Why:** rules can depend on the path (`der_key_file` needs a `.der` or `.key` name, `pkcs12_file` a `.p12` or `.pfx` name), so a renamed file's old verdict does not carry over, and the offsets of findings in a binary file are not lines of a diff.
- **How it shows up:** `git mv` of a file holding a secret blocks the commit until the secret is removed, baselined, or ignored. Baseline fingerprints include the repository-relative path, so a baseline entry recorded under the old path stops matching after a rename; regenerate it with `riskgrep baseline <path>`.

### Type changes into a symlink and submodule pointers are not scanned

- **Not covered:** a staged path that became a symlink through a type change (a regular file replaced by a symlink), and submodule pointers (gitlinks). Newly added or modified symlinks are scanned, and a type change into a regular file is scanned whole.
- **Why:** the hook does not score a type change whose new side is a symlink, and a gitlink holds a commit id, not content.
- **How it shows up:** nothing is scanned for those paths.

## Cache

### The cache is trusted when it passes ownership and mode checks

- **Not covered:** a same-user process writing cache rows or replacing the rules bundle (see the threat model above).
- **Why:** cache integrity beyond ownership and mode checks is outside the threat model.
- **How it shows up:** forged evidence rows are believed.

### Pruning removes by age and size, not by use

- **Not covered:** keeping a row or a bundle because it was used recently. Rows are aged by the time they were written, because a cache hit never writes (the Claude Code hook's cached-read path stays read-only), and a bundle is aged by its files' modification time. After the maximum age (`[cache] max_age_days`, default 30) a row that is still in use is removed and rewritten by the next scan of that file, and a bundle that is not the selection the command line resolves in the current directory, nor the Claude Code hook's selection outside a trusted repository, in the current repository, or in a repository listed in `trusted_repos` (for example one made by `--ruleset`) is compiled again once.
- **Why:** recording a last-used time on every hit adds a database write to a path with a 5 ms p95 target.
- **How it shows up:** a periodic rescan of files that did not change, and one recompile of a bundle used only with non-default options. The scores do not change.

### Pruning runs only from the command line and the git hook

- **Not covered:** a machine that uses RiskGrep only through the Claude Code hook never prunes: the hook does not, so the cache keeps growing until `riskgrep scan`, `riskgrep git pre-commit`, or `riskgrep cache prune` runs.
- **Why:** the hook's time budget is short and its cached-read path stays read-only.
- **How it shows up:** the cache directory grows with the number of files the hook has seen and with each rules change.

### Pruning shrinks the database with VACUUM, which blocks other writers

- **Not covered:** a scan that writes to the database while a prune is running. A prune that removes rows rewrites the database file (`VACUUM`) and holds the write lock while it does.
- **Why:** deleted rows leave free pages in the file, and only `VACUUM` returns them to the file system.
- **How it shows up:** a concurrent scan waits up to two seconds for the lock and then runs uncached for that run, with one `cache bypassed` line on standard error.
