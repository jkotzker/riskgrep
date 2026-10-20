# Known limitations

RiskGrep scores files with rules and simple structural checks, not with a model of what the data means. This page lists what it does not detect, what it may flag wrongly, and why, so you can judge how much to rely on a score. Each entry says what is not covered, why, how it shows up, and whether a fix is planned. The measurements behind the detection entries are in [`eval/README.md`](../eval/README.md). Entries are also the improvement backlog; "none decided" means the gap is known and no change is scheduled.

- [Scope and threat model](#scope-and-threat-model)
- [Biometric embeddings](#biometric-embeddings)
- [Secrets](#secrets)
- [File handling](#file-handling)
- [Claude Code hook](#claude-code-hook)
- [Git hook and command line](#git-hook-and-command-line)
- [Configuration and cache](#configuration-and-cache)

## Scope and threat model

### Accidental exposure by a cooperative agent, not an adversary

- **Not covered:** an agent or user who works around the checks on purpose. An agent with shell access running as the same user can edit the user configuration, write cache rows, replace the compiled rules bundle, or read a file through a path RiskGrep does not see.
- **Why:** v1 protects against accidental exposure, which is what happened in the motivating incident. Ownership and mode checks on the cache directory keep other users out, but nothing stops a process with the same user's rights. A keyed integrity check on the bundle was considered and not adopted: a same-user attacker can read any key stored where the hook can read it.
- **How it shows up:** nothing is reported; the protection is absent by design.
- **Planned fix:** none. Stronger isolation is outside v1.

### Files are checked, command output is not

- **Not covered:** the output of a command or program (a database client, `env`, a script that prints a credential), and data that never passes through a file the hook can name. Tools other than `Read`, `NotebookRead`, `Grep`, and `Bash` (other MCP tools, web fetches) are not checked at all.
- **Why:** the hook runs before a tool call and reasons about the files the call would read.
- **How it shows up:** the hook produces no decision and the call proceeds.
- **Planned fix:** a separate output-redaction tool is the intended backstop; it is not part of v1.

### Scores are heuristic

- **Not covered:** a score is not a verdict. A matching rule shows a pattern, not that the data is sensitive, and the absence of a match does not show the absence of sensitive data.
- **Why:** detection is rule- and structure-based. The evaluation corpus is public repositories plus generated files, and recall on the generated positives is circular by construction (see [`eval/README.md`](../eval/README.md)).
- **How it shows up:** false positives and false negatives, at the rates the evaluation reports.
- **Planned fix:** the rules are the part meant to improve; each entry on this page is a candidate.


## Biometric embeddings

### Embedding banks are found by a name and structure heuristic

- **Not covered:** a bank of speaker or face vectors stored under hierarchical names (for example `model.speakers.0.vec`, or `model_p225` with an underscore), or stored alongside at least as many other float tensors as bank vectors. Conversely, a model checkpoint whose parameter names are flat and not on the exclusion lists can be mistaken for a bank.
- **Why:** a file is treated as a bank when 3 or more tensors (or `.npz` members) share one embedding shape, have flat names, and make up more than half of the file's float tensors. Model checkpoints are excluded by their parameter names (`weight`, `bias`, `kernel`, `scale`, `gamma`, `beta`, `time_mix`, `mixer`, and others) and by layer segments (`layers`, `blocks`, `encoder`, `transformer`, `backbone`, `model`, also when followed by `_`) or dot- or slash-delimited index segments (`.0.`) in their names. Underscore-delimited numbers (`spk_3_emb`, `19_198_0001`) do not exclude a bank. A naming scheme outside those lists is not recognised.
- **How it shows up:** a missed bank scores 25 to 30, or 70 when one tensor is flat-named; a checkpoint mistaken for a bank scores 94 (deny in Claude Code, blocked by the git hook).
- **Planned fix:** none decided. Possible approaches are reading the checkpoint's metadata or architecture fields, and extending the exclusion lists as new layouts are found.

### Unnamed tensors with parameter-like or hierarchical names are not treated as embeddings

- **Not covered:** a single embedding saved in safetensors or `.npz` under a name containing a parameter word (`kernel`, `scale`, `beta`, …) or a layer or index segment (`encoder.0.out`, `vec_1_a`).
- **Why:** the same name exclusions that keep model checkpoints out apply to the single-tensor rules.
- **How it shows up:** the file scores 25 (safetensors) or 30 (`.npz`) instead of 70; it is not flagged.
- **Planned fix:** none decided.

### Single embeddings under underscore-indexed identity keys

- **Not covered:** a file holding one or two embeddings under a key with an underscore-delimited number, such as `spk_12_emb`, `speaker_0_vec`, or LibriSpeech-style `19_198_0001`.
- **Why:** the single-tensor rules treat `_N_` as an index segment, so they ignore such names. This keeps reference-vector archives in the style of scipy's FFT test data (members `dct_1_128`, `dst_2_256`, …) from scoring 70; the bank rules do not apply that exclusion, so 3 or more such vectors are still found.
- **How it shows up:** the file scores 25 (safetensors) or 30 (`.npz`) and is not flagged, unless the key is also an embedding name in safetensors (`speaker_0_vec` scores 85 by name).
- **Planned fix:** none decided.

### Embedding widths outside the configured list

- **Not covered:** embeddings whose last dimension is not in `embedding_dims` (`128, 192, 256, 384, 512, 640, 768, 1024, 1536, 2048, 3072, 4096`), for example 100, 300, or 1000.
- **Why:** shape is the main signal for unnamed tensors and printed arrays; any width would match ordinary scientific data.
- **How it shows up:** such files score 30 (`.npy`, `.npz`), 25 (safetensors), or 40 (printed floats) and are not flagged. A safetensors tensor named like an embedding (`speaker_embedding`) is still flagged at any width.
- **Planned fix:** none decided; the list can be extended in the ruleset.

### Three or more leading dimensions

- **Not covered:** arrays shaped like `[2, 2, 2, d]`.
- **Why:** an embedding-shaped tensor may have at most two dimensions before the width (`[d]`, `[n, d]`, `[a, b, d]`).
- **How it shows up:** such a `.npy` scores 30 and is not flagged.
- **Planned fix:** none decided.

### Banks of two vectors

- **Not covered:** a file with exactly two identically shaped embedding tensors is not scored as a bank.
- **Why:** the bank rules need at least 3 tensors of one shape (`min_bank = 3`).
- **How it shows up:** the file scores 70 (ask) from the single-tensor rule instead of 94.
- **Planned fix:** none decided.

### Several embeddings of different shapes

- **Not covered:** a file holding embeddings of different widths (for example one 192-wide speaker vector and one 512-wide face vector per person) is not scored as a bank.
- **Why:** a bank is defined as tensors of one identical shape.
- **How it shows up:** the file scores 70 (ask), not 94.
- **Planned fix:** none decided.

### Flat-named float arrays of an embedding width are flagged

- **Not covered (false positive):** ordinary numeric arrays in `.npy`, `.npz`, or safetensors files whose last dimension happens to be an embedding width, such as benchmark or test data, a Gaussian mixture's `means` [8, 192], or a small numpy MLP's flat-named biases (`b1` [256]).
- **Why:** an unnamed array of an embedding width cannot be told apart from an embedding by its header.
- **How it shows up:** a score of 70 (ask in Claude Code; below the git hook's block threshold of 75). In the evaluation's 55,876 public-repository files, 4 such files were flagged; the evaluation's flat-MLP probe scores 70 (ask), never deny, in all 10 files.
- **Planned fix:** none decided.

### Printed float arrays of an embedding width in test code

- **Not covered (false positive):** test files that print expected values as one bracketed float array whose length is an embedding width.
- **Why:** a printed array of 128, 256, 512, … floats looks the same whether it is an embedding or a test's expected output.
- **How it shows up:** a score of 60 (ask in Claude Code; not blocked by the git hook). In the evaluation's public repositories one file was flagged: transformers' RoPE utility test.
- **Planned fix:** none decided.

### Only some file formats are inspected

- **Not covered:** embeddings and voiceprints in formats other than `.npy`, `.npz`, safetensors, and printed float text: PyTorch pickles (`.pt`, `.pth`), ONNX, HDF5, Parquet, SQLite and vector databases, and raw audio or face images (images are skipped). Biometric data embedded in an archive is not looked into.
- **Why:** v1 recognises only the formats whose headers state shape and type; the others are not parsed.
- **How it shows up:** such files score at most 30 from the file-name rule (`voiceprint`, `embedding`, `speaker`, `enroll`, or `faceprint` in the path), or nothing.
- **Planned fix:** none decided.

### The file-name rule is weak and broad

- **Not covered (false positive and false negative):** `path_biometric_name` gives 30 to any path containing `voiceprint`, `embedding`, `speaker`, `enroll`, or `faceprint`, whatever the content. It does not recognise other names (`vp`, `spk`, `ecapa`).
- **Why:** a path says little about content; the weight is low so that it never decides alone.
- **How it shows up:** a score of 30, below every default threshold. It adds to other evidence by noisy-or.
- **Planned fix:** none decided.

### Safetensors and `.npz` header recognition

- **Not covered:** a safetensors file whose JSON header starts with whitespace, or declares a header of 4 GiB or more (classified as unknown binary), and the part of a safetensors file beyond the first 100 MiB.
- **Why:** classification checks for `{"` at byte 8 and a declared length below 2^32 so that arbitrary text is not taken for a model file; reads are capped at 100 MiB.
- **How it shows up:** the file is skipped as a binary of unknown format (no score).
- **Planned fix:** none decided.

### Every zip-based file triggers the `.npz` rule's cheap check

- **Not covered (cost, not accuracy):** `.docx`, `.xlsx`, `.jar`, and other zip containers match the `.npz` header rule and are inspected as possible numpy archives.
- **Why:** a zip is a zip until its members are listed; the listing is cheap.
- **How it shows up:** no score unless members are float arrays of an embedding shape.
- **Planned fix:** none decided.

## Secrets

### Generic secrets with letter-only values

- **Not covered:** a generic `name = "value"` credential whose value contains only letters, `_`, `.`, or `-`.
- **Why:** the generic rule is converted from gitleaks, whose allowlist drops values matching `^[a-zA-Z_.-]+$` as identifiers; the converter keeps it.
- **How it shows up:** no evidence is reported for that line.
- **Planned fix:** none decided.

### Generic secrets under other key names

- **Not covered:** generic credentials whose key name does not end in a credential noun or an uppercase `_KEY`, for example `consumer_key`, `app_key`, or `master_key`.
- **Why:** the generic rule only accepts key names ending in `secret`, `password`, `token`, `credential(s)`, `creds`, `auth`, an `…_key` form such as `api_key` or `access_key`, or an uppercase `[A-Z0-9_]+_KEY`; broader names flagged too many ordinary files.
- **How it shows up:** no evidence is reported; provider-specific rules still find credentials in a provider's own format.
- **Planned fix:** none decided.

### Generic secret assignments in test code and documentation

- **Not covered (false positive):** credential-named assignments with placeholder or test values in test code, test configuration, and documentation (for example `api_key = "..."` in a test fixture or a tutorial).
- **Why:** the generic rule sees a credential-named key with a random-looking value and cannot tell a test value from a real one.
- **How it shows up:** a score of 80 (blocked by the git hook; below Claude Code's ask threshold of 90). In the evaluation's 55,876 public-repository files, 21 such files were flagged, most of the 25 secret false positives (0.45 per 1,000).
- **Planned fix:** none decided.

### Provider coverage is gitleaks v8.30.1 plus local key-store rules

- **Not covered:** credential formats gitleaks does not define or that were added after v8.30.1, internal token formats of the user's own services, and secrets that are encoded, split across lines, built at run time, or stored encrypted.
- **Why:** the 222 provider rules are converted from one pinned gitleaks release (`rulesets/secrets-core/UPSTREAM.md`); rules are not written by hand except key stores. Two local changes (a stricter generic key name and a higher generic weight) differ from upstream and are listed there.
- **How it shows up:** no evidence for such a credential unless the generic rule happens to match.
- **Planned fix:** the pin is updated by regenerating from a newer release; no schedule.

### Provider-specific false positives

- **Not covered (false positive):** `hashicorp_tf_password` fires on a dummy 10-character password with entropy 2.9 in Terraform test data; `curl_auth_user` fires when the user value is two shell variable references, as in `prometheus/scripts/sync_repo_files.sh`.
- **Why:** both rules match a credential-shaped assignment or option without checking that the value is a placeholder or an expansion; they are upstream rules and not changed locally.
- **How it shows up:** 3 and 1 files in the 55,876-file evaluation.
- **Planned fix:** none decided; a local allowlist could be added to the converter.

### Provider-specific rules match test keys

- **Not covered (false positive):** private-key blocks in test data and documentation (`private_key` in Terraform and Prometheus test certificates, MDN SubtleCrypto examples) score as real keys.
- **Why:** a PEM block that parses as a key is a key; whether it is secret is not decidable from the file.
- **How it shows up:** 14 files in the evaluation, recorded as known findings in `eval/oss-known-findings.json` and excluded from the false-positive count.
- **Planned fix:** none; use `[ignore]` rules or a baseline for test keys.

## File handling

### Large text files are scanned only at their ends

- **Not covered:** the middle of a text file above 8 MiB. Only the first and last 1 MiB are read, and the report says `partial`.
- **Why:** bounds scan time and memory; both limits (`limits.text_max`, `limits.sample`) are configurable.
- **How it shows up:** a `partial` status with the unread byte range; a secret inside that range is not found.
- **Planned fix:** none decided.

### Archives, images, and unknown binaries are not scanned

- **Not covered:** the contents of archives (the kinds RiskGrep recognises by header), images, and binary files of unknown format. Only `.npy`, `.npz`, safetensors, and key-store files (PKCS#12, DER) are read as binaries. A secret inside a compiled binary or a database file is not found.
- **Why:** v1 scans text and a small set of binary formats; unpacking archives adds decompression risk and time.
- **How it shows up:** archives are reported `unscanned` (so `on_error` applies: ask in the hook, block in the git hook); images and unknown binaries are reported `skipped` (so `on_skipped` applies: allow by default).
- **Planned fix:** none decided.

### Standard input is always treated as text

- **Not covered:** binary data piped to `riskgrep scan -` is classified as text, so a numpy or safetensors file on standard input is not recognised as one.
- **Why:** the stream is classified as text without sniffing its header.
- **How it shows up:** only the text rules run on it.
- **Planned fix:** none decided; scan the file by path.

### Directory walks have a file limit and skip symlinks

- **Not covered:** files past the 10,000th in one walk (`limits.walk_files`), symlinked files and directories found during a walk, and any directory entry that cannot be read (one unreadable entry fails the whole directory). Directories themselves do not count against the limit.
- **Why:** a bound on work and on following links out of the tree.
- **How it shows up:** symlinks appear as skipped targets; a walk that reaches the limit reports the remainder as an error (`walk limit`).
- **Planned fix:** none decided.

### Path rules see a path relative to the working directory

- **Not covered:** consistent behaviour of path-based rules and allowlists for files outside the working directory.
- **Why:** the `path` value rules read is relative to the process's working directory when the file is under it and absolute otherwise; allowlist patterns written against one form may match differently for the other.
- **How it shows up:** an allowlist or path rule that matches for a file inside the project may not match the same file scanned from elsewhere.
- **Planned fix:** none decided.

## Claude Code hook

### Bash analysis is a static reading of one command line

- **Not covered:** variables, functions, and aliases defined elsewhere; files a program opens at run time; anything a script or interpreter does; commands that run other programs but are not in the command tables; an option missing from the hand-written option tables (which makes the result unresolved, not wrong). Commands over 64 KiB, unparseable, too deeply nested, or too slow fall back to a whitespace split.
- **Why:** the parser (brush-parser 0.4.0, pinned) sees syntax only, and exact semantics need a shell. Detail and the accepted costs: [`docs/decisions/shell-parser.md`](decisions/shell-parser.md).
- **How it shows up:** such commands are `unresolved`. The default `on_unresolved = "allow"` lets them run; set `ask` or `deny` to be stricter at the cost of more prompts.
- **Planned fix:** none; the tables and rules grow with reports. A separate output-redaction tool is the backstop.

### Bash command details that are not resolved

- **Not covered:** the `-fPATTERNS` form of an attached short option value, the order of resolved files (not source order), and the glob forms `**` (not walked) and walks past 10,000 entries.
- **Why:** deferred during review as low-impact.
- **How it shows up:** an unresolved result or a file missing from the target list.
- **Planned fix:** none decided.

### Files can change between the check and the read

- **Not covered:** a file whose content changes after the hook scans it and before the tool reads it, including a file the same command writes before reading it.
- **Why:** the hook runs before the tool call and cannot lock the file.
- **How it shows up:** the earlier content is the one that was scored.
- **Planned fix:** none.

### Repository detection is by walking up for `.git`

- **Not covered:** repositories located through `GIT_DIR`, a bare repository with a separate work tree, and a repository above a symlinked `$HOME`. The walk stops before the parent of `$HOME`.
- **Why:** git is not spawned in the hook, to stay inside the time budget.
- **How it shows up:** the directory is treated as having no repository, so its `.riskgrep.toml` and baseline are not read (the stricter outcome, because an untrusted repository is never allowed to loosen the checks).
- **Planned fix:** none decided.

### The time budget can end a scan early

- **Not covered:** scans that need more than `claude_code.time_budget_ms` (2000 ms by default), and the first call after a rules change when the rules bundle has not been warmed.
- **Why:** a hook that blocks the agent for long is worse than one that asks; a bundle compile that cannot finish inside the budget is never cached.
- **How it shows up:** the hook asks with `scan exceeded time budget`. Run `riskgrep rules compile` once to warm the bundle.
- **Planned fix:** none.

## Git hook and command line

### Type changes are not scanned by the git hook

- **Not covered:** staged changes that only change a file's type (for example a regular file replaced by a symlink), and submodule pointers (gitlinks).
- **Why:** the hook lists staged files with `--diff-filter=ACMR`, which leaves out type changes; a gitlink holds a commit id, not content.
- **How it shows up:** nothing is scanned for those paths.
- **Planned fix:** none decided.

### Line numbers for files with CRLF line endings are unverified

- **Not covered:** that line numbers in git-hook evidence match the numbers in `git diff` for files with CRLF endings.
- **Why:** the numbering was derived from the hunk headers and has not been checked against CRLF input.
- **How it shows up:** an evidence line number that is off for such files. Scores are unaffected.
- **Planned fix:** none decided.

### Staged blobs over 128 MiB are not scanned, and the hook's hints are partial

- **Not covered:** staged blobs larger than 128 MiB, which are reported as unscanned rather than read; and the hint on accepting or ignoring a finding (`riskgrep baseline`, `[ignore]`), which is printed only when a file scored over its threshold.
- **Why:** a bound on memory in the hook; the hint was written for score offences only.
- **How it shows up:** an unscanned blob blocks the commit under the default `on_error = "block"` with no hint on how to resolve it.
- **Planned fix:** none decided.

## Configuration and cache

### Configuration values are lightly validated

- **Not covered:** range checks on `thresholds` and `block_at` values, the existence of rule ids in `weight_overrides` for rulesets that are not loaded, and typos in `trusted_repos`.
- **Why:** configuration is read leniently so that a persistent user setting does not break runs that narrow the rulesets.
- **How it shows up:** a nonsense threshold changes behaviour without an error. A misspelt `trusted_repos` entry fails closed: the repository file is not read in the hook, with no message.
- **Planned fix:** none decided.

### Cached results ignore changed limits

- **Not covered:** a change to scan limits (for example a lower `limits.text_max`) is not part of the evidence cache key.
- **Why:** the key is the file content hash, the rules bundle, and the path.
- **How it shows up:** a file scanned whole earlier is reported whole from the cache after the limit is lowered. Use `--no-cache` to rescan.
- **Planned fix:** none decided.

### The cache is trusted when it passes ownership and mode checks

- **Not covered:** a same-user process writing cache rows or replacing the rules bundle (see the threat model above), and orphaned temporary bundle files left by a killed writer.
- **Why:** cache integrity beyond ownership and mode checks was judged out of scope for v1.
- **How it shows up:** forged evidence rows are believed; temporary files stay in the cache directory until removed by hand.
- **Planned fix:** none.

### No cache without a home directory

- **Not covered:** caching when no absolute cache directory can be derived (no `HOME`, no absolute `XDG_CACHE_HOME`).
- **Why:** a relative cache path would write into the working directory, so the cache is disabled with a warning.
- **How it shows up:** every scan is uncached and compiles the rules bundle, which exceeds the hook's time budget.
- **Planned fix:** none.
