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
- **Why:** a file is treated as a bank when 3 or more tensors (or `.npz` members) share one embedding shape, have flat names, and make up more than half of the file's float tensors. Model checkpoints are excluded by their parameter names (`weight`, `bias`, `kernel`, `scale`, `gamma`, `beta`, `time_mix`, `mixer`, and others) and by layer segments (`layers`, `blocks`, `encoder`, `transformer`, `backbone`, `model`, also when followed by `_`) or dot- or slash-delimited index segments (`.0.`) in their names. Underscore-delimited numbers (`spk_3_emb`, `19_198_0001`) do not exclude a bank. A naming scheme outside those lists is not recognised. For example, a GPT-2 style checkpoint with flat names `h0_ln_1_g`, `h0_ln_1_b`, `h0_ln_2_g`, and `h0_ln_2_b`, all of shape [768], scores 86 as an `.npz` and 85 as a safetensors file (deny in Claude Code, blocked by the git hook); a unit test pins both.
- **How it shows up:** a missed bank scores 25 to 30, or 70 when one tensor is flat-named; a checkpoint mistaken for a bank scores 85 to 94 (deny in Claude Code, blocked by the git hook).
- **Planned fix:** none decided. Possible approaches are reading the checkpoint's metadata or architecture fields, and extending the exclusion lists as new layouts are found.

### Unnamed tensors with parameter-like or hierarchical names are not treated as embeddings

- **Not covered:** a single embedding saved in safetensors or `.npz` under a name containing a parameter word (`kernel`, `scale`, `beta`, …) or a layer or index segment (`encoder.0.out`, `vec_1_a`).
- **Why:** the same name exclusions that keep model checkpoints out apply to the single-tensor rules. The parameter words count only as whole tokens: `weight(s)`, `bias(es)`, `token(s)`, `patch(es)`, `wte`, `wpe`, and `lm_head` between non-alphanumeric characters (`.`, `_`, `/`, `-`, `:`) or the ends of the name; `kernel`, `scale`, `gamma`, `beta`, and the other JAX, RWKV, and Mamba names between `.`, `_`, `/`, or the ends. So `qkv_bias` and `mask_token` are excluded, while identities that contain such a word inside a longer word (`tobias`, `abiasi`, `patchett`) are not: `tobias_embedding` [192] scores 85 and a bank keyed `tobias`, `patchett`, `abiasi`, `dave` scores 94 (unit tests pin both).
- **How it shows up:** the file scores 25 (safetensors) or 30 (`.npz`) instead of 70; it is not flagged. An identity name that is itself one of the words as a token (`bias_2`, `token.alice`) is excluded the same way.
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
- **How it shows up:** a score of 70 (ask in Claude Code; below the git hook's block threshold of 75). In the evaluation's 55,877 scanned public-repository files, 4 such files were flagged; the evaluation's flat-MLP probe scores 70 (ask), never deny, in all 10 files.
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

### Safetensors header recognition

- **Not covered:** a safetensors file whose JSON header starts with whitespace, or declares a header of 4 GiB or more (classified as unknown binary), and the part of a safetensors file beyond the first 100 MiB.
- **Why:** classification checks for `{"` at byte 8 and a declared length below 2^32 so that arbitrary text is not taken for a model file; reads are capped at 100 MiB.
- **How it shows up:** the file is skipped as a binary of unknown format (no score).
- **Planned fix:** none decided.

### `.npz` archives are read only as far as their array headers

- **Not covered:** `.npy` members after the first 1,024 entries of an archive's directory, and, in archives larger than 8 MiB (8,388,608 bytes), array data beyond the first 4,096 bytes of each member, so a secret stored inside such an archive is not reported. Archives of 8 MiB or less are read whole.
- **Why:** bounds on work and memory. The tensor rules need only member names and `.npy` headers (`NPZ_MAX_MEMBERS` and `NPZ_MEMBER_BYTES` in `crates/riskgrep-core/src/post/tensor.rs`). A larger archive is read selectively: the central directory, located from the end of the file (at most 8 MiB read), and the first 4,096 bytes of each of the first 1,024 entries named `*.npy` (at most 128 KiB read per entry), as for `.npy` and safetensors files, whose data beyond the header is not scanned either.
- **How it shows up:** an embedding or bank member past entry 1,024 is not seen, and the bank share is computed over the first 1,024 entries only, so an archive with more members can score lower than its content warrants. Large archives score like small ones: a 9.2 MB `.npz` holding one `[12000, 192]` float32 array scores biometric 70, the same as its 77 KB `[100, 192]` form, and a 9.6 MB `.npz` with three `[192]` members before a 2,400,000-float member scores 94 (`cargo test -p riskgrep-core --test scanner npz_over_text_limit`). An archive whose directory cannot be parsed, or that needs more than those amounts, is reported `unscanned` (so `on_error` applies).
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
- **How it shows up:** a score of 80 (blocked by the git hook; asks in Claude Code, whose default `secret` ask threshold is 80). In the evaluation's 55,877 scanned public-repository files, 21 such files were flagged, most of the 25 secret false positives (0.45 per 1,000).
- **Planned fix:** none decided.

### Paths on gitleaks' global allowlist are skipped by the converted secret rules

- **Not covered:** secrets in files whose path matches gitleaks' global path allowlist, which every rule converted from gitleaks skips (the hand-written key-store rules for `.p12`, `.pfx`, `.der`, and `.key` files still apply): any path containing `gitleaks.toml`; `node_modules/`, `bower_components/`, `vendor/` Go module directories, and Ruby and Python library directories; lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `gradle.lockfile`); `gradlew` and `mvnw` wrappers; and files ending in `.bin`, `.pdf`, `.docx`, `.xlsx`, `.exe`, `.pdb`, and font and image extensions. Ordinary `.dll` files are not on the allowlist (upstream wrote the alternative as `\.(?:…|.dll|…)$`, a literal dot, then any one character, then `dll`): `foo.dll` scores like any text file, while `foo.xdll` and `x..dll`, with one extra character between the dot and `dll`, are skipped (measured: secret 95, 0, and 0 for a file holding a synthetic key). The list is `gitleaks_global_path_allowlist` in `rulesets/secrets-core/gitleaks.yar` (lines 9 to 39).
- **Why:** it is converted unchanged from gitleaks, whose defaults assume that vendored and generated files hold no first-party secrets.
- **How it shows up:** no evidence from the converted rules for a secret placed in such a path, including a real one in a file named like a lockfile or inside `node_modules/`. A path containing `gitleaks.toml` is skipped wherever it is.
- **Planned fix:** none decided; the exclusions could be made configurable per ruleset.

### The `true|false|null` value allowlist drops any secret containing `false`

- **Not covered:** a secret that contains the text `false` (or starts with `true`, or ends with `null`), for 221 of the 222 converted rules: every converted rule with a regex, provider-specific ones included. Only `pkcs12_file`, which matches on the path alone, does not carry it.
- **Why:** the expression is in gitleaks' global allowlist, which applies to every rule's secret, and is written `(?:(?i)^true|false|null$)`. The alternation binds looser than the anchors, so it reads "starts with `true`, or contains `false`, or ends with `null`" rather than "is exactly `true`, `false`, or `null`". The converter keeps the expression.
- **How it shows up:** a secret that happens to contain `false` (case-insensitive; also the matching forms of `true` and `null`) is not reported. In a random 32-character alphanumeric value this is rare (the five letters must occur in sequence), but a deliberately chosen value can contain the word.
- **Planned fix:** none decided; anchoring the three alternatives is a local change to the converter.

### Binary private keys are recognised only as DER in `.der` and `.key` files

- **Not covered:** encrypted PKCS#8 keys (`EncryptedPrivateKeyInfo`, which starts SEQUENCE, SEQUENCE like a certificate), binary key formats that are not DER (OpenSSH's binary format, JKS key stores), DER keys under other file names (`id_ec`, `server.pem` holding DER), DER keys in a `.der` or `.key` file larger than 1 MiB, and DER keys whose length uses three or more bytes (`30 83` and above).
- **Why:** a `.der` or `.key` file of at most 1 MiB (`KEY_STORE_MAX`) that starts with a DER SEQUENCE header (`30` and a short-form length, `81`, or `82`; the `der_key_file` rule never matches `83`) is read as a key store, and the `der_key_file` rule (`rulesets/secrets-core/keystores.yar`) then reports SEC1, PKCS#1, PKCS#8, and RFC 5958 version 2 private keys with a one-byte, `81`, or `82` length; other files are classified by content, and DER is binary. Measured with the release build on keys generated at run time by OpenSSL 3.5.9 (`openssl ecparam -genkey -noout -outform DER`, `openssl genpkey -outform DER`, `openssl ec -no_public`), each scanned with `riskgrep scan --no-cache --format json`: SEC1 secp256k1 (`30 74`), P-224 (`30 68`), brainpoolP256r1 (`30 78`), P-256 (`30 77`), and P-256 without the public key (`30 31`), and PKCS#8 Ed25519 and X25519 (`30 2e`), Ed448 (`30 47`), and RSA 2048 (`30 82`) all score secret 90 by `der_key_file`; `cargo test -p riskgrep-core --test ruleset_secrets der_` covers the same kinds plus PKCS#1 RSA, PKCS#8 P-256, and RFC 5958 version 2 Ed25519 with key material generated by the test.
- **How it shows up:** a non-DER binary key or a DER key under another name is a binary of unknown format and is skipped (`on_skipped` applies: allow by default). An encrypted PKCS#8 key in a `.der` or `.key` file is not skipped: it is read as a key store, matches no rule, and scores 0. A `.der` or `.key` file over 1 MiB, or with another length byte, is scanned as text when it has no NUL byte in its first 8 KiB, otherwise skipped as binary of unknown format. PEM-encoded keys are found by `private_key` under any name. A text `.key` file of at most 1 MiB that starts with `0` (0x30) followed by an ASCII byte is also read as a key store; the same bytes are read as for a text file and every rule runs on them, so the text rules still apply (`cargo test -p riskgrep-core --test ruleset_secrets text_key_file_starting_with_a_digit_is_still_scanned_for_tokens`). A larger text `.key` file takes the text path, including the first-and-last-megabyte sampling above 8 MiB (`cargo test -p riskgrep-core --test ruleset_secrets large_text_key_file`: a 9 MiB `.key` file starting with `0x` and ending in a generated AWS key scores secret 95, as the same bytes named `.txt` do).
- **Planned fix:** none decided.

### Generic and weight-80 secrets ask in Claude Code, false positives included

- **Not covered (false positive):** the generic secret rule and the provider rules that need context score 80. The default Claude Code thresholds for `secret` are `ask` at 80 and `deny` at 95, so these hits prompt rather than block, and the false positives among them (test values, documentation examples) prompt as well.
- **Why:** the default `ask` threshold equals the generic rule's weight, so every secret the git hook blocks (at 80) also prompts in Claude Code; only provider-specific formats and private keys (95) reach `deny`.
- **How it shows up:** reading a file whose only credential is a generic assignment asks first (`cargo test -p riskgrep-claude --test hook read_generic_secret_asks`). The 21 generic false positives in the evaluation's public-repository corpus (see "Generic secret assignments in test code and documentation") score 80, so each meets the `ask` threshold. Raise `claude_code.thresholds.secret.ask` above 80 to stop prompting on them, at the cost of reading real generic credentials without a prompt.
- **Planned fix:** none decided.

### Embedding names with a parameter suffix are not flagged by name

- **Not covered:** a tensor whose name contains an embedding word and also a parameter word (for example `speaker_embedding.weight`, `face_embedding.bias`).
- **Why:** the named safetensors rule ignores parameter-like names (`weight` and `bias` as whole tokens, `running_mean`, `in_proj`, and others) so that model layers named like embeddings are not flagged; the exclusion wins over the embedding word.
- **How it shows up:** the file scores 25 (the generic float-tensor rule) instead of 85.
- **Planned fix:** none decided.

### Provider coverage is gitleaks v8.30.1 plus local key-store rules

- **Not covered:** credential formats gitleaks does not define or that were added after v8.30.1, internal token formats of the user's own services, and secrets that are encoded, split across lines, built at run time, or stored encrypted.
- **Why:** the 222 rules converted from one pinned gitleaks release (`rulesets/secrets-core/UPSTREAM.md`: 221 regex rules, among them the generic `generic-api-key`, and the path rule `pkcs12-file`) are the only credential rules besides the two hand-written key-store rules. Two local changes (a stricter generic key name and a higher generic weight) differ from upstream and are listed there.
- **How it shows up:** no evidence for such a credential unless the generic rule happens to match.
- **Planned fix:** the pin is updated by regenerating from a newer release; no schedule.

### A few matches differ from gitleaks

- **Not covered:** a small share of the matches gitleaks reports. Sampled agreement over 5,206 generated matches of the 217 converted rules that have a regex and no path condition: 5,203 agree, 3 are missed, and 1 is reported that gitleaks drops.
- **Why:** the 3 misses (2 for `contentful_delivery_api_token`, 1 for `discord_client_secret`) were traced in review to YARA-X reporting one match where a regex's alternatives overlap at different offsets: the match YARA-X keeps is not the one gitleaks reports, so the post-processor never sees the secret. The extra one is a `curl_auth_header` value whose entropy equals the rule's threshold exactly: gitleaks drops a secret whose entropy is at most the threshold, the `entropy` post-processor one below it.
- **How it shows up:** no evidence for the missed forms; one extra hit at the entropy boundary.
- **Planned fix:** none decided.

### Provider-specific false positives

- **Not covered (false positive):** `hashicorp_tf_password` fires on a dummy 10-character password with entropy 2.9 in Terraform test data; `curl_auth_user` fires when the user value is two shell variable references, as in `prometheus/scripts/sync_repo_files.sh`.
- **Why:** both rules match a credential-shaped assignment or option without checking that the value is a placeholder or an expansion; they are upstream rules and not changed locally.
- **How it shows up:** 3 and 1 files in the evaluation's 55,877 scanned public-repository files.
- **Planned fix:** none decided; a local allowlist could be added to the converter.

### Provider-specific rules match test keys

- **Not covered (false positive):** private-key blocks in test data and documentation (`private_key` in Terraform and Prometheus test certificates, MDN SubtleCrypto examples) score as real keys.
- **Why:** a PEM block that parses as a key is a key; whether it is secret is not decidable from the file.
- **How it shows up:** 14 files in the evaluation, recorded as known findings in `eval/oss-known-findings.json` and excluded from the false-positive count.
- **Planned fix:** none; use `[ignore]` rules or a baseline for test keys.

## File handling

### Large text files are scanned only at their ends

- **Not covered:** the middle of a text file above 8 MiB. Only the first and last 1 MiB are read, and the report says `partial`. Findings in the last MiB carry their true byte offsets but no line numbers, because the lines in the unread middle are not counted.
- **Why:** bounds scan time and memory; both limits (`limits.text_max`, `limits.sample`) are configurable.
- **How it shows up:** a `partial` status with the unread byte range; a secret inside that range is not found. Text output and git pre-commit messages show `line unknown` for findings in the last MiB of a text file larger than 8 MiB; JSON output keeps `line_start` and `line_end` at 0 for them (`cargo test -p riskgrep --test cli tail_line_is_unknown_in_text_and_0_in_json`, `cargo test -p riskgrep --test git tail_secret_line_is_shown_as_unknown`). For a partly read staged file the git pre-commit hook scores every finding in the sample instead of only those on added lines, so a commit that touches such a file can be blocked by a secret already present in its first or last MiB (`cargo test -p riskgrep --test git secret_appended_past_text_limit_is_blocked`).
- **Planned fix:** none decided.

### A scan that runs past the time budget leaves the file unscanned

- **Not covered:** the content of a file whose scan takes longer than `limits.time_budget_ms` (2,000 ms by default), in the command line and the git hook as in the Claude Code hook.
- **Why:** a bound on time per file. Dense hexadecimal text is the slowest ordinary input, because `sourcegraph_access_token` (converted unchanged from gitleaks) accepts any 40-character hex string, so every such run is checked. Measured on an Apple M4 Max with the release binary and `--no-cache` (whole command, including compiling the rules): 8 MB of 40-character hex lines 1.36 s, 8 MB of printed floats 0.76 s. Before the converter kept YARA-X from searching digit runs, digit-dense data files of 1.2 to 1.9 MB timed out under load.
- **How it shows up:** the file is reported `unscanned` with reason `timeout` (so `on_error` applies: ask in the Claude Code hook, block in the git hook). On a slower or busy machine, a file near 8 MiB of dense hex text can reach the budget.
- **Planned fix:** none decided.

### Archives, images, and unknown binaries are not scanned

- **Not covered:** the contents of archives (the kinds RiskGrep recognises by header), images, and binary files of unknown format. Only `.npy`, `.npz`, safetensors, and key-store files (PKCS#12, DER) are read as binaries. A secret inside a compiled binary or a database file is not found.
- **Why:** v1 scans text and a small set of binary formats; unpacking archives adds decompression risk and time.
- **How it shows up:** archives are reported `unscanned` (so `on_error` applies: ask in the hook, block in the git hook); images and unknown binaries are reported `skipped` (so `on_skipped` applies: allow by default).
- **Planned fix:** none decided.

### UTF-16 text and text with a NUL byte are skipped as binary

- **Not covered:** a file whose first 8 KiB contains a NUL byte and that matches no known format, including UTF-16 and UTF-32 text.
- **Why:** classification treats a NUL byte in the sniff window as the mark of a binary file; only the known binary formats are read.
- **How it shows up:** the file is reported `skipped: binary file of unknown format` (so `on_skipped` applies: allow by default). Measured with the release build: a 98-byte UTF-16 file and a 50-byte file starting with a NUL byte, each holding a generated AWS key, are both skipped, while the 48-byte ASCII form scores secret 95 (`riskgrep scan --format json key_ascii.txt key_utf16.txt key_nul.txt`).
- **Planned fix:** none decided for v1.

### Standard input is always treated as text

- **Not covered:** binary data piped to `riskgrep scan -` is classified as text, so a numpy or safetensors file on standard input is not recognised as one.
- **Why:** the stream is classified as text without sniffing its header.
- **How it shows up:** only the text rules run on it.
- **Planned fix:** none decided; scan the file by path.

### Directory walks have a file limit and skip symlinks

- **Not covered:** files past the 10,000th in one walk (`limits.walk_files`), symlinked files and directories found during a walk, and any directory entry that cannot be read (one unreadable entry fails the whole directory). Directories themselves do not count against the limit.
- **Why:** a bound on work and on following links out of the tree.
- **How it shows up:** symlinks appear as skipped targets. A walk that reaches the limit reports the directory `unscanned` with the reason `directory walk stopped at the limit of N files (limits.walk_files)`, so `on_error` applies: with `--on-error block` (the default when `--fail-at` is given) `riskgrep scan` exits 2 (`cargo test -p riskgrep --test cli walk_limit_follows_on_error`). Raise the limit or scan subdirectories separately.
- **Planned fix:** none decided.

### Path rules see a path relative to the working directory

- **Not covered:** consistent behaviour of path-based rules and allowlists for files outside the working directory.
- **Why:** the `path` value rules read is relative to the process's working directory when the file is under it and absolute otherwise; allowlist patterns written against one form may match differently for the other.
- **How it shows up:** an allowlist or path rule that matches for a file inside the project may not match the same file scanned from elsewhere.
- **Planned fix:** none decided.

## Claude Code hook

### Bash analysis is a static reading of one command line; indirectly named files are missed

- **Not covered:** variables, functions, and aliases defined elsewhere; files a program opens at run time; anything a script or interpreter does. A file that the command line names only indirectly is not found unless the command is recognised as an executor. Measured with the release hook, an isolated HOME, `on_unresolved = "deny"`, and a secret-scoring `a.txt`:
  - no decision (the gap): `tmux new -d "cat a.txt"`; an alias defined through `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0`, and `GIT_CONFIG_VALUE_0` that runs `cat a.txt`; `yq "load_str(\"a.txt\")" x.yml`.
  - Before the interpreter list below existed, these gave no decision (measured in review, before the change), because the file is named only inside code, in a script or list file, or on standard input: `osascript -e 'do shell script "cat a.txt"'`, `lua -e`, `Rscript -e`, `pwsh -Command`, `pwsh -File x.ps1`, `echo "cat a.txt" | at now`, `sort --files0-from=l`, `vim -s s.vim`, `echo "r a.txt" | ed`, and `ed < cmds`. They are now treated as executors: the interpreters and editors `osascript`, `lua`, `luajit`, `Rscript`, `R`, `pwsh`, `powershell`, `tclsh`, `julia`, `groovy`, `at`, `batch`, `ed`, `ex`, `vi`, `vim`, `nvim`, and `view` are `unresolved` (so `on_unresolved` applies) when they are the command word, as is any command with a `--files0-from` option. They are not recognised as arguments of other commands, because names such as `view`, `at`, `ex`, and `R` are ordinary words there (`gh pr view 12`, `docker run --rm img at`, `make R`; all measured as no decision). Re-measured after the change, each of these gives a decision under `deny`.
  - Naming the file directly is found: `LESSOPEN="|cat %s" less a.txt` gives ask, because `a.txt` is scanned; `lua a.txt`, `sort --files0-from=a.txt`, `ed a.txt`, and the other always-unresolved forms are denied by `on_unresolved = "deny"` (the named file is also scanned).
  - Accepted cost: an unknown wrapper that runs one of these names is not flagged. Measured: `somewrapper lua a.txt` asks because `a.txt` is a named argument and is scanned, but `somewrapper lua -e 'io.open("a.txt")'` gives no decision.
  Other programs outside the tables behave like the first group: the analysis does not know they run or read other files, so the command is resolved as reading only its named arguments. Commands over 64 KiB, unparseable, too deeply nested, or too slow fall back to a whitespace split and are `unresolved`.
- **Why:** the parser (brush-parser 0.4.0, pinned) sees syntax only. Classification is by command name and hand-written tables, so an executor missing from them is invisible; `on_unresolved` applies only to commands the analysis recognises. Detail and the accepted costs: [`docs/decisions/shell-parser.md`](decisions/shell-parser.md).
- **How it shows up:** no decision, so the command runs. Tightening `on_unresolved` does not close this gap.
- **Planned fix:** the lists grow with reports, but an enumerated list cannot be complete. The intended backstop is the separate output-redaction tool, which is not part of v1; until then, treat the Bash check as best-effort.

### Bash command details that are not resolved

- **Not covered:** the `-fPATTERNS` form of an attached short option value, the order of resolved files (not source order), and the glob forms `**` (not walked) and walks past 10,000 entries.
- **Why:** deferred during review as low-impact.
- **How it shows up:** an unresolved result or a file missing from the target list.
- **Planned fix:** none decided.

### Unresolved Bash commands get no decision by default

- **Not covered:** with the default `claude_code.on_unresolved = "allow"`, a Bash command that may read files the analysis cannot name gets no decision, unless a file it does name crosses a threshold. This covers recursive searches without a named file, interpreters and scripts, git subcommands that print repository content, words built from variables other than `HOME` and `PWD`, and uses of `HOME` or `PWD` in a command line that changes them. Measured with the release `riskgrep-claude`, an isolated HOME, a user configuration holding only `time_budget_ms = 2000`, and `a.txt` (in the working directory and under `~/proj/`) holding a generated AWS key that scores secret 95; the third column repeats each command with `on_unresolved = "deny"`:

| Command | Default (`allow`) | `on_unresolved = "deny"` |
|---|---|---|
| `cat "$PWD/a.txt"` | deny (secret 95.0) | deny (secret 95.0) |
| `cat $PWD/a.txt`, `cat ${PWD}/a.txt` | deny | deny |
| `cat $HOME/proj/a.txt`, `cat "${HOME}/proj/a.txt"` | deny | deny |
| `cat ~/proj/a.txt` | deny | deny |
| `cat "$(echo a.txt)"` | deny (`a.txt` is named in the substitution) | deny (secret 95.0 and unresolved) |
| `HOME=/x cat $HOME/proj/a.txt` | no decision | deny (unresolved) |
| `export HOME=/x; cat ~/proj/a.txt` | no decision | deny (unresolved) |
| `cd h && cat $PWD/a.txt` | no decision | deny (unresolved) |
| `cat $F` | no decision | deny (unresolved) |
| `grep -rn aws .`, `grep -rn aws`, `rg aws` | no decision | deny (unresolved) |
| `python3 x.py`, `node -e 1` | no decision | deny (unresolved) |
| `git diff`, `git show HEAD:a.txt` | no decision | deny (unresolved) |
| `bash -c "$X"` | no decision | deny (unresolved) |
| `xargs cat < list` | no decision | deny (unresolved) |
| `cat **/*.txt` | no decision | deny (unresolved) |
| `source env.sh` | no decision | deny (unresolved) |

- **Why:** the default keeps routine commands (`grep -rn`, `git diff`, `python3 script.py`) from prompting on every call; the check targets files a command names.
- **How it shows up:** the command runs without a prompt. Setting `on_unresolved = "ask"` or `"deny"` under `[claude_code]` prompts or blocks on these commands instead, at the cost of prompting on routine ones. Commands that run a program outside the analysis tables are not marked unresolved at all (see "Bash analysis is a static reading of one command line"), so this setting does not cover them.
- **Planned fix:** none decided.

### `$HOME`, `$PWD`, and `~` are resolved only in plain forms

- **Not covered:** `$HOME`, `${HOME}`, a leading `~` or `~/`, `$PWD`, and `${PWD}` are resolved from the hook's `HOME` and the command's working directory. Other forms (`${HOME:-x}`, `${HOME%/}`, `~user`, `~+`, `$OLDPWD`) are unresolved. A resolved form becomes unresolved when the same command line, anywhere in it, spells `HOME` or `PWD` other than as such a reference (an assignment, `export`, `unset`, `read`, a `for` variable), mentions `IFS`, changes directory (`cd`, `pushd`, `popd`), runs code in the current shell (`eval`, `source`, `.`, `trap`), has a command name that is not literal, or passes a non-literal argument to an assigning builtin; inside a command line run through `env`, `sudo`, `doas`, `su`, `runuser`, `chroot`, `unshare`, or `systemd-run`; and when the reference is unquoted and the value contains whitespace, `*`, `?`, `[`, or `\`.
- **Why:** these values are known to the hook only while the command line cannot have changed them. A change is detected anywhere in the line, not only before the use, because loops and functions run later text first. Indirection built to evade the checks (assembling the name `HOME` from pieces) is outside the cooperative-agent threat model.
- **How it shows up:** an unresolved result, so `on_unresolved` applies (no decision by default; see the table above).
- **Planned fix:** none decided.

### `Grep` checks mirror Claude Code 2.1.301

- **Not covered:** files that Claude Code's `Grep` would search but the hook does not walk, if a later Claude Code version changes how `Grep` runs ripgrep. The hook mirrors version 2.1.301: hidden files are searched, the directories `.git`, `.svn`, `.hg`, `.bzr`, `.jj`, and `.sl` are excluded, `.gitignore` is honoured, symlinks are not followed, the `glob` field is split on whitespace and then on commas (a piece holding both `{` and `}` is kept whole), and a leading `~` or `~/` in `path` is expanded from `HOME`. Files inside the excluded directories and gitignored files are not scanned, because `Grep` does not search them either.
- **Why:** the hook predicts which files the tool will read; it does not run the search itself.
- **How it shows up:** after a Claude Code update that changes these defaults, a `Grep` call may read files the hook did not scan, and no decision is given for them. Exclusions that Claude Code derives from permission rules are not mirrored, so the hook may scan more files than `Grep` reads.
- **Planned fix:** re-check the mirrored behaviour against each Claude Code release the documentation is verified against.

### Partial reads are offered for few secret rules

- **Not covered:** a partial `Read` of a file whose findings include a rule not marked `line_complete`. Of the 222 converted gitleaks rules, 59 are marked; the others include `private_key`, `kubernetes_secret_yaml`, `generic_api_key`, `anthropic_api_key`, `openai_api_key`, `stripe_access_token`, and `npm_access_token`. No hand-written or biometric rule is marked.
- **Why:** a rule is marked only when its `span_regex` cannot match a line feed. Many gitleaks regexes end with a delimiter class such as `[\x60'"\s;]` or allow whitespace between a key name and its value, so a match can include a line feed even when the secret itself sits on one line; the check does not distinguish those cases. The printed-float rules are not marked because a run broken by a value they do not parse (`nan`, a word) can leave floats outside every reported range.
- **How it shows up:** the reason ends with `No partial read is available for this file; ask the user.`, and every `Read` of the file, with or without `offset` and `limit`, gets the decision.
- **Planned fix:** none decided; checking only the part of the regex up to the end of the secret group would mark more rules.

### Partial reads rely on Claude Code 2.1.301's line numbering

- **Not covered:** a later Claude Code version whose `Read` numbers lines differently, returns lines outside `offset` and `limit`, or starts honouring them for notebooks.
- **Why:** a range-limited `Read` gets no decision when its lines avoid every flagged line, which holds only while the tool reads the lines the hook expects. The behaviour was read from the 2.1.301 binary: `offset` is 1-based (0 reads as 1), `limit` counts lines, lines end at LF with one CR removed, and `.ipynb` files are read whole. The hook widens the request by one line on each side, so a difference of one line cannot expose a flagged line, and treats notebooks as having no partial read.
- **How it shows up:** after a Claude Code update that changes line selection, a `Read` with `offset` and `limit` may return a flagged line without a decision.
- **Planned fix:** re-check the mirrored behaviour against each Claude Code release the documentation is verified against.

### Files can change between the check and the read

- **Not covered:** a file whose content changes after the hook scans it and before the tool reads it, including a file the same command writes before reading it.
- **Why:** the hook runs before the tool call and cannot lock the file.
- **How it shows up:** the earlier content is the one that was scored. For a `Read` with `offset` and `limit`, lines inserted or removed in between can also move a flagged line into the requested range after the hook allowed it.
- **Planned fix:** none.

### Repository detection is by walking up for `.git`

- **Not covered:** repositories located through `GIT_DIR` or `GIT_WORK_TREE` (in the hook), a bare repository with a separate work tree, a repository above a symlinked `$HOME`, and a repository whose root or `.git` is owned by another user. The walk stops before the parent of `$HOME` and at `GIT_CEILING_DIRECTORIES`, and a working directory inside a `.git` directory has no repository.
- **Why:** git is not spawned in the hook, to stay inside the time budget, and the walk applies the checks of git's own discovery that matter for trust: ceilings, no `.git` interiors, ownership of both the root and its `.git` by the effective user, and no crossing of a filesystem boundary unless `GIT_DISCOVERY_ACROSS_FILESYSTEM` is true. It does not replicate `safe.directory` entries or `core.worktree`.
- **How it shows up:** the directory is treated as having no repository, so its `.riskgrep.toml` and baseline are not read (the stricter outcome, because an untrusted repository is never allowed to loosen the checks).
- **Planned fix:** none decided.

### The time budget can end a scan early

- **Not covered:** scans that need more than `claude_code.time_budget_ms` (2000 ms by default), and the first call after a rules change when the rules bundle has not been warmed.
- **Why:** a hook that blocks the agent for long is worse than one that asks; a bundle compile that cannot finish inside the budget is never cached.
- **How it shows up:** the hook asks with `scan exceeded time budget`. Run `riskgrep rules compile` once to warm the bundle.
- **Planned fix:** none.

## Git hook and command line

### The command line finds the repository by the same walk

- **Not covered:** the command line (`scan`, `baseline`, `rules`) finds the repository root with the in-process walk used by the hook, not with `git rev-parse`, unless `GIT_DIR` or `GIT_WORK_TREE` is set (then git is asked). The same exclusions apply as for the hook: a root owned by another user, a working directory inside `.git`, and layouts that need git's configuration (`core.worktree`, `safe.directory` entries the user added) are not recognised, and a `.git` entry that is not a valid repository still counts as a root.
- **Why:** spawning git costs 7 to 9 ms, which was a third of a small scan and put two benchmark targets out of reach. `git pre-commit` still asks git.
- **How it shows up:** a repository's `.riskgrep.toml` and baseline are not loaded for the command line in those layouts; the user configuration still applies.
- **Planned fix:** none decided.

### Renamed, copied, and binary files are scored whole by the git hook

- **Not covered (false positive):** limiting a renamed or copied file, or a binary file (key store or tensor file), to the lines a commit adds. A secret already in such a file blocks the commit that renames, copies, or edits it.
- **Why:** rules can depend on the path (`der_key_file` needs a `.der` or `.key` name, `pkcs12_file` a `.p12` or `.pfx` name), so a renamed file's old verdict does not carry over; and the offsets of findings in a binary file are not lines of a diff (`cargo test -p riskgrep --test git -- rename_is_scored_whole pure_rename_into_a_key_extension_blocks text_diffed_binary_key_is_scored_whole`).
- **How it shows up:** `git mv` of a file holding a secret blocks the commit until the secret is removed, baselined, or ignored. Baseline fingerprints include the repository-relative path (`crates/riskgrep-core/src/suppress.rs`), so a baseline entry recorded under the old path stops matching after a rename; regenerate it with `riskgrep baseline <path>`.
- **Planned fix:** none decided.

### Type changes into a symlink and submodule pointers are not scanned by the git hook

- **Not covered:** a staged path that became a symlink through a type change (a regular file replaced by a symlink), and submodule pointers (gitlinks). Newly added or modified symlinks are scanned, and a type change into a regular file (a symlink replaced by a file) is scanned whole.
- **Why:** the hook lists staged files with `--diff-filter=ACMRT` and does not score a type change whose new side is a symlink; a gitlink holds a commit id, not content (`cargo test -p riskgrep --test git -- symlink_replaced_by_a_file_with_a_secret_blocks file_replaced_by_a_symlink_is_not_scanned`).
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
- **Why:** cached evidence is keyed by the file's content hash and the rules bundle key (next entry), not by the limits it was read with.
- **How it shows up:** a file scanned whole earlier is reported whole from the cache after the limit is lowered. Use `--no-cache` to rescan.
- **Planned fix:** none decided.

### The cache key covers the ruleset files and versions only

- **Not covered:** changes that affect scanning but are not in the cache key. The rules-bundle cache and the evidence cache are keyed by the YARA-X version, the riskgrep version, the platform, and each enabled ruleset's id and files (`ruleset.toml`, every `*.yar`, and every `stopwords/*.txt`). Other files in a ruleset directory are not part of the key, and a build of riskgrep that changes scanning behaviour without changing its version number (a development build) reuses evidence cached by the previous build.
- **Why:** the key is computed from what the rulesets load; the binary itself is identified by its version. A stopword change invalidates cached evidence in both directions (`cargo test -p riskgrep-core --test scanner stopword_change_invalidates_cached_evidence`).
- **How it shows up:** stale evidence after such a change. Delete the cache directory, or use `--no-cache`.
- **Planned fix:** none decided.

### The cache is trusted when it passes ownership and mode checks

- **Not covered:** a same-user process writing cache rows or replacing the rules bundle (see the threat model above), and orphaned temporary bundle files left by a killed writer.
- **Why:** cache integrity beyond ownership and mode checks was judged out of scope for v1.
- **How it shows up:** forged evidence rows are believed; temporary files stay in the cache directory until removed by hand.
- **Planned fix:** none.

### No cache and no user configuration without an absolute home directory

- **Not covered:** the user configuration file `~/.config/riskgrep/config.toml` without an absolute `HOME`, and caching without an absolute `HOME` (on Linux, an absolute `XDG_CACHE_HOME` still enables the cache).
- **Why:** a relative cache or configuration path would resolve against the working directory, which an agent controls, so the compiled-rules cache and the evidence cache are both off (with a warning) and the user configuration is not read.
- **How it shows up:** every run compiles the rules and the defaults apply. Measured: a Claude Code hook call on a 64 KB file takes 0.72 to 0.74 s on an idle machine and 0.83 to 0.84 s on a loaded one (`hyperfine --runs 10` with `env -u HOME -u XDG_CACHE_HOME`), within the 2 s hook budget.
- **Planned fix:** none.

### Relative paths in configuration resolve against the declaring file

- **Not covered:** a relative path in configuration (`extra_ruleset_dirs`, `trusted_repos`) meaning the working directory. Each one resolves against the directory of the file that declares it: `~/.config/riskgrep/` for the user file and the repository root for `.riskgrep.toml` (read only when that file is applied).
- **Why:** paths must not depend on where a command runs, and a repository the Claude Code hook does not trust must not supply a ruleset through a relative path in the user file (`cargo test -p riskgrep-core --test config -- relative_paths_resolve_against_the_declaring_config claude_mode_never_resolves_user_paths_in_an_untrusted_repo`).
- **How it shows up:** a setup that relied on a relative path meaning the working directory no longer finds its rulesets or trusted repository; use an absolute path.
- **Planned fix:** none; this is the intended behaviour.

### `*` in `[ignore]` globs also matches `/`

- **Not covered:** a narrow `[ignore]` pattern. `paths = ["src/*.txt"]` ignores `src/a/b/key.txt` as well as `src/key.txt`.
- **Why:** the glob matcher lets `*` cross directory separators.
- **How it shows up:** findings in deeper files are suppressed too. Measured with `riskgrep scan --format json src/key.txt src/a/b/key.txt`: both reported with one suppressed finding and secret 0. List files or use a more specific pattern when a narrower match is intended.
- **Planned fix:** none decided.

### Baselines of header and path findings follow the file's content

- **Not covered:** keeping a header or path finding suppressed after the file changes. A baseline entry for a finding located by its matched bytes (a secret) stays valid wherever those bytes move within the same path. A finding decided by a tensor header (`.npy`, `.npz`, safetensors) or one with no location (path-name rules) is identified by the digest of everything riskgrep read from the file.
- **Why:** an entry keyed by rule and path alone would suppress any later content at that path, including a different, larger embedding store.
- **How it shows up:** any change to that content (the whole file for path-name rules on text files; the header region for tensor files) reports the finding again until the file is baselined again, while a change only to tensor data outside the header region keeps it suppressed (`cargo test -p riskgrep-core --test scanner baseline_of_`). Baselines written by earlier builds identified these findings by rule and path only (or by the format's magic number) and must be regenerated.
- **Planned fix:** none.
