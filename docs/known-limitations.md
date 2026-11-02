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

- **Not covered:** the output of a command or program (a database client, `env`, a script that prints a credential), and data that never passes through a file the hook can name. Tools other than `Read`, `NotebookRead`, `Grep`, `Glob`, `Bash`, and MCP tools (web fetches, for example) are not checked at all, and an MCP tool without a `claude_code.mcp_tools` entry gets no decision unless `on_unresolved` says otherwise.
- **Why:** the hook runs before a tool call and reasons about the files the call would read.
- **How it shows up:** the hook produces no decision and the call proceeds.

### Scores are heuristic

- **Not covered:** a score is not a verdict. A matching rule shows a pattern, not that the data is sensitive, and the absence of a match does not show the absence of sensitive data.
- **Why:** detection is rule- and structure-based. The evaluation corpus is public repositories plus generated files, and recall on the generated positives is circular by construction (see [`eval/README.md`](../eval/README.md)).
- **How it shows up:** false positives and false negatives, at the rates the evaluation reports.

## Biometric embeddings

### Only `.npy`, `.npz`, safetensors, and printed float arrays are inspected

- **Not covered:** embeddings and voiceprints in other containers: PyTorch pickles (`.pt`, `.pth`), ONNX, HDF5, Parquet, SQLite and vector databases, and biometric data inside archives other than zip (gzip, tar, 7z). Raw audio and face images are not inspected (images are skipped).
- **Why:** only the formats whose headers state shape and type are parsed.
- **How it shows up:** such files score at most 30 from the file-name rule (`voiceprint`, `embedding`, `speaker`, `enroll`, or `faceprint` in the path), or nothing.
- **Large `.npz` with prepended bytes:** an `.npz` over the text limit whose first entry does not start at byte 0 is reported unscanned (`npz central directory unreadable`), because its central directory is located from a fixed start offset of 0.
- **What an `.npz` leaves unread:** an `.npz` whose members are all named `.npy` is opened only for the first 4,096 uncompressed bytes of each of its first 1,024 members, whose shape and type the tensor rules read. At or under the text limit, every rule also sees the file's bytes as stored, so text stored uncompressed can match; deflated members cannot. Nothing else in it is read, and none of this makes it `partial`: the rest of each member (the tensor data, and so a wrong checksum on a member over 4,096 bytes, which only a member read whole reveals), members past the 1,024th, the archive comment and entry comments, extra fields, bytes outside the listed members, bytes after a member's deflate stream, a local header name that differs from the directory, and entries hidden behind a later entry of the same name. With the tensor rules not enabled (`--category secret`), the members are not opened at all, so a member without the magic bytes goes unnoticed too. A member named `.npy` that does not start with the npy magic bytes makes the file `partial` (`npz member N is not an npy file`) but is not scanned; reading it would cost a second read of every member of every real `.npz`. Any other member, in any position, makes the file a zip archive like any other, read in full within the limits below (`cargo test -p riskgrep-core --test container an_npz_with_another_member_goes_through_the_framework`), as does an `.npz` at or under the text limit whose directory does not parse from offset 0. Its `.npy` members are then scored as `.npy` files, without the `.npz` rules' bank scoring and member-name exclusions: five same-shape vectors score 94 alone and 70 beside a `meta.json`, and a member named `weights.npy` scores 30 alone and 70 beside one (`riskgrep scan <file> --no-cache`).

### How embeddings are recognised

- **What is caught:** a float tensor or printed float array whose last dimension is in `embedding_dims` (`128, 192, 256, 384, 512, 640, 768, 1024, 1536, 2048, 3072, 4096`) with at most two dimensions before it scores 70 (`.npy`, `.npz`, unnamed safetensors tensors) or 60 (printed arrays); a safetensors tensor named like an embedding (`speaker_embedding`) scores 85 at any width; a bank of 3 or more tensors of one embedding shape with flat names, making up more than half of the file's float tensors, scores 85 to 97.
- **What is missed:** banks stored under hierarchical names (`model.speakers.0.vec`, `model_p225`) or alongside at least as many other float tensors as bank vectors; banks of two vectors (70, not 94); several embeddings of different widths in one file (70, not a bank); widths outside the list (for example 100, 300, or 1000) and arrays with three or more leading dimensions (25 to 40, not flagged); and single tensors whose names contain a parameter word as a token (`weight`, `bias`, `kernel`, `scale`, `gamma`, `beta`, and others), a layer segment (`encoder`, `layers`, `blocks`), or an index segment (`encoder.0.out`, `spk_12_emb`), which score 25 (safetensors) or 30 (`.npz`). A name holding both an embedding word and a parameter word (`speaker_embedding.weight`) is not flagged by name.
- **Why:** shape and names are the only signals in a header. Any width would match ordinary scientific data, and the name exclusions keep model checkpoints out.
- **How it shows up:** a missed file scores below every default threshold. In the other direction, ordinary arrays of an embedding width are flagged: a Gaussian mixture's `means` [8, 192] or a flat MLP's biases score 70 (ask in Claude Code; below the git hook's block threshold of 75), a test that prints an expected float array of an embedding width scores 60, and a checkpoint whose flat parameter names are not on the exclusion lists can be taken for a bank (a GPT-2 style checkpoint with names `h0_ln_1_g` and `h0_ln_1_b`, all [768], scores 86 as an `.npz` and 85 as safetensors). In the evaluation's 55,877 scanned public-repository files, 5 such files were flagged.

## Secrets

### Coverage is gitleaks v8.30.1 plus local key-store rules

- **Not covered:** credential formats gitleaks does not define or that were added after v8.30.1, internal token formats of your own services, and secrets that are encoded, split across lines, built at run time, or stored encrypted. A small share of matches differ from gitleaks: of 5,206 generated matches for the 217 converted rules that have a regex and no path condition, 5,203 agree, 3 are missed (2 for `contentful_delivery_api_token`, 1 for `discord_client_secret`, where YARA-X keeps a different one of a regex's overlapping alternatives), and 1 is reported that gitleaks drops (a `curl_auth_header` value whose entropy equals the threshold).
- **Why:** the 222 rules converted from one pinned gitleaks release (`crates/riskgrep-core/rulesets/secrets-core/UPSTREAM.md`) plus the hand-written key-store, credential-file, and vault rules are the only credential rules. The local changes to upstream are listed in `UPSTREAM.md`.
- **How it shows up:** no evidence for such a credential unless the generic rule happens to match.

### Generic-secret limits

- **Not covered:** generic `name = "value"` credentials whose key name does not end in a credential noun (`secret`, `password`, `token`, `credential(s)`, `creds`, `auth`, an `…_key` form such as `api_key` or `access_key`, or an uppercase `[A-Z0-9_]+_KEY`), for example `consumer_key` or `master_key`; values made only of letters, `_`, `.`, or `-` (gitleaks' identifier allowlist, kept by the converter); values with Shannon entropy below 3.5, except hex values of 32 to 128 digits, which `credential_key_hex_value` (`crates/riskgrep-core/rulesets/secrets-core/hex_keys.yar`, which also applies gitleaks' global path allowlist) accepts from entropy 3.0; and values containing `false` (or starting with `true`, or ending with `null`), which gitleaks' global allowlist drops for every converted rule because its expression `(?:(?i)^true|false|null$)` binds the anchors to the outer alternatives only.
- **Why:** these rules are converted from gitleaks with a stricter key name; broader names flagged too many ordinary files.
- **How it shows up (false negatives):** no evidence for such a line; provider-specific rules still find credentials in a provider's own format.
- **How it shows up (false positives):** credential-named assignments with placeholder or test values in test code, test configuration, and documentation score 80, the generic rule's weight. That blocks a commit in the git hook (threshold 80) and asks in Claude Code, whose default `secret` ask threshold is 80 (only provider-specific formats and private keys, at 95, reach `deny`). In the evaluation's 55,877 scanned public-repository files, 21 such files were flagged, most of the 25 secret false positives (0.45 per 1,000). Raise `claude_code.thresholds.secret.ask` above 80 to stop prompting on them, at the cost of reading real generic credentials without a prompt.

### Configuration-file credential limits

- **Not covered:** the rules in `crates/riskgrep-core/rulesets/secrets-core/config.yar` read only an XML element's text, an `<add>` element's `value` attribute when its `key` or `name` attribute directly before or after it is a credential name, a string member directly inside a JSON object, and a scalar on a line below a YAML mapping key indented by 0, 2, 4, or 6 spaces. They do not read other XML attributes, `<add>` elements with another attribute between `key` and `value`, passwords inside a connection string (`Password=…;`), TOML or INI sections, members of an object nested inside the credential-named one, quoted YAML keys, or flow-style YAML (`securityKeys: {…}`). A name must be a qualified credential word: `GitHubToken` or `ServiceKey` does not match, while `AccessToken` and `ApiKey` do. A value must be 16 to 200 characters from letters, digits, and `+/=_.-` with a digit and a letter, and not a UUID, so passphrases with spaces, values containing `:`, short PINs, and credentials issued as UUIDs are not found.
- **Why:** each extension is a new source of false positives (public keys, primary keys, pagination tokens, design tokens, and hashes use the same layouts), and the filters are the ones that keep placeholders, templates, and file paths out.
- **How it shows up (false negatives):** no evidence from these rules; `generic_api_key` still finds a credential-named key with a high-entropy literal on the same line.
- **How it shows up (scores):** these rules, `credential_key_hex_value`, and `generic_api_key` share the family `credential_assignment` with a cap of 80, so a value two of them find (`credentials:` then `  token: …`) scores 80, and so does a file with several such values; the family does not add them up toward the Claude Code `secret` deny threshold of 95.

### gitleaks' global path allowlist skips lockfiles, `node_modules`, and similar

- **Not covered:** secrets in files whose path matches gitleaks' global path allowlist, which every converted rule skips (the hand-written key-store rules still apply): any path containing `gitleaks.toml`; `node_modules/`, `bower_components/`, `vendor/` Go module directories, and Ruby and Python library directories; lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `gradle.lockfile`); `gradlew` and `mvnw` wrappers; and files ending in `.bin`, `.pdf`, `.docx`, `.xlsx`, `.exe`, `.pdb`, and font and image extensions. The list is `gitleaks_global_path_allowlist` in `crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`.
- **Why:** it is converted unchanged from gitleaks, whose defaults assume that vendored and generated files hold no first-party secrets.
- **How it shows up:** no evidence from the converted rules for a secret in such a path, including a real one in a file named like a lockfile or inside `node_modules/`.

### Binary private keys are recognised only as DER in `.der` and `.key` files of up to 1 MiB

- **Not covered:** encrypted PKCS#8 keys, binary key formats that are not DER (OpenSSH's binary format, JKS key stores), DER keys under other file names (`id_ec`, `server.pem` holding DER), DER keys in a `.der` or `.key` file larger than 1 MiB, and DER keys whose length uses three or more bytes (`30 83` and above).
- **Why:** a `.der` or `.key` file of at most 1 MiB that starts with a DER SEQUENCE header (`30` and a short-form length, `81`, or `82`) is read as a key store, and the `der_key_file` rule reports SEC1, PKCS#1, PKCS#8, and RFC 5958 version 2 private keys in it; other files are classified by content, and DER is binary.
- **How it shows up:** a non-DER binary key or a DER key under another name is skipped as a binary of unknown format (`on_skipped` applies: allow by default). An encrypted PKCS#8 key in a `.der` or `.key` file is read and scores 0. PEM-encoded keys are found by `private_key` under any name.

### Credential files are recognised by structure, in the forms listed

- **Not covered:** one-time-password seeds other than `otpauth://` URIs and Google Authenticator `otpauth-migration://` links with a `secret` or `data` value (a bare base32 seed in a config file, a percent-encoded URI inside a QR-code image link); password-manager exports other than the Bitwarden (JSON and CSV), 1Password `export.data` (JSON), LastPass, Chrome, and Apple Passwords layouts, and any of those with reordered or renamed columns, or whose first line is not the header row; recovery codes that are not GitHub-style hex pairs, two groups of four digits, or ten-character alphanumeric codes containing a digit, in a file over 8 KiB, with fewer than six codes, or without "recovery codes" or "backup codes" in the file name or in the first 512 bytes; encrypted vaults other than KeePass (`.kdb`, `.kdbx`), macOS keychain files, Password Safe v3 (`.psafe3`), and 1Password OPVault bundle files.
- **Why:** each rule matches a documented or observed layout; looser matching would flag ordinary CSV files, lists of identifiers, and documentation. The Chrome and Apple Passwords column lists come from observed exports, not from vendor documentation.
- **How it shows up:** the export, seed, and recovery-code rules score 95 or 90 (deny or near deny in the Claude Code hook), so a documentation page that quotes an example in the same layout can be flagged. Encrypted vaults score 85, which asks in the Claude Code hook and blocks a commit in the git hook. A 1Password `.1pux` export is a zip, so its plaintext `export.data` member is scanned and detected inside the archive (`cargo test -p riskgrep-core --test container a_1password_export_is_found_inside_its_1pux_archive`); 1Password's SQLite database is still reported unscanned, so only `on_error` applies.

## File handling

### Large text files are scanned only at their ends

- **Not covered:** the middle of a text file above 8 MiB. Only the first and last 1 MiB are read, and the report says `partial`. Findings in the last MiB carry their true byte offsets but no line numbers.
- **Why:** bounds scan time and memory; both limits (`limits.text_max`, `limits.sample`) are configurable. For UTF-16 and UTF-32 text both limits apply to the file's bytes, not to the transcoded text, and each sample ends on a code-unit boundary.
- **How it shows up:** a `partial` status with the unread byte range; a secret inside that range is not found. Text output and git pre-commit messages show `line unknown` for findings in the last MiB; JSON output keeps `line_start` and `line_end` at 0 for them. For a partly read staged file the git hook scores every finding in the sample, not only those on added lines.

### Archives other than zip, PDFs, SQLite, images, and unknown binaries are not scanned

- **Not covered:** the contents of containers recognised by header other than zip (gzip, tar, 7z, PDF, SQLite), images, binary files of unknown format, and text whose first 8 KiB contains a NUL byte unless it is recognised as UTF-16 or UTF-32 (see below). Only `.npy`, `.npz`, safetensors, key-store files (PKCS#12, DER), password-vault headers (the first 64 bytes), and zip archives are read as binaries, so a secret inside a compiled binary or a database file is not found.
- **Why:** each container format needs its own reader, and a NUL byte in the sniff window marks a file as binary.
- **How it shows up:** these containers are reported `unscanned` (so `on_error` applies: ask in the Claude Code hook, block in the git hook), also when they are members of a zip, where they make the zip `partial`; images and unknown binaries are reported `skipped` (so `on_skipped` applies: allow by default), and as zip members they are counted as skipped without making the zip partial.

### Zip members are read within shared limits

- **Not covered:** the members of a zip archive (including jar, docx, xlsx, and wheel files) past any of its limits, which are shared by the archive and every archive nested in it: 8 MiB of uncompressed bytes in all (`limits.container_bytes`), 8 MiB per member (`limits.member_bytes`), 1,000 members (`limits.container_members`), nesting depth 3 counting the file itself (`limits.container_depth`), an uncompressed-to-compressed ratio of 100 for each member and for the whole archive, each checked once it has produced 1 MiB (`limits.container_ratio`), and one deadline for the whole archive (`limits.time_budget_ms`, 2,000 ms by default; in the Claude Code hook `claude_code.time_budget_ms` also bounds the whole call). Encrypted members, members stored with a compression method other than stored or deflate, and members that fail to decompress are not read, nor are bytes of the file that belong to no listed member: data ahead of the first member, between members (other than data descriptors), or after the central directory (other than its end records and the archive comment), an entry that the central directory does not list (such as one hidden by a later entry of the same name), and bytes held by a directory entry, unless they are one deflate stream of at most 64 bytes that inflates to nothing (some encoders write directory entries that way). Also not read: bytes inside a member's declared compressed size after the end of its deflate stream, and a local header name that differs from the central directory's name (the member's data is still read, under the directory's name), or that cannot be read to compare; the same goes for a directory entry's local header name, including an empty one. A stored member whose compressed size exceeds its size is refused as unreadable, so none of it is scanned. Extra fields belong to a listed member and are not read, and do not make the archive `partial`. The end record and central directory are read within 8 MiB, including any search for a directory that is not where the end record places it, so an archive behind more than about 8 MiB of other data whose offsets do not account for it is reported `unscanned`. A file is recognized as a zip archive only when it begins with a zip entry, so an archive behind any other bytes (a self-extracting stub) is reported `skipped` as an unknown binary and its members are not read. The archive comment is scanned as text, whatever bytes it holds, under the reserved member name `comment!` (a stored member named `comment!` is shown as `comment!!`, since escaping adds a `!` to every name ending in one), and counts against the same limits as a member. So does each entry's comment, directory entries included, under the entry's escaped name followed by `!comment!` (`config/app.ini!comment!`, which no stored member can take, since escaping makes every name ending in `!` end in at least two). An `.npz` is read differently, as long as all its members are named `.npy` (see [above](#only-npy-npz-safetensors-and-printed-float-arrays-are-inspected)).
- **Why:** members are decompressed in memory, and a decompression bomb (a small archive that expands to gigabytes) must not exhaust memory or time. Declared sizes can lie, so the limits count the bytes actually produced.
- **How it shows up:** the archive is reported `partial`, with the positions of the members not read and why (`members 1001..4096 not read (limits.container_members)`, `member 3 encrypted`, `member 2 read only in part (12 bytes after its data not read)`, `member 5 sampled (bytes 1048576..7340032 not read)`), the number of bytes outside the listed members, or the number of directory entries whose local header name differs (`1 directory entry: local header name differs from the directory`), never their names. The report counts each member once: `members` is the sum of `scanned` (read whole), `read_in_part`, `skipped`, `not_read`, and `opened` (nested archives, whose own members are counted as members). A partial archive applies `on_partial`, which by default follows `on_error`: the Claude Code hook asks, the git hook blocks, and `riskgrep scan --on-error block` (or `--on-partial block`) exits 2. Set `on_partial` under `[claude_code]` or `[git]` (`error`, `allow`, `ask`, `deny`, or `block`) to change this; it also applies to an `.npz` with a `.npy` member that cannot be read (`cargo test -p riskgrep --test cli an_unreadable_npz_member_follows_on_partial`). A file outside an archive read in part by design is `partial` and is not affected: a sampled large text file, a key store or safetensors file past its read cap, or standard input past its limit. The same file as a member of an archive does keep the archive `partial` and does apply `on_partial`, reported as `sampled` (`cargo test -p riskgrep --test cli a_sampled_file_passes_but_the_same_file_in_an_archive_follows_on_partial`). An archive with nothing in scope read is `unscanned`; a skipped or nested member with bytes after its stream or a differing local header name was read, so an archive holding only that is `partial`, and so is one holding only a directory entry with a differing name (`cargo test -p riskgrep-core --test container a_lone_skipped_member`, `an_archive_of_one_directory_entry`). Findings name the member (`backup.zip!/config/app.ini`, nested `outer.zip!/inner.zip!/x`); their `start` and `end` are offsets into the member's uncompressed bytes, not the archive, and their lines are the member's lines. The Claude Code hook offers no partial read of an archive. Only an archive read whole, from a file of at most 64 MiB, is cached; others are read again on each scan.

### UTF-16 and UTF-32 text is recognised by its byte-order mark or by mostly ASCII content

- **Not covered:** UTF-16 or UTF-32 text without a byte-order mark whose first 8 KiB is not more than half ASCII characters (for example CJK text), or holds U+0000, a control character other than tab, LF, VT, FF, CR, and ESC, or an invalid code unit; text with a byte-order mark whose first 8 KiB after the mark holds U+0000 or more than one invalid code point in 16; and other encodings (UTF-7, legacy code pages, EBCDIC), which are scanned as bytes like any other text. Text read from standard input (`riskgrep scan -`) is always scanned as bytes.
- **Why:** without a byte-order mark the encoding is inferred from the code units of the sniff window, and the test has to reject binaries whose bytes include NULs. A UTF-16 or UTF-32 file of ASCII characters shows the NUL pattern of its encoding form; a binary with runs of NULs holds U+0000 in every form.
- **How it shows up:** text that is not recognised is skipped as a binary of unknown format. Recognised text is transcoded to UTF-8 for the rules and scores as the same text in UTF-8 does: measured with the release build (`riskgrep scan --format json` over generated files), a generated AWS key scores secret 95 in ASCII and in UTF-16 and UTF-32 of either byte order, with and without a mark. Locations are byte offsets in the file and lines are lines of the file; invalid code units are read as U+FFFD and the file is still reported `scanned`. In the Claude Code hook a partial `Read` is available only for UTF-16 LE text with a byte-order mark: measured by reading generated files of numbered lines with the `Read` tool of Claude Code 2.1.309, it decodes that form and numbers its lines as RiskGrep does, but reads UTF-16 BE, UTF-32, and text without a mark as bytes split at 0x0A bytes, which a code unit other than LF can hold. The git hook checks every staged UTF-16 or UTF-32 file whole rather than only its added lines: git reports such a file as a binary change (an LF code unit holds a NUL byte; `git diff --numstat` prints `-` for its line counts), and git numbers lines at 0x0A bytes in any case.

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

- **Not covered:** a partial `Read` of a file with a finding from a rule not marked `line_complete`. Of the 222 converted gitleaks rules, 211 are marked (`grep -c 'line_complete = true' crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`, also stated in `crates/riskgrep-core/rulesets/secrets-core/UPSTREAM.md`); the others include `private_key`, `kubernetes_secret_yaml`, and `atlassian_api_token`. Of the hand-written rules only `xml_credential_element` and `xml_add_key_value` (`crates/riskgrep-core/rulesets/secrets-core/config.yar`) and `credential_key_hex_value` (`hex_keys.yar`) are marked, no biometric rule is, and binary, sampled (`partial`), and structural findings, and findings in UTF-16 or UTF-32 text other than UTF-16 LE with a byte-order mark, never allow a partial read.
- **Why:** a rule is marked only when every match stays on the line of its secret: nothing up to the end of the secret can match a line feed, and after it at most one byte can (gitleaks' trailing delimiter). A regex that allows whitespace before the secret can put a provider name and its value on different lines, so the rule is not marked even when most values sit on one line. When the secret is the first non-empty group of an alternation (`atlassian_api_token`), no part of the regex may match a line feed, and gitleaks' trailing delimiter can. The key-store rules locate only a binary file's header, the path and tensor rules have no text lines, and the printed-float rules do not locate runs shorter than 64 floats or arrays of other lengths.
- **How it shows up:** the reason ends with `No partial read is available for this file; ask the user.`, and every `Read` of the file, with or without `offset` and `limit`, gets the decision.

### Files can change between the check and the read

- **Not covered:** a file whose content changes after the hook scans it and before the tool reads it, including a file the same command writes before reading it.
- **Why:** the hook runs before the tool call and cannot lock the file.
- **How it shows up:** the earlier content is the one that was scored. For a `Read` with `offset` and `limit`, lines inserted or removed in between can also move a flagged line into the requested range after the hook allowed it.

### Grep handling mirrors Claude Code 2.1.301

- **Not covered:** files that Claude Code's `Grep` would search but the hook does not walk, if a later Claude Code version changes how `Grep` runs ripgrep, and a later version whose `Read` numbers lines differently for partial reads. The hook mirrors version 2.1.301: hidden files are searched, the directories `.git`, `.svn`, `.hg`, `.bzr`, `.jj`, and `.sl` are excluded, `.gitignore` is honoured, symlinks are not followed, the `glob` field is split on whitespace and then on commas, and a leading `~` or `~/` in `path` is expanded from `HOME`.
- **Why:** the hook predicts which files the tool will read; it does not run the search itself.
- **How it shows up:** after a Claude Code update that changes these defaults, a `Grep` call may read files the hook did not scan, and no decision is given for them. Exclusions that Claude Code derives from permission rules are not mirrored, so the hook may scan more files than `Grep` reads.

### MCP tools and Glob are judged from their inputs

- **Not covered:** files an MCP tool reads through input fields its `claude_code.mcp_tools` entry does not name, or reads in a way its kind does not describe (a server that follows links, or whose search honours different exclusions); the content a search tool mapped as `names` reads, such as Desktop Commander's `start_search` with `searchType` `content`, whose matching lines reach the agent while only the file names under its path are judged; MCP tools without an entry, which are unresolved and get no decision under the default `on_unresolved = "allow"`; and, for `Glob` and `names` tools, names past `limits.walk_files` entries. The built-in entries cover the official filesystem server and Desktop Commander under their usual server names only. A relative path in an MCP tool's input is resolved against the hook's `cwd`, while the server resolves it against its own working directory, so a server started elsewhere may read a different file than the one scanned.
- **Why:** the hook cannot see what an MCP server does; it predicts the files from the tool input. File names alone are low risk, so a walk that stops at the limit is not treated as an error for names. Scanning the content of every file under a search path, as `Grep` is handled, does not fit the hook's time budget on large trees, so `start_search` is judged by names.
- **How it shows up:** the call proceeds with no decision. In the other direction, `Glob` and `names` tools are judged on every entry the walk finds, hidden and ignored files included, where `Glob` itself returns at most 100 files; and only the path rules (`pkcs12_file` asks by default, `path_biometric_name` scores 30, below the default thresholds) apply to names.

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
