# Changelog

All notable changes to RiskGrep are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Credentials in configuration files are found by the name of the element, object, or mapping that holds them (`secrets-core/config.yar`, weight 80, the same as `generic_api_key`): an XML element named like a credential (`<ApiKey>…</ApiKey>`, the layout of the *arr apps' `config.xml`; also `…Token`, `…Secret`, `Password`, `Psk`, and qualified `…Key` names, but not `PublicKey`, `PrimaryKey`, a bare `Key`, `NextToken`, or any name containing `public`), a .NET `<add key="…" value="…" />` entry (`appSettings`; also `name=` and either attribute order) whose key is such a name, and the string members of a JSON object or YAML mapping named like a credential store (`securityKeys`, `apiKeys`, `credentials`, `secrets`, and similar, as Z-Wave JS UI stores a network's keys), whatever the members are called. A value must be 16 to 200 token characters with Shannon entropy of at least 3.0, a digit, and a letter, and must not be a UUID, a placeholder, a template, a sequential run, or a file path. Files in these layouts with random 32-character hex values scored 0 before; the evaluation's 20 synthetic files of each layout are now all flagged (`cargo xtask eval --skip-oss`, kinds `config_xml`, `config_dotnet`, `config_json_object`, and `config_yaml_mapping`). The two XML rules are marked `line_complete`, so the Claude Code hook can offer partial reads around its findings.
- A credential-named key with a hex value of 32 to 128 digits is found whatever its entropy above 3.0 (`credential_key_hex_value`): `generic_api_key` drops values below entropy 3.5, which a random 32-character hex value falls below about one time in five, so such a key was found about four times in five; the evaluation's 20 `config_key_hex` files, whose values all have entropy from 3.0 to below 3.5, are now all flagged (`cargo xtask eval --skip-oss`). The rule is marked `line_complete` and, like `generic_api_key`, skips the paths in gitleaks' global path allowlist. `generic_api_key` and the configuration-file rules share the family `credential_assignment` with a cap of 80, so a value that two of them find (`token:` inside `credentials:`) scores 80 instead of 96, which was above the Claude Code `secret` deny threshold of 95.
- Zip archives are scanned. Members of a zip (including jar, docx, xlsx, wheel, and `.1pux` files) are decompressed in memory and scanned like files, nested zips included, and findings name their member: `backup.zip!/config/app.ini` in text output, the git hook, and the Claude Code hook, and an optional `member` field on each evidence item in JSON. For evidence with `member`, `start` and `end` are byte offsets into the member's uncompressed bytes, not into the archive, and lines are the member's lines; a consumer that ignores `member` would misplace them. Container targets gain a `container` object (format, member counts, and a table of members with findings or not read whole). The JSON of every other target is unchanged (`cargo test -p riskgrep-core --test model non_container_target_json_is_unchanged`). A container's score merges its members' evidence by rule, so findings spread over several members count together. Ignore globs match the archive's path or the joined member path, and baselines record member findings under the joined path.
- Limits shared by an archive and everything nested in it: `limits.container_bytes` and `limits.member_bytes` (8 MiB each), `limits.container_members` (1,000), `limits.container_depth` (3), `limits.container_ratio` (100, per member and for the whole archive, checked once 1 MiB has been produced), and one time budget for the whole archive. Encrypted members, unsupported compression methods, members past a limit, and bytes outside the listed members (an entry hidden by a duplicate name, data between entries or after the central directory, bytes held by a directory entry) make the archive `partial`; the archive comment is scanned as text under the reserved member name `comment!`, and each entry's comment under the entry's name followed by `!comment!`, both counting as members; images and unknown binaries inside it are counted as skipped and do not.
- `on_partial` under `[claude_code]` and `[git]`, and `riskgrep scan --on-partial`: what a target does when part of its content could not be read, as with an archive's unread members or an `.npz` member that cannot be read; a file read in part by design, such as a sampled large text file, is not affected. The default, `error`, follows `on_error` (ask in the Claude Code hook, block in the git hook, and `--on-error` in `riskgrep scan`).
- `riskgrep rules test` accepts the `zip:MEMBER=SPEC` generator for samples inside an archive.

### Changed

- The Claude Code hook offers partial reads for files whose findings come from `generic_api_key` and the provider-context rules. With both separators on one line, 100 of the 101 rewritten rules are marked `line_complete`: 211 of the 222 converted rules, up from 111 (`grep -c 'line_complete = true' crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`). `atlassian_api_token` stays unmarked, because its regex is an alternation whose secret is the first non-empty group and its trailing delimiter can match a line feed. Each marked rule is checked by `cargo test -p riskgrep-core --test ruleset_secrets every_line_complete_rule_locates_every_secret`.
- The evidence database's schema version is 4: rows can describe an archive's members. The first run after upgrading discards the existing rows and the cache refills as files are scanned; upgrade `riskgrep` and `riskgrep-claude` together, as for 1.1.0.
- gzip, tar, 7z, PDF, and SQLite files are still reported unscanned; inside a zip they make it `partial`.
- Upgraded the `zip` dependency from 8.6 to 9.0.5. Version 9.0.5 scans every byte before the end record when it detects where an archive starts, which would read a whole large `.npz`, so an `.npz` over the text limit is now opened with a fixed start offset of 0. An over-limit `.npz` with bytes prepended before its first entry is reported unscanned (`npz central directory unreadable`) instead of being read (`cargo test -p riskgrep-core --test classify npz_over_limit_with_prepended_bytes_is_unscanned`).
- An `.npz` with a `.npy` member that cannot be read, because of a wrong checksum, a declared size smaller than the data, or an unreadable header, is reported partial (`npz member N could not be read`, N being the member's position in the archive) instead of scanned, whether it is read whole or over the text limit. The scores of the members that could be read are kept, the result is not cached, so a later run scans it again, and `on_partial` applies. An `.npz` inside a zip makes the zip partial the same way. Other members are not affected, and neither is a damaged member that is not named `.npy` (`cargo test -p riskgrep-core --test scanner npz_unreadable`). Post-processors report such a gap with the new `PostResult::Incomplete`.
- The central directory budget of an `.npz` over the text limit counts bytes fetched from the file instead of buffer refills, so an `.npz` with hundreds of members is read in full: with 600 or more members the directory read had exceeded 8 MiB of refills while the directory itself is under 100 KB (`cargo test -p riskgrep-core --test scanner npz_over_text_limit_with_a_thousand_members_scores_like_small`).

### Fixed

- Converted gitleaks rules no longer read an assignment across a line break. The separators on both sides of the assignment operator admitted a line feed. After the operator, an empty `NAME=` followed by a line starting with a name of 10 or more characters scored secret 80 under `generic_api_key`, which blocked commits of `.env.example`-style files. Before the operator, a CSV header ending in a credential name such as `password` took the first field of the next row (`,value`) as its value. The name, the operator, and the start of the value must now share a line, in the 101 rules built from gitleaks' generic assignment pattern (`generic_api_key` and the provider-context rules such as `adafruit_api_key`).

## [1.1.0] – 2026-10-25

### Changed

- The evidence database records the time each row was written, which pruning needs, so its schema version is 3. The first run after upgrading discards the existing rows and the cache refills as files are scanned. Upgrade `riskgrep` and `riskgrep-claude` together: the two binaries share the cache, and while one is at 1.0.1 and the other at 1.1.0, each run of either resets it to its own schema, so cached reads miss until both are upgraded.
- Upgraded the YARA-X engine from 1.21.0 to 1.22.0, with `yara-x-macros` and `yara-x-parser` pinned to the same version. Detection results and scores are unchanged on the evaluation corpus. The compiled rules bundle is keyed by the engine version, so each machine compiles it once on first use after the upgrade.
- The Claude Code hook offers partial reads for many more files. The gitleaks converter now marks a rule `line_complete` when nothing up to the end of its secret can match a line feed and at most one trailing byte can (gitleaks' trailing delimiter), instead of only when no part of the regex can match one: 111 of the 222 converted rules are marked, up from 59 (`grep -c 'line_complete = true' crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`), including `openai_api_key`, `anthropic_api_key`, and `stripe_access_token`. Detection results and scores are unchanged. Every marked rule is checked with generated secrets on one line, on adjacent lines, with CRLF line endings, and at the end of a file (`cargo test -p riskgrep-core --test ruleset_secrets every_line_complete_rule_locates_every_secret`). The hand-written key-store and biometric rules were audited and stay unmarked.

### Added

- The Claude Code hook gates MCP tools and `Glob`. `claude_code.mcp_tools` maps each MCP tool to the input fields that hold its paths and to what it does with them (`read`, `walk`, `names`, or `none`); built-in entries cover the official filesystem server and Desktop Commander, and user entries, with `*` wildcards, add other servers. An MCP tool without an entry follows `on_unresolved`. `Glob`, and MCP tools that list directories, are judged by the file names they would reveal, with the path rules alone. `print-config` now emits the matcher `^(Read|NotebookRead|Grep|Glob|Bash|mcp__.*)$`; an existing installation must update its matcher to gate the new tools.
- `RiskGrep::scan_names` scores file names without reading their content.
- Cache pruning. The evidence cache and the compiled rule bundles no longer grow without limit. `riskgrep cache prune` removes compiled bundles of rule sets that are not in use once they are older than `[cache] max_age_days`, the evidence rows written under bundles that are gone, rows older than the same age, rows for files that no longer exist, and the oldest rows when the database is over `[cache] max_size_mb`. `--dry-run` reports what would go and the sizes without changing anything. `riskgrep scan` and the git pre-commit hook run the same prune at most once a day, after their own work; the Claude Code hook never prunes. A pruned row or bundle only means a rescan or a recompile, never a different score. The `[cache]` section is read from the user configuration only.
- UTF-16 and UTF-32 text, little- or big-endian, is scanned like UTF-8 instead of being skipped as binary. It is recognised by its byte-order mark, or without one by a sniff window of mostly ASCII characters with no NUL characters or stray control characters, and transcoded to UTF-8 for the rules. Evidence offsets are byte offsets in the original file and lines are lines of the file, so partial `Read` ranges in the Claude Code hook work as for UTF-8 for UTF-16 LE text with a byte-order mark, the one form Claude Code's `Read` decodes. The git hook checks staged UTF-16 and UTF-32 files whole: git numbers their lines at 0x0A bytes, which a code unit other than LF can hold, and reports most of them as binary changes. Size limits apply to the file's bytes. The evaluation corpus has a new `encoded_text` group: every provider format in each encoding, and hard negatives.
- Credential-file rules in `secrets-core` (`credentials.yar`, `vaults.yar`), each recognising a file by its structure so that the Claude Code hook and the git hook decide on files that scored secret 0 before:
  - `otpauth://totp/` and `otpauth://hotp/` URIs with a base32 `secret` parameter, and Google Authenticator `otpauth-migration://` export links, score 95 (deny). The public example seeds from one-time-password documentation are ignored.
  - Plaintext password-manager exports score 95: Bitwarden JSON (`"encrypted": false`) and CSV, 1Password `export.data` JSON, and LastPass, Chrome, and Apple Passwords CSV files, matched by header row or JSON layout rather than by the passwords inside.
  - Two-factor backup and recovery codes: a file under 8 KiB with at least six code-shaped lines (GitHub-style hex pairs, two groups of four digits, or ten-character alphanumeric codes containing a digit) scores 90 when its name contains "recovery codes" or "backup codes" and 80 when only a "recovery codes" or "backup codes" heading appears in its first 512 bytes.
  - Encrypted vaults, recognised by magic bytes, score 85 (ask): KeePass `.kdb` and `.kdbx`, macOS keychain files (`.keychain`, `.keychain-db`), Password Safe v3 (`.psafe3`), and the known files of a 1Password OPVault bundle. These binary files are now read for their first 64 bytes instead of being skipped.
- `riskgrep rules test` accepts the `file:KIND` generator for credential-file samples.
- GitHub releases link to each crate's version on crates.io and attach the published `.crate` files with a `SHA256SUMS` file. The Release workflow adds them after publishing, once each file's checksum matches the crates.io index.

## [1.0.1] – 2026-10-23

### Fixed

- `cargo install riskgrep` and `cargo install riskgrep-claude` without `--locked` failed to compile: yara-x 1.21.0 accepts version 1.22.0 of its own `yara-x-macros` crate, which does not compile against it. `riskgrep-core` now pins `yara-x-macros` to 1.21.0, matching its yara-x pin, and pins `yara-x-parser` to 1.21.0 as well to keep them aligned. Detection and scores are unchanged. Reported upstream as [VirusTotal/yara-x#819](https://github.com/VirusTotal/yara-x/issues/819).

### Added

- A "Fresh dependencies" CI workflow builds both binaries without `Cargo.lock` on every pull request, on every push to `main`, and weekly, so an upstream release that breaks installation is caught in CI.
- The README describes installing from crates.io.
- A "Release" workflow publishes the three crates to crates.io when a GitHub release is published, through crates.io Trusted Publishing: no API token is stored, and the job waits for the maintainer's approval in the `release` environment.

## [1.0.0] – 2026-10-22

The first public release.

### Added

- **Categories.** Files are scored from 0 to 100 for two categories. `secret` covers API keys, tokens, private keys, and credentials: 222 rules converted from gitleaks v8.30.1 plus hand-written rules for PKCS#12 files and DER private keys. `biometric` covers voice and face embeddings: float tensors of an embedding width in `.npy`, `.npz`, and safetensors files (single tensors, tensors named like embeddings, and banks of identically shaped vectors) and printed float arrays of an embedding width. Scoring uses YARA-X rules and structural checks; it never calls an LLM, never uses the network at scan time, and never records matched values.
- **Command line.** `riskgrep scan` scores files, directories, and standard input, as text or JSON; `--fail-at CATEGORY=N` sets an inclusive exit-status threshold. `riskgrep baseline` records known findings in `.riskgrep-baseline.json`, and `riskgrep rules list|compile|test` inspects, compiles, and tests the rulesets.
- **Git hook.** `riskgrep git install-hook` installs a `pre-commit` hook that scores the lines added by the staged changes and blocks at `secret` 80 and `biometric` 75 by default. Renamed, copied, binary, and partly read files are scored whole.
- **Claude Code hook.** `riskgrep-claude` is a `PreToolUse` hook for `Read`, `NotebookRead`, `Grep`, and `Bash`. It answers `ask` or `deny` at its thresholds (`biometric` ask 50 and deny 75, `secret` ask 80 and deny 95) and never `allow`. For files whose findings all come from rules with complete line locations, the reason names the flagged lines and a `Read` limited to other lines gets no decision. `riskgrep-claude print-config` prints the `settings.json` fragment.
- **Configuration.** Settings are layered: built-in defaults, `~/.config/riskgrep/config.toml`, the repository's `.riskgrep.toml`, and command-line options. Keys cover thresholds per integration, rulesets and extra ruleset directories, rule weight overrides, `[ignore]` paths and rules, scan limits, and `trusted_repos`, without which the Claude Code hook never reads a repository's configuration or baseline. Compiled rules and per-file evidence (no file content) are cached in `~/Library/Caches/riskgrep` on macOS and `$XDG_CACHE_HOME/riskgrep` or `~/.cache/riskgrep` on Linux.
- **Platforms.** macOS and Linux.

### Accuracy

The release bar is at most 1 flagged file per 1,000 ordinary files per category, 100% recall on the generated positives for provider-specific secrets and biometric file formats, and at least 90% recall on generated generic secrets. Measured by `cargo xtask eval` in the 2026-10-20 run, which the stored baseline holds:

- 55,877 files scanned in 13 pinned public repositories: 25 flagged for `secret` (0.45 per 1,000) and 5 for `biometric` (0.09 per 1,000).
- 250 generated negatives: none flagged.
- 470 generated positives: 100% recall for provider-specific secrets, generic secrets, and biometric formats.

Recall on generated positives is circular by construction and covers only the generated formats; most converted gitleaks rules have no generated positive. See [`eval/README.md`](eval/README.md) and [`docs/known-limitations.md`](docs/known-limitations.md).

### Performance

p95 latency targets, checked by `cargo xtask bench` on the release build with a warm rules bundle, and the p95 measured on the release candidate (Apple M4 Max, macOS, load average about 4.5):

| Case | Target | Measured |
|---|---|---|
| Claude Code `Read`, cached file | 5 ms | 4.49 ms |
| Claude Code `Read`, uncached 64 KB text file | 15 ms | 9.35 ms |
| `riskgrep scan -`, 4 KB | 15 ms | 11.31 ms |
| `riskgrep scan -`, 1 MB | 50 ms | 17.05 ms |
| `riskgrep git pre-commit`, 20 staged text files, uncached | 100 ms | 90.15 ms |

[Unreleased]: https://github.com/jkotzker/riskgrep/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/jkotzker/riskgrep/releases/tag/v1.0.1
[1.0.0]: https://github.com/jkotzker/riskgrep/releases/tag/v1.0.0
