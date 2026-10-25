# Changelog

All notable changes to RiskGrep are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Upgraded the YARA-X engine from 1.21.0 to 1.22.0, with `yara-x-macros` and `yara-x-parser` pinned to the same version. Detection results and scores are unchanged on the evaluation corpus. The compiled rules bundle is keyed by the engine version, so each machine compiles it once on first use after the upgrade.

### Added

- The Claude Code hook gates MCP tools and `Glob`. `claude_code.mcp_tools` maps each MCP tool to the input fields that hold its paths and to what it does with them (`read`, `walk`, `names`, or `none`); built-in entries cover the official filesystem server and Desktop Commander, and user entries, with `*` wildcards, add other servers. An MCP tool without an entry follows `on_unresolved`. `Glob`, and MCP tools that list directories, are judged by the file names they would reveal, with the path rules alone. `print-config` now emits the matcher `^(Read|NotebookRead|Grep|Glob|Bash|mcp__.*)$`; an existing installation must update its matcher to gate the new tools.
- `RiskGrep::scan_names` scores file names without reading their content.
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
