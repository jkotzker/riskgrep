# Agent instructions

RiskGrep is a local scanner that scores files from 0 to 100 per sensitive-data category (`secret`, `biometric`) with YARA-X rules and structural checks. Read [`README.md`](README.md) for what it does and [`docs/known-limitations.md`](docs/known-limitations.md) for what it does not.

## Priorities

- **General purpose.** RiskGrep is not tied to any one agent, system, or use case. What is specific to one agent harness belongs in that harness's adapter and everything else in shared code, and a new setting goes under an agent's section only if it concerns only that agent. Check each design, issue, and change for assumptions about one agent, one system, or one user.
- **No assumptions from one setup.** Do not infer anything about the world or about the project's users from one contributor's machine, tools, configuration, or session. A tool being present on one machine is not evidence that it is common. Establish such claims from a neutral source and say what was measured, or mark them unverified.

## Layout

- `crates/riskgrep-core`: the library (classification, rules bundle, scanning, scoring, cache, configuration, baselines). The built-in rulesets live in `crates/riskgrep-core/rulesets/` and are embedded at build time; their format is in [`crates/riskgrep-core/rulesets/README.md`](crates/riskgrep-core/rulesets/README.md).
- `crates/riskgrep`: the `riskgrep` command line and the git `pre-commit` hook.
- `crates/riskgrep-claude`: the Claude Code `PreToolUse` hook ([`docs/claude-code.md`](docs/claude-code.md)).
- `xtask`: `cargo xtask eval`, `cargo xtask bench`, `cargo xtask instructions`, and `cargo xtask convert-gitleaks` (not published).

## Setup

After cloning, install the pre-commit hook: git never enables hooks from a clone by itself.

```sh
cargo install --locked --path crates/riskgrep
riskgrep git install-hook
```

## Build and test

The toolchain is pinned in `rust-toolchain.toml`; rustup installs it on first use. Run all of these before proposing a change; CI runs the same.

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p riskgrep -p riskgrep-claude
./target/release/riskgrep rules test
```

Test output must have no warnings. Write the failing test first, then the change.

## Gates

- **Accuracy.** `cargo xtask eval --skip-oss` runs the synthetic corpus in seconds and is what CI runs. Any change to rules, classification, or scoring also needs the full `cargo xtask eval`, which clones 13 pinned public repositories into `eval/oss/` (gitignored, about 850 MB, needs network access). The release bar must pass, and `eval/baseline-metrics.json` changes only through `--write-baseline` with the reason stated in the pull request. See [`eval/README.md`](eval/README.md).
- **Latency regressions.** `cargo xtask instructions` answers "did this change make it slower?". It counts the instructions of every case in `bench/targets.toml` and fails when a case's count is more than 1% over or under the committed baseline. CI's `instruction counts` job runs it with Valgrind's callgrind on the pinned `ubuntu-26.04` runner image, against `bench/instructions-linux-x86_64-callgrind.json`. That baseline holds for that image, its Valgrind and C library, and the toolchain in `rust-toolchain.toml`, under any load. `cargo xtask instructions --counter callgrind` also runs on any other Linux x86_64 machine with Valgrind, but its counts there can differ from the baseline. A deliberate increase rewrites the baseline in the pull request that causes it, with the reason stated: copy the `baseline` object of the job's `instruction-counts` artifact into the file, or run `--write-baseline` on Ubuntu 26.04 x86_64 with the same Valgrind and toolchain. A drop fails too, so the baseline follows improvements. An update within the `ubuntu-26.04` image, or of the Valgrind package the job installs on each run, can still move every count at once; the fix is the same rewrite, with the update as the reason, and moving the job to another image needs one too. On macOS the counter is `/usr/bin/time -l` and on Linux `perf` can be used where a hardware counter exists; their counts belong to one machine, so their baselines go in the target directory, uncommitted, to compare two local builds. Hosted macOS runners report no instruction count.
- **Latency targets.** `cargo xtask bench` (needs `hyperfine`) answers "is it fast enough?": it checks the p95 targets in `bench/targets.toml` and the stored per-OS baseline. Run it on an otherwise idle machine. Relaxing a target needs the maintainer's approval.
- **Repository scan.** CI runs `riskgrep scan . --fail-at secret=80,biometric=75 --on-error block` with the committed `.riskgrep.toml`. Add an `[ignore]` entry only for deliberate content (rule sources, upstream example keys, test data), scoped as narrowly as possible and commented with why it is safe.

## Rulesets

`crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`, `UPSTREAM.md`, and `stopwords/secrets_core_*.txt` are generated: never edit them by hand. Regenerate with the command in `UPSTREAM.md`; `cargo test -p xtask --test convert` fails when the committed output is stale. Every ruleset's `tests.toml` cases run with `riskgrep rules test`.

## Data safety

- Never commit matched secrets or real biometric data. Generate fixtures that look like secrets, and random-float embeddings, at test run time, so the repository itself never trips a secret scanner.
- Never print embedding vectors or file contents that hold them, in tests, tools, or logs; assert shapes and counts.
- No report, hook output, log line, error message, cache row, or baseline entry may contain matched bytes. `Evidence` has no field that can hold match content; keep it that way.
- Vendored or generated files that hold secret-shaped strings on purpose (upstream rule sets, published example keys, test vectors) are reviewed before they land. In the same change, add each such file to `paths-ignore` in `.github/secret_scanning.yml`, by exact path rather than directory, so GitHub secret scanning does not alert on reviewed content. Real secrets anywhere else stay scanned, and the repository scan in CI still covers these files.

## Private files

Anything private to a contributor or machine (plans, notes, scratch output, local settings) goes in the gitignored `.claude/local/`. Never commit it.

## Documentation

- Write each paragraph as one line; never hard-wrap prose.
- Use the serial (Oxford) comma.
- No first person and no personal names.
- Measured claims name the command that reproduces them.
- File newly found detection gaps as GitHub issues. Keep `docs/known-limitations.md` accurate when a change affects one of its entries.

## Contributing changes

- Open a pull request to `main`; nothing is pushed to `main` directly.
- Pull requests are merged with merge commits only (no squash or rebase merges).
- CI must pass: `test (macos-latest)`, `test (ubuntu-latest)`, and `riskgrep scan`.
- Commit subjects are under 72 characters and describe the change technically.

## Releases

- A release bumps `version` in the root `Cargo.toml` (and the `riskgrep-core` path-dependency versions), adds a dated `CHANGELOG.md` entry, and lands through a pull request like any other change.
- The maintainer tags the merge commit with a signed tag `v<version>` and publishes a GitHub release from it. `.github/workflows/release.yml` then publishes the three crates to crates.io through Trusted Publishing, after the maintainer approves the job in the `release` environment. The job fails if the tag does not match the workspace version. After publishing, it runs `.github/scripts/crates_release_assets.py`, which checks each published `.crate` file against the checksum in the crates.io index, then adds a "Published to crates.io" section to the release notes and attaches the `.crate` files and `SHA256SUMS`.
- Never publish to crates.io by hand, and never add a crates.io API token to the repository.
