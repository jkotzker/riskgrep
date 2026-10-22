# Agent instructions

RiskGrep is a local scanner that scores files from 0 to 100 per sensitive-data category (`secret`, `biometric`) with YARA-X rules and structural checks. Read [`README.md`](README.md) for what it does and [`docs/known-limitations.md`](docs/known-limitations.md) for what it does not.

## Layout

- `crates/riskgrep-core`: the library (classification, rules bundle, scanning, scoring, cache, configuration, baselines). The built-in rulesets live in `crates/riskgrep-core/rulesets/` and are embedded at build time; their format is in [`crates/riskgrep-core/rulesets/README.md`](crates/riskgrep-core/rulesets/README.md).
- `crates/riskgrep`: the `riskgrep` command line and the git `pre-commit` hook.
- `crates/riskgrep-claude`: the Claude Code `PreToolUse` hook ([`docs/claude-code.md`](docs/claude-code.md)).
- `xtask`: `cargo xtask eval`, `cargo xtask bench`, and `cargo xtask convert-gitleaks` (not published).

## Setup

After cloning, install the pre-commit hook: git never enables hooks from a clone by itself.

```sh
cargo install --path crates/riskgrep
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
- **Latency.** `cargo xtask bench` (needs `hyperfine`) checks the p95 targets in `bench/targets.toml` and the stored per-OS baseline. Run it on an otherwise idle machine. Relaxing a target needs the maintainer's approval.
- **Repository scan.** CI runs `riskgrep scan . --fail-at secret=80,biometric=75 --on-error block` with the committed `.riskgrep.toml`. Add an `[ignore]` entry only for deliberate content (rule sources, upstream example keys, test data), scoped as narrowly as possible and commented with why it is safe.

## Rulesets

`crates/riskgrep-core/rulesets/secrets-core/gitleaks.yar`, `UPSTREAM.md`, and `stopwords/secrets_core_*.txt` are generated: never edit them by hand. Regenerate with the command in `UPSTREAM.md`; `cargo test -p xtask --test convert` fails when the committed output is stale. Every ruleset's `tests.toml` cases run with `riskgrep rules test`.

## Data safety

- Never commit matched secrets or real biometric data. Generate fixtures that look like secrets, and random-float embeddings, at test run time, so the repository itself never trips a secret scanner.
- Never print embedding vectors or file contents that hold them, in tests, tools, or logs; assert shapes and counts.
- No report, hook output, log line, error message, cache row, or baseline entry may contain matched bytes. `Evidence` has no field that can hold match content; keep it that way.

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
