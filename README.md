# RiskGrep

RiskGrep is a local scanner that scores files from 0 to 100 per sensitive-data category. Version 1 has two categories: `secret` (API keys, tokens, private keys, credentials) and `biometric` (voice and face embedding files and printed embedding arrays). Scoring uses YARA-X rules and small structural checks in Rust; it never calls an LLM, never uses the network at scan time, and never records matched values. Reports hold rule identifiers, paths, line numbers, and scores only.

It has three front ends: the `riskgrep` command line, a git `pre-commit` hook, and `riskgrep-claude`, a Claude Code `PreToolUse` hook that asks or denies before an agent reads a sensitive file.

Licensed under MIT or Apache-2.0, at your option.

## What RiskGrep is

- **A static risk-assessment tool.** It scores files, directories, standard input, and the files a shell command names, from 0 to 100 for each category of sensitive data.
- **Heuristic, with no LLM.** Scores come from pattern rules, checksums, and structural checks such as file headers and tensor shapes. Nothing is sent to a model or over the network, and with the same rules and configuration the same input always gets the same score.
- **A way to assess content without reading it.** Agents and automated systems learn how risky something is before they open it. Reports carry rule identifiers, paths, line numbers, and scores, never the matched content.
- **Scores first, decisions second.** The command line reports scores and fails only at thresholds you choose; the git hook blocks at its thresholds; the Claude Code hook asks or denies at its own. Each consumer sets the policy that fits it.

## What RiskGrep is not

- **Not a security measure against a hostile agent.** It protects against accidental exposure by a cooperative agent or person. An agent that sets out to get around it can do so, for example by editing your configuration, reading a file through a path RiskGrep does not see, or running a program that opens the file itself.
- **Not a replacement for sandboxing.** It does not isolate processes or restrict what a program can reach on the filesystem or the network.
- **Not a replacement for permission rules.** It does not control access to files or tools; it scores content so that something else can decide. Keep your file permissions and your agent's allow and deny rules.
- **Not a guarantee of anything.** Heuristics miss sensitive content and flag harmless content. A low score does not mean a file is safe, and a hook decision does not guarantee that a read, a commit, or a leak is prevented. See [Known limitations](docs/known-limitations.md).

Use it as one layer alongside those controls, not in place of them.

## Install

RiskGrep is built from source with the stable Rust release pinned in `rust-toolchain.toml` (rustup installs it on first use). Nothing is published to a registry yet.

```sh
cargo install --path crates/riskgrep
cargo install --path crates/riskgrep-claude
```

This puts `riskgrep` and `riskgrep-claude` in `~/.cargo/bin`. Run `riskgrep rules compile` once afterwards, from any directory: it compiles the rulesets the Claude Code hook uses (the defaults and your user configuration) and stores them in the cache directory, so the first scan or hook call does not pay for it (about one second). It prints `already compiled` when the cache already holds them. Add `--repo` to compile the rulesets a repository's `.riskgrep.toml` selects instead; run it from inside that repository.

## Command line

```sh
riskgrep scan path/to/file.env                  # a file
riskgrep scan src/ --format json                # a directory, as JSON
cat notes.txt | riskgrep scan -                 # standard input
riskgrep scan . --fail-at secret=80,biometric=75
riskgrep baseline .                             # record current findings as known
riskgrep rules list                             # every rule, category, and weight
riskgrep rules test                             # run the rulesets' own test cases
```

`--fail-at CATEGORY=N[,CATEGORY=N…]` makes the exit status 1 when a target's score for that category is at or above `N`. A target meets a threshold when its score rounded to one decimal, the number every output shows, is at least the threshold; `--fail-at`, the git hook's `block_at`, and the Claude Code hook's `ask` and `deny` thresholds all use that one rule (`cargo test -p riskgrep --test cli fail_at_is_inclusive`). Exit status 2 means a target could not be scanned and `--on-error block` applies; 3 is a usage or configuration error. When standard output is closed early (`riskgrep scan … | head -1`), the command stops writing without a message and keeps the exit status the scan computed, so a gate in a pipeline with `set -o pipefail` still fails on 1 or 2; a scan that passed exits 0 (`cargo test -p riskgrep --test epipe`). `--category` and `--ruleset` narrow what runs, and `--no-cache` skips the evidence cache. Findings recorded by `riskgrep baseline` go to `.riskgrep-baseline.json` in the repository root; later scans treat them as known. Run `riskgrep --help` and `riskgrep <command> --help` for every option.

## Git hook

```sh
riskgrep git install-hook          # writes the pre-commit hook (honours core.hooksPath)
riskgrep git pre-commit            # what the hook runs; also usable by hand
```

The hook scores the lines added by the staged changes (`--full-files` or `git.full_files = true` scores whole files; renamed and copied files, binary files such as key stores and tensor files, and partly read files are always scored whole) and exits 1 when a category reaches its `git.block_at` threshold: 80 for `secret` and 75 for `biometric` by default. It prints the path, rule identifiers, score, and line numbers, never the matched text.

## Claude Code hook

`riskgrep-claude` checks `Read`, `NotebookRead`, `Grep`, and `Bash` tool calls before they run. It finds the files the call would read, scans them, and answers `ask` or `deny` when a score reaches its threshold (defaults: `biometric` ask at 50 and deny at 75, `secret` ask at 80 and deny at 95). It never answers `allow`, and any other tool is untouched. When every finding in a text file comes from a rule whose locations cover every match on their own lines, the reason names the flagged line numbers and tells the agent to read the rest with `offset` and `limit`, and a `Read` whose requested lines, widened by one line on each side, avoid every flagged line gets no decision; other files get no partial read (see [Partial reads](docs/claude-code.md#partial-reads)). A Bash command whose files the analysis cannot determine gets no decision by default (`claude_code.on_unresolved = "allow"`); set it to `"ask"` or `"deny"` to prompt or block on such commands (see [Known limitations](docs/known-limitations.md#the-bash-analysis-is-a-best-effort-static-reading-and-unresolved-commands-get-no-decision-by-default)).

```sh
riskgrep rules compile        # warm the rules cache before the first call (any directory)
riskgrep-claude print-config  # prints a settings.json fragment
```

Merge the printed fragment into `~/.claude/settings.json` by hand: a `PreToolUse` hook entry and deny rules that keep the agent from editing `~/.config/riskgrep/`. The full behaviour, decision rules, time budget, and what was verified against Claude Code is in [`docs/claude-code.md`](docs/claude-code.md).

## Configuration

Settings are layered: built-in defaults, then `~/.config/riskgrep/config.toml` (both platforms), then the repository's `.riskgrep.toml`, then command-line options. Example:

```toml
trusted_repos = ["/Users/me/work/project"]

[claude_code.thresholds.secret]
ask = 80
deny = 95

[git.block_at]
secret = 85

[limits]
walk_files = 20000
```

Other keys select rulesets (`rulesets`, `extra_ruleset_dirs`), adjust rule weights (`weight_overrides`), and list paths and rules to ignore (`[ignore]`).

Trust: the Claude Code hook reads a repository's `.riskgrep.toml` and `.riskgrep-baseline.json` only when the repository is listed in `trusted_repos` in the user config. An agent can write files in a repository, so an untrusted repository file is never allowed to loosen the checks. The command line and the git hook read the repository files without this restriction. `trusted_repos` in a repository file is ignored.

The cache (compiled rules and per-file evidence, with no file content) is in `~/Library/Caches/riskgrep` on macOS and `$XDG_CACHE_HOME/riskgrep` or `~/.cache/riskgrep` on Linux.

## Changes users may notice

- `--fail-above` is replaced by `--fail-at`, which is inclusive like the hook thresholds.
- Relative paths in configuration (`extra_ruleset_dirs`, `trusted_repos`) resolve against the directory of the file that declares them (`~/.config/riskgrep/` for the user file, the repository root for `.riskgrep.toml`), never against the working directory. Use absolute paths where a path meant the working directory.
- The user configuration file is read only when `HOME` is an absolute path; without one, the defaults apply and the cache is off.
- Baselines identify findings decided by a tensor header or a path-name rule by the file's content, not by rule and path. Regenerate `.riskgrep-baseline.json` with `riskgrep baseline` if it holds such findings from an earlier build.
- Text output and git pre-commit messages show `line unknown` for findings in the last MiB of a text file larger than 8 MiB; JSON output keeps `line_start` and `line_end` at 0 for them.

## Accuracy

`cargo xtask eval` measures the shipped release binary against a generated corpus and 13 pinned public repositories (55,877 files scanned in the 2026-10-20 run; files whose scan times out are listed by the run and not counted). The release bar is at most 1 flagged file per 1,000 ordinary files per category, 100% recall on the generated positives for provider-specific secrets and biometric file formats, and at least 90% for generic secrets; the current numbers meet it. The 100% recall figures cover only the generated formats: AWS, GitHub, Anthropic, Stripe, Slack, npm, and OpenAI tokens, PEM private keys, PKCS#12 files, and DER private-key headers for secrets, and `.npy`, `.npz`, safetensors (named, unnamed, and banks), and printed float arrays at the listed embedding widths for biometrics. Most of the 222 rules converted from gitleaks have no generated positive in the evaluation, and formats outside these lists are not measured at all. The measurements, corpus, and caveats are in [`eval/README.md`](eval/README.md). The recall figures on generated positives are circular by construction, and the public-repository figures are the better estimate of false positives.

Latency is checked by `cargo xtask bench` against the targets in [`bench/targets.toml`](bench/targets.toml) (for example, a cached hook call under 5 ms at the 95th percentile) and against a stored baseline per OS. The local run is the gate. CI runs the same benchmark on hosted runners as an informational step that cannot fail the build, because shared runners are slower and noisier than the reference machine the targets were set on.

## Known limitations

What RiskGrep does not detect, what it may flag wrongly, and why is listed in [Known limitations](docs/known-limitations.md). Read it before relying on a score.

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask eval --skip-oss    # synthetic corpus only; omit the flag to include public repositories
cargo xtask bench              # needs hyperfine
```

CI (`.github/workflows/ci.yml`) runs the same checks on macOS and Ubuntu.

## Licence

MIT or Apache-2.0, at your option: see [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE). The `secrets-core` ruleset is converted from gitleaks (MIT); see `rulesets/secrets-core/UPSTREAM.md`.
