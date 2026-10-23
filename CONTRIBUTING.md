# Contributing

Bug reports, detection gaps, false positives, and pull requests are welcome.

- **Issues.** Describe what you ran, what you expected, and what happened. Reproduce with generated data only: never paste a real secret or real biometric data into an issue. Report security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).
- **Setup.** After cloning, run `cargo install --locked --path crates/riskgrep` and `riskgrep git install-hook`: git never enables hooks from a clone by itself.
- **Pull requests.** Open them against `main`. CI must pass, including the required `riskgrep scan` job, which scans the repository with RiskGrep itself. Pull requests are merged with merge commits.

The build, test, evaluation, and benchmark commands, the documentation rules, and the rules for test data are in [`AGENTS.md`](AGENTS.md). They apply to people and coding agents alike.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed under MIT or Apache-2.0, as the rest of the project, without any additional terms or conditions.
