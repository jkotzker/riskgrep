# riskgrep-core

The scoring engine of [RiskGrep](https://github.com/jkotzker/riskgrep): rulesets, classification, YARA-X scanning, scoring, the evidence cache, configuration, and baselines. It scores files from 0 to 100 per sensitive-data category (`secret` and `biometric`) and never records matched values. The built-in rulesets are embedded at build time.

This crate is the library behind the `riskgrep` command line and the `riskgrep-claude` Claude Code hook. Documentation for users is in the [main README](https://github.com/jkotzker/riskgrep#readme).

Licensed under MIT or Apache-2.0, at your option. The `secrets-core` ruleset is converted from gitleaks (MIT); see `rulesets/secrets-core/UPSTREAM.md`.
