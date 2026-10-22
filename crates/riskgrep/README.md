# riskgrep

The command line and git `pre-commit` hook of [RiskGrep](https://github.com/jkotzker/riskgrep), a local scanner that scores files from 0 to 100 per sensitive-data category: `secret` (API keys, tokens, private keys, and credentials) and `biometric` (voice and face embedding files and printed embedding arrays). It uses YARA-X rules and structural checks, never calls an LLM or the network at scan time, and never records matched values.

```sh
riskgrep scan . --fail-at secret=80,biometric=75
riskgrep git install-hook
```

Installation, configuration, accuracy figures, and known limitations are in the [main README](https://github.com/jkotzker/riskgrep#readme).

Licensed under MIT or Apache-2.0, at your option.
