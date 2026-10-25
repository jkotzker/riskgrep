# riskgrep-claude

A Claude Code `PreToolUse` hook from [RiskGrep](https://github.com/jkotzker/riskgrep). For `Read`, `NotebookRead`, `Grep`, `Bash`, and MCP tool calls it finds the files the call would read (and for `Glob` it judges the file names the call would reveal), scores them for secrets and biometric embeddings, and answers `ask` or `deny` when a score reaches its threshold. It never answers `allow` and never puts matched content in its output.

```sh
riskgrep-claude print-config   # a settings.json fragment to merge by hand
```

The hook's behaviour, thresholds, and known limitations are in the [main README](https://github.com/jkotzker/riskgrep#readme) and [`docs/claude-code.md`](https://github.com/jkotzker/riskgrep/blob/main/docs/claude-code.md).

Licensed under MIT or Apache-2.0, at your option.
