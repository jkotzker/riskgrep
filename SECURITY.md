# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a vulnerability. Include the RiskGrep version, the platform, and the steps to reproduce. Reproduce with generated data only: never include a real secret or real biometric data in a report.

## Supported versions

Security fixes are made for the latest release.

## Scope

RiskGrep protects against accidental exposure of sensitive data by a cooperative agent or person (see [What RiskGrep is not](README.md#what-riskgrep-is-not)). A vulnerability is a way in which it fails that purpose contrary to its documentation, for example:

- a matched value (secret text or embedding data) appearing in a report, hook output, log line, error message, cache row, or baseline entry;
- a hook failing open contrary to the docs: the Claude Code hook giving no decision where [`docs/claude-code.md`](docs/claude-code.md) says it asks or denies (on a scan error, a timeout, or a crash), or the git hook passing a commit it is documented to block;
- an untrusted repository's `.riskgrep.toml` or baseline loosening the Claude Code hook's checks;
- the cache directory or its files becoming readable or writable by another user;
- network access at scan time.

Out of scope:

- bypasses by a hostile agent or user running as the same user, such as editing the user configuration, writing cache rows, replacing the compiled rules bundle, or reading a file through a path RiskGrep does not see;
- detection gaps and false positives, including those listed in [`docs/known-limitations.md`](docs/known-limitations.md); report these as ordinary GitHub issues.
