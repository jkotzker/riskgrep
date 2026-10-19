# RiskGrep

RiskGrep is a local, non-LLM scanner that scores files from 0 to 100 per sensitive-data category (such as secrets, credentials, and personal data) using YARA-X rules, with a Claude Code hook adapter that can check files before an agent reads them; it never uses the network at scan time and never records matched values. Licensed under MIT or Apache-2.0, at your option.
