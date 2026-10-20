# Evaluation

`cargo xtask eval` measures the shipped rulesets against a synthetic corpus and a pinned set of public repositories, and fails when the release accuracy bar is not met or a metric is worse than `baseline-metrics.json`.

```sh
cargo xtask eval                    # synthetic corpus and OSS repositories
cargo xtask eval --skip-oss         # synthetic corpus only (no network, seconds)
cargo xtask eval --write-baseline   # also rewrite baseline-metrics.json from a failing run
```

## How it runs

- It builds the release binary (`cargo build --release -p riskgrep`) and runs `riskgrep scan --no-cache --format json`, so it measures the shipped artefact, not a debug build of the library. `HOME` points at an empty temporary directory, so no user configuration or cache is involved; that home's config only raises `limits.walk_files` so whole repositories fit in one walk.
- Scores come from the JSON report (rounded to 0.1). A file is **flagged** for a category when its score is at or above the lowest default threshold for that category across integrations: secret ≥ 80 (`git.block_at`), biometric ≥ 50 (`claude_code.ask`). Results are also printed at every default threshold (`claude_code.ask`, `claude_code.deny`, `git.block_at`); the thresholds are read from `Config::default()`.
- Raw reports (rule ids, paths, lines, scores; no file content) are kept in `target/eval/` for analysis; the latest metrics are in `target/eval/metrics.json`.

## Synthetic corpus

Generated deterministically at run time into a temporary directory (`xtask/src/eval.rs`, `corpus()`); nothing is written to the repository. Positive file names are neutral (no `embedding`, `speaker`, … in the path), so they measure the content rules without help from `path_biometric_name`.

| Group | Formats | Files |
|---|---|---|
| Provider-specific secrets | `aws_access_key`, `github_pat`, `anthropic_key`, `pem_private_key`, `stripe_key`, `slack_bot_token`, `npm_token`, `openai_key` (each in 7 file types; PEM in 4 containers), `pkcs12`, `der_key` | 20 each, 200 |
| Generic secrets | `generic_api_key` assignments in 7 file types and key names | 50 |
| Biometric formats | `npy`, `npz`, `safetensors_named` (tensor name matches the embedding regex), `safetensors_unnamed`, printed floats in python, numpy, and JSON styles; widths 128 to 3072 | 20 each, 140 |
| Hard negatives (generated) | sensor CSVs (plain float matrices and timestamped logs), model-weight safetensors, integer `.npy`, example and placeholder keys, low-entropy assignments, UUID lists, hex hashes, base64 blobs, source code, prices and logs | 220 |
| Hard negatives (existing) | the `expect = "none"` cases from the ruleset tests, plus the model-weight and sensor-CSV cases from `ruleset_biometric.rs` | 11 |

## OSS corpus

`oss-repos.toml` pins 13 repositories with 9 language labels (Python, Go, JavaScript, TypeScript, Rust, Java, Ruby, C, and Markdown for MDN's docs). They are fetched shallow at the pinned commits into `eval/oss/` (gitignored; about 850 MB on disk, so exclude it from any sync service: `xattr -w com.dropbox.ignored 1 eval/oss` for Dropbox). The run scans 55,876 files (scanned or partially scanned; skipped binaries are not counted).

Findings are inspected only through the report (rule ids, paths, lines, scores). `oss-known-findings.json` lists findings that are excluded from the false-positive count (`rule`, `path` relative to `eval/oss`, `line`); a flagged file is excluded only when every hit behind its score is listed.

### Decisions on OSS findings (2026-10-19)

| Finding | Files | Decision |
|---|---|---|
| `private_key` (terraform test keys, prometheus test keys, MDN SubtleCrypto examples) | 14 | Provider-specific rule: recorded as known findings and excluded |
| `hashicorp_tf_password` in terraform test data | 3 | False positive: a 10-character dummy value containing a dictionary word, entropy 2.9 |
| `curl_auth_user` in `prometheus/scripts/sync_repo_files.sh` | 1 | False positive: the value is two shell variable references |
| `generic_api_key` (credential-named keys in test code, test configs, and docs) | 20 | Counted as false positives without triage (the bar holds even so) |
| `npz_embedding_tensor` in scipy (benchmark and FFT reference arrays whose last dimension is an embedding width) | 6 | False positives: test artefacts, none named as an embedding |
| `printed_embedding_array` in `transformers/tests/utils/test_modeling_rope_utils.py` | 1 | False positive: expected values of a test |

Before the rule changes below, 124 scipy `.npy`/`.npz` files (linprog benchmark matrices, test reference data) scored 70; they were counted as false positives, none being named as an embedding.

## Release bar

Per category, at the flag threshold: at most 1 flagged file per 1,000 ordinary files (synthetic hard negatives and OSS each); recall 100% for provider-specific secret rules and for biometric file formats, at least 90% for generic secret rules.

## Results (2026-10-19)

| Metric | Value | Bar | |
|---|---|---|---|
| Recall, provider-specific secrets | 200/200 (100%) | 100% | met |
| Recall, generic secrets | 50/50 (100%) | ≥ 90% | met |
| Recall, biometric formats | 140/140 (100%), every format 20/20 | 100% | met |
| Synthetic FP per 1,000, secret | 0/231 (0.0) | ≤ 1 | met |
| Synthetic FP per 1,000, biometric | 0/231 (0.0) | ≤ 1 | met |
| OSS FP per 1,000, secret | 24/55,876 (0.43); 14 known findings excluded | ≤ 1 | met |
| OSS FP per 1,000, biometric | 7/55,876 (0.13) | ≤ 1 | met |

`baseline-metrics.json` holds these numbers.

## Changes

### Weight tuning alone (first pass)

No weight setting met the bar: each missed positive scored below its threshold because of its rule's weight (generic 50 < 80, `safetensors_float_tensor` 30 < 50, `printed_float_run` 40 < 50), and each rule fired at the same weight on the negatives it had to stay below. Candidate weights were evaluated by re-scoring the saved reports with the noisy-or scorer, checked against the binary with `weight_overrides` (138 secret and 333 biometric OSS files flagged by both for `generic_api_key = 80` plus `printed_float_run = 50`).

| Weights | Recall provider / generic / biometric | Synthetic FP per 1,000 secret / biometric | OSS FP per 1,000 secret / biometric |
|---|---|---|---|
| as first shipped | 1.000 / 0.000 / 0.429 | 0.0 / 0.0 | 0.07 / 2.22 |
| `generic_api_key` 80 | 1.000 / 1.000 / 0.429 | 21.6 / 0.0 | 2.22 / 2.22 |
| `printed_float_run` 50 | 1.000 / 0.000 / 0.857 | 0.0 / 86.6 | 0.07 / 5.96 |
| `safetensors_float_tensor` 50 | 1.000 / 0.000 / 0.571 | 0.0 / 112.6 | 0.07 / 2.22 |
| `npy_float_tensor`, `npz_float_tensor` 45 | 1.000 / 0.000 / 0.143 | 0.0 / 0.0 | 0.07 / 0.00 |

- `generic_api_key` at 80 flagged 120 more OSS files; 97 of them had no credential-like key name (`AutoTokenizer` model ids, `first_key`/`second_key` test data, `Sec-WebSocket-Key`, `key_sha256`, `CertIssuerPublicKey`, …). In the synthetic negatives it flagged the 5 UUID lists written as `key="<uuid>"`.
- `printed_float_run`: `min_floats` could not separate them either. OSS files whose longest float run reaches 64, 128, 256, 512, 1024 floats: 209, 175, 137, 109, 79; the plain float-matrix sensor CSVs are single runs of 40 to 7,230 floats.
- `npy`/`npz`: 124 scipy test and benchmark arrays scored 70; below 50 the npy and npz positives were lost.

### Rule changes

Each row is a full `cargo xtask eval` run of the release binary, in this order.

| Change | Recall generic / biometric | OSS FP per 1,000 secret / biometric | Synthetic FP per 1,000 |
|---|---|---|---|
| before | 0.000 / 0.429 | 0.07 / 2.22 | 0.0 / 0.0 |
| Embedding shapes and printed arrays (1, 2) | 0.000 / 1.000 | 0.07 / 0.13 | 0.0 / 0.0 |
| Credential-named generic secrets, weight 80 (3) | 1.000 / 1.000 | 0.43 / 0.13 | 0.0 / 0.0 |

1. **Embedding shapes** (`rulesets/biometric-embeddings`). The npy, npz, and safetensors post-processors take `embedding_dims` (`128,192,256,384,512,640,768,1024,1536,2048,3072,4096`): a float tensor qualifies only when its last dimension is one of them and at most two dimensions precede it. New rules `npy_embedding_tensor`, `npz_embedding_tensor` (70), and `safetensors_embedding_tensor` (70, ignoring tensors named like layer parameters: `weight`, `bias`, `running_mean`/`running_var`, `num_batches_tracked`) score embedding-shaped tensors; the existing float-tensor rules drop to 30. Each format's pair shares a family capped at its embedding weight (npy and npz 70, safetensors 85), so an embedding-shaped `.npy` scores 70, an unnamed embedding-shaped safetensors file 79 (70 and 30 by noisy-or), a named one 85, and other float arrays 30. In scipy, 6 of the 124 files are still flagged (their last dimension is an embedding width); all 25 generated model-weight files and the existing `w.safetensors` stay at 30.
2. **Printed arrays** (`text.yar`). `printed_embedding_array` (60) uses the new `float_array` post-processor: one bracketed array of floats whose length is an embedding width. `printed_float_run` stays at 40 for every other run of 64 or more floats; the two share family `printed_floats` capped at 60. One OSS file is flagged (a transformers test with expected values); the sensor CSVs stay at 40.
3. **Generic secrets** (`xtask/src/convert.rs`, `LOCAL_CHANGES`; `rulesets/secrets-core/UPSTREAM.md`, "Local changes"). The converter rewrites gitleaks' `generic-api-key` so the key name must end in a credential noun (`secret`, `password`/`passwd`, `token`, `credential(s)`, `creds`, `auth`, or `api`/`access`/`private`/`secret`/`auth`/`client`/`encryption`/`signing` followed by `key`) instead of containing a keyword followed by up to 20 more characters, and weights it 80 so a hit is flagged. The 20 OSS files it flags are counted as false positives without triage.

The weights above met the bar on the first measured setting, so no further tuning was done.
