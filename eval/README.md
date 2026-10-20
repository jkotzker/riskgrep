# Evaluation

`cargo xtask eval` measures the shipped rulesets against a synthetic corpus and a pinned set of public repositories, and fails when the release accuracy bar is not met or a metric is worse than `baseline-metrics.json`.

```sh
cargo xtask eval                    # synthetic corpus and OSS repositories
cargo xtask eval --skip-oss         # synthetic corpus only (no network, seconds)
cargo xtask eval --write-baseline   # rewrite baseline-metrics.json (from any run)
cargo xtask eval --keep-corpus DIR  # also keep the synthetic corpus in DIR (an empty or new directory)
```

## How it runs

- It builds the release binary (`cargo build --release -p riskgrep`) and runs `riskgrep scan --no-cache --format json`, so it measures the shipped artefact, not a debug build of the library. `HOME` points at an empty temporary directory, so no user configuration or cache is involved; that home's config only raises `limits.walk_files` so whole repositories fit in one walk.
- Scores come from the JSON report (rounded to 0.1). A file is **flagged** for a category when its score is at or above the lowest default threshold for that category across integrations: secret ≥ 80 (`git.block_at`), biometric ≥ 50 (`claude_code.ask`). Results are also printed at every default threshold (`claude_code.ask`, `claude_code.deny`, `git.block_at`); the thresholds are read from `Config::default()`.
- Raw reports (rule ids, paths, lines, scores; no file content) are kept in `target/eval/` for analysis; the latest metrics are in `target/eval/metrics.json`.
- `baseline-metrics.json` changes only with `--write-baseline`; without it, a run prints the changes it would write. The exit status reports the bar and regressions either way.

## Synthetic corpus

Generated deterministically at run time into a temporary directory (`xtask/src/eval.rs`, `corpus()`); nothing is written to the repository. Positive file names are neutral (no `embedding`, `speaker`, … in the path), so they measure the content rules without help from `path_biometric_name`.

| Group | Formats | Files |
|---|---|---|
| Provider-specific secrets | `aws_access_key`, `github_pat`, `anthropic_key`, `pem_private_key`, `stripe_key`, `slack_bot_token`, `npm_token`, `openai_key` (each in 7 file types; PEM in 4 containers), `pkcs12`, `der_key` | 20 each, 200 |
| Generic secrets | `generic_api_key` assignments in 7 file types and key names | 50 |
| Biometric formats | `npy`, `npz`, `safetensors_named` (tensor name matches the embedding regex), `safetensors_unnamed`, printed floats in python, numpy, and JSON styles; widths 128 to 3072; embedding banks as safetensors and as npz (3, 5, 20, or 109 identically shaped vectors keyed `p225…` VCTK-style or `person_NNN`) | 20 each, 180 |
| Hard negatives (generated) | sensor CSVs (plain float matrices and timestamped logs), model-weight safetensors, header-only model checkpoints (7 single parameters named or shaped like embeddings: timm `pos_embed`/`cls_token`, BERT `word_embeddings`, HF ViT `position_embeddings`, OpenCLIP `positional_embedding`/`visual.class_embedding`, diffusers `time_embedding`; and a reduced 4-tensor OpenCLIP checkpoint, BERT-base, CLIP ViT-B/32, SD UNet, timm ViT-B, Mamba-130m, RWKV-4 169M, Flax BERT-base, and TF BERT-base layouts, and a Google ViT-B/16 `.npz`), two reference-vector `.npz` archives in the style of scipy's FFT test data (`dct_K_N`/`dst_K_N` at 14 lengths, so each embedding width repeats 8 times), integer `.npy`, example and placeholder keys, low-entropy assignments, UUID lists, hex hashes, base64 blobs, source code, prices and logs | 239 |
| Hard negatives (existing) | the `expect = "none"` cases from the ruleset tests, plus the model-weight and sensor-CSV cases from `ruleset_biometric.rs` | 11 |
| Probes (not gated) | embeddings at widths outside `embedding_dims` (100, 300, 1000) as npy, safetensors, and printed floats; npy embeddings with 3 leading dimensions; generic secrets under env-style `<PROVIDER>_KEY` names and `consumer_key`/`app_key`/`master_key`/`HMAC_KEY`; tensor counts around the bank rule (2 identical tensors, 5 tensors of different shapes, banks at off-list widths) | 92 |

**Gated recall is circular by construction:** the biometric positives use widths that are in `embedding_dims` with at most two leading dimensions, banks use 3 or more identically shaped tensors, and the generic positives use key names the generic rule accepts. The probes measure what falls outside those lists; they are reported, kept in the baseline as `probe.*`, and neither gated nor compared.

## OSS corpus

`oss-repos.toml` pins 13 repositories with 9 language labels (Python, Go, JavaScript, TypeScript, Rust, Java, Ruby, C, and Markdown for MDN's docs). They are fetched shallow at the pinned commits into `eval/oss/` (gitignored; about 850 MB on disk, so exclude it from any sync service: `xattr -w com.dropbox.ignored 1 eval/oss` for Dropbox). The run scans 55,876 files (scanned or partially scanned; skipped binaries are not counted).

Findings are inspected only through the report (rule ids, paths, lines, scores). `oss-known-findings.json` lists findings that are excluded from the false-positive count (`rule`, `path` relative to `eval/oss`, `line`); a flagged file is excluded only when every hit behind its score is listed.

### Decisions on OSS findings (2026-10-19)

| Finding | Files | Decision |
|---|---|---|
| `private_key` (terraform test keys, prometheus test keys, MDN SubtleCrypto examples) | 14 | Provider-specific rule: recorded as known findings and excluded |
| `hashicorp_tf_password` in terraform test data | 3 | False positive: a 10-character dummy value containing a dictionary word, entropy 2.9 |
| `curl_auth_user` in `prometheus/scripts/sync_repo_files.sh` | 1 | False positive: the value is two shell variable references |
| `generic_api_key` (credential-named keys in test code, test configs, and docs) | 21 | Counted as false positives without triage (the bar holds even so) |
| `npz_embedding_tensor` in scipy (linprog benchmark arrays and `fftpack/tests/test.npz`, flat-named arrays whose last dimension is an embedding width) | 4 | False positives at 70 (ask): test artefacts, none named as an embedding. Until round 4, `fftpack/tests/fftw_double_ref.npz` and `fftw_single_ref.npz` also scored 94 by `npz_embedding_bank`; their members are named `dct_K_N` (an index segment), so they now score 30 |
| `printed_embedding_array` in `transformers/tests/utils/test_modeling_rope_utils.py` | 1 | False positive: expected values of a test |

Before the rule changes below, 124 scipy `.npy`/`.npz` files (linprog benchmark matrices, test reference data) scored 70; they were counted as false positives, none being named as an embedding.

## Release bar

Per category, at the flag threshold: at most 1 flagged file per 1,000 ordinary files (synthetic hard negatives and OSS each); recall 100% for provider-specific secret rules and for biometric file formats, at least 90% for generic secret rules.

## Results (2026-10-19)

| Metric | Value | Bar | |
|---|---|---|---|
| Recall, provider-specific secrets | 200/200 (100%) | 100% | met |
| Recall, generic secrets | 50/50 (100%) | ≥ 90% | met |
| Recall, biometric formats | 180/180 (100%), every format 20/20 | 100% | met |
| Synthetic FP per 1,000, secret | 0/250 (0.0) | ≤ 1 | met |
| Synthetic FP per 1,000, biometric | 0/250 (0.0); every safetensors checkpoint scores 25, the ViT `.npz` and reference-vector archives 30 | ≤ 1 | met |
| OSS FP per 1,000, secret | 25/55,876 (0.45); 14 known findings excluded | ≤ 1 | met |
| OSS FP per 1,000, biometric | 5/55,876 (0.09); all score 60 or 70 (ask), none reaches 75 | ≤ 1 | met |

`baseline-metrics.json` holds these numbers.

### Probes (not gated)

| Probe | Flagged |
|---|---|
| npy at widths 100, 300, 1000 | 0/10 |
| npy with 3 leading dimensions | 0/10 |
| safetensors at widths 100, 300, 1000 | 0/10 |
| printed floats at widths 100, 300, 1000 | 0/10 |
| generic, `<PROVIDER>_KEY` in `.env` | 9/10 |
| generic, `consumer_key`/`app_key`/`master_key`/`HMAC_KEY` | 3/12 (the `HMAC_KEY` ones) |
| safetensors with 2 identical embedding-shaped tensors | 10/10 (70: the single-tensor rule, not the bank) |
| safetensors with 5 embedding-shaped tensors of different shapes | 10/10 (70) |
| banks of 3 to 109 tensors at widths 100, 300, 1000 | 0/10 (25) |

Off-list embedding widths score 30 (npy), 25 (safetensors), or 40 (printed floats): known, not flagged. One `<PROVIDER>_KEY` probe is not reported: its random 32-character value happens to contain no digit, and gitleaks' generic allowlist `^[a-zA-Z_.-]+$` (kept by the converter) drops letter-only values as identifiers. Found with `--keep-corpus` by re-scanning the value under other key names (no evidence for any) and testing it against the allowlist pattern; the value was not printed.

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

1. **Embedding shapes** (`rulesets/biometric-embeddings`). The npy, npz, and safetensors post-processors take `embedding_dims` (`128,192,256,384,512,640,768,1024,1536,2048,3072,4096`): a float tensor qualifies only when its last dimension is one of them and at most two dimensions precede it. New rules `npy_embedding_tensor`, `npz_embedding_tensor` (70), and `safetensors_embedding_tensor` (70, ignoring tensors named like layer parameters: `weight`, `bias`, `running_mean`/`running_var`, `num_batches_tracked`) score embedding-shaped tensors; the existing float-tensor rules drop to 30. Each format's pair shares a family capped at its embedding weight (npy and npz 70, safetensors 85), so an embedding-shaped `.npy` scores 70, an unnamed embedding-shaped safetensors file 79 (70 and 30 by noisy-or), a named one 85, and other float arrays 30. In scipy, 6 of the 124 files are still flagged (their last dimension is an embedding width); all 25 generated model-weight files and the existing `w.safetensors` stay at 30. (Round 2 below re-weights the safetensors rules and narrows them for model checkpoints.)
2. **Printed arrays** (`text.yar`). `printed_embedding_array` (60) uses the new `float_array` post-processor: one bracketed array of floats whose length is an embedding width. `printed_float_run` stays at 40 for every other run of 64 or more floats; the two share family `printed_floats` capped at 60. One OSS file is flagged (a transformers test with expected values); the sensor CSVs stay at 40.
3. **Generic secrets** (`xtask/src/convert.rs`, `LOCAL_CHANGES`; `rulesets/secrets-core/UPSTREAM.md`, "Local changes"). The converter rewrites gitleaks' `generic-api-key` so the key name must end in a credential noun (`secret`, `password`/`passwd`, `token`, `credential(s)`, `creds`, `auth`, or `api`/`access`/`private`/`secret`/`auth`/`client`/`encryption`/`signing` followed by `key`) instead of containing a keyword followed by up to 20 more characters, and weights it 80 so a hit is flagged. The 20 OSS files it flags are counted as false positives without triage.

The weights above met the bar on the first measured setting, so no further tuning was done.

### Round 2: model checkpoints, the env key form

Each row is a full `cargo xtask eval` run.

| Change | Recall generic / biometric | Synthetic FP per 1,000 secret / biometric | OSS FP per 1,000 secret / biometric | Probes: env key / other key names |
|---|---|---|---|---|
| before (231 negatives, no checkpoints) | 1.000 / 1.000 | 0.0 / 0.0 | 0.43 / 0.13 | not measured |
| checkpoint exclusions and caps, 11 checkpoint negatives (4) | 1.000 / 1.000 | 0.0 / 0.0 | 0.43 / 0.13 | 1/10 / 0/12 |
| uppercase env form `[A-Z0-9_]+_KEY` (5) | 1.000 / 1.000 | 0.0 / 0.0 | 0.45 / 0.13 | 9/10 / 3/12 |

4. **Model checkpoints.** Header-only checkpoints scored 79 (timm `pos_embed`, `cls_token`, by the unnamed embedding-shape rule) or 85 (BERT `word_embeddings`, HF ViT `position_embeddings`, OpenCLIP `positional_embedding`/`class_embedding`, diffusers `time_embedding`, by the named rule). Now `safetensors_named_embedding` ignores tensor names matching `(\.weight|\.bias)$|pos(ition(al)?)?_?embed|word_embed|token|patch|time_embed|class_embed|cls_token|lm_head|wte|wpe` (case-insensitive) and also counts `dvector` and `spk_emb`. `safetensors_embedding_tensor` ignores the same names plus layer parameters and applies only to files with at most 4 tensors (`max_tensors`: a model layout has many, and CLIP's `text_projection` and `visual.proj` are embedding-shaped); it is weighted 60 and `safetensors_float_tensor` 25, so an unnamed embedding-shaped file scores 70 (ask, not deny). All 11 checkpoint negatives score 25. (Round 3 replaces `max_tensors` with name exclusions and a bank rule.)
5. **Env key form.** The generic rule also accepts an identifier ending in uppercase `_KEY` after `[A-Z0-9_]` (`STRIPE_KEY`, `HMAC_KEY`). It met the bar (one more OSS file, a terraform S3 backend test), so it is kept.

### Round 3: embedding banks, precise checkpoint exclusions

| Change | Recall biometric | Synthetic FP per 1,000 biometric | OSS FP per 1,000 biometric | Bank probes (2 tensors / mixed shapes / off-list) |
|---|---|---|---|---|
| before (140 gated biometric, 242 negatives) | 1.000 | 0.0 | 0.13 (7) | not measured |
| banks, `max_tensors` removed, exclusions, token-bounded names (6, 7) | 1.000 (180 gated) | 0.0 (243 negatives) | 0.13 (7; 2 at 94) | 10/10 / 10/10 / 0/10 |

Secret metrics did not change (OSS 0.45, synthetic 0.0).

6. **Embedding banks.** `max_tensors` is gone: it hid speaker and face stores (5, 20, and 109 tensors keyed `p225…`, each [192], and `person_NNN` [3,256], scored 25; `voiceprints.safetensors` with 20 such tensors scored 47.5). New rules `safetensors_embedding_bank` and `npz_embedding_bank` (80, outside the format families, so they add to them) fire on 3 or more non-excluded tensors or `.npy` members of one identical embedding shape (`min_bank = 3`); a bank scores 94 (1 − 0.2 × 0.3), a single unnamed embedding-shaped tensor stays at 70. CLIP's projections are excluded by name instead: the unnamed and bank rules ignore `(^|[._])proj(ection)?($|[._])`, `_proj$`, and `text_projection`, plus `in_proj`. The reduced OpenCLIP checkpoint (`positional_embedding`, `text_projection` [512,512], `token_embedding.weight`, `visual.class_embedding`) and all other checkpoint negatives score 25.
7. **Named rule.** Parameter-like names anywhere (`weight`, which also covers `weight_ih`/`weight_hh`; `bias`; `running_mean`/`running_var`; `in_proj`) and the model-parameter names never count, and `name_regex` is token-bounded (`(^|[._/-])` … `($|[._/-])`), so `invoice_total`, `surface_normals`, and `interface.dense` are not named embeddings while `face_embedding` and `voice.embedding` are.

### Round 4: bank share and flat keys, broader parameter names

| Change | Recall biometric (bank npz / bank safetensors) | Synthetic FP per 1,000 biometric | OSS FP per 1,000 biometric |
|---|---|---|---|
| before, with the 7 new negatives below (250 negatives) | 1.000 (20/20 / 20/20) | 28.0 (7: all 5 new checkpoints and both reference archives) | 0.13 (7; 2 at 94) |
| bank share and flat keys, parameter names, npz exclusions (8, 9, 10) | 1.000 (20/20 / 20/20, all ≥ 75) | 0.0 | 0.09 (5; none ≥ 75) |

Secret metrics did not change (OSS 0.45, synthetic 0.0). The probes did not change.

8. **Bank discriminators.** A bank (`safetensors_embedding_bank`, `npz_embedding_bank`) now also needs (a) at least half of the file's float tensors (`min_bank_share = 50`; `.npz`: float members, counting excluded and differently shaped ones) and (b) flat names: a name with a layer or block segment (`layers`, `blocks`, `h`, `encoder`, `encoderblock_0`, `decoder`, `transformer`, `backbone`, `model`) or an index segment between separators (`.0.`, `_1_`) never joins a bank. Identity keys such as `p225`, `person_000`, `spk_12`, `faces.0`, and `speakers/p225` stay flat. Without them, any checkpoint with 3 or more identically shaped embedding-width tensors scored 94: Mamba's `backbone.layers.N.mixer.D` [1536] × 24, RWKV-4's `time_mix_*` [1,1,768] and `time_decay` [768], Flax BERT's `kernel` [768,768] and `scale` [768], TF BERT's `gamma`/`beta` [768], a Google ViT `.npz` (`kernel`, `scale`, `bias`), and scipy's FFT reference archives (113 members `dct_K_N`/`dst_K_N`, embedding widths repeating 8 times).
9. **Parameter names.** The unnamed, bank, and named rules also ignore token-bounded JAX/Flax/TF, RWKV, Mamba, and ViT parameter names: `kernel`, `scale`, `gamma`, `beta`, `moving_mean`/`moving_variance`, `time_mix`, `time_decay`, `time_first`, `mixer`, `A_log`, `dt_bias`, `conv1d`, and `cls` (Google ViT's class token [1,1,768]). Token-bounded means between `.`, `_`, `/`, or the ends of the name, so a bank keyed `Betancourt_0`, `Betancourt_1`, … still counts.
10. **Unnamed single tensors and npz.** `npz_members` gained `exclude_name_regex`; `npz_embedding_tensor` and `safetensors_embedding_tensor` (70) ignore the same parameter and hierarchical names as the bank rules. Without the hierarchical part, every scipy-style reference archive scored 70 (`dct_1_128` [128] is embedding-shaped), and no parameter-name list could separate it. All 7 new negatives now score 25 (safetensors) or 30 (`.npz`); scipy's `fftw_double_ref.npz` and `fftw_single_ref.npz` score 30 (were 94).

## Caveats

Detection limits these measurements show; each is also in [`docs/known-limitations.md`](../docs/known-limitations.md).

- **Banks are found by a name and structure heuristic.** A checkpoint whose parameter names fall outside the exclusion lists (and are flat) can still score high when 3 or more of its tensors share one embedding shape and make up half its float tensors. A real bank stored under hierarchical names (`model.speakers.0.vec`) or alongside more other float tensors than bank vectors scores as a single unnamed tensor (70) or not at all.
- **Embedding widths outside `embedding_dims`** (100, 300, 1000 in the probes) score 30 (npy, npz), 25 (safetensors), or 40 (printed floats): not flagged.
- **Three or more leading dimensions** (`[2, 2, 2, d]`) are not embedding-shaped: 30, not flagged.
- **Banks of 2** identical tensors score 70 (the single-tensor rule, ask), not 94.
- **Several embeddings of different shapes** in one file score 70, not as a bank.
- **Generic secrets with letter-only values** are dropped by gitleaks' generic allowlist (`^[a-zA-Z_.-]+$`, kept by the converter); generic secrets under key names that do not end in a credential noun (`consumer_key`, `app_key`, `master_key`) are not reported (3 of 12 probes flagged, the `HMAC_KEY` ones).
- **Flat-named float arrays of an embedding width** (scipy's linprog benchmark data) score 70 (ask): 4 of the 5 OSS biometric false positives.
