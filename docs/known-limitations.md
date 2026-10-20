# Known limitations

RiskGrep scores files with rules and simple structural checks, not with a model of what the data means. This page lists what it does not detect, what it may flag wrongly, and why, so you can judge how much to rely on a score. Each entry says what is not covered, why, how it shows up, and whether a fix is planned. The measurements behind the detection entries are in [`eval/README.md`](../eval/README.md).

## Biometric embeddings

### Embedding banks are found by a name and structure heuristic

- **Not covered:** a bank of speaker or face vectors stored under hierarchical names (for example `model.speakers.0.vec`), or stored alongside more other float tensors than bank vectors. Conversely, a model checkpoint whose parameter names are flat and not on the exclusion lists can be mistaken for a bank.
- **Why:** a file is treated as a bank when 3 or more tensors (or `.npz` members) share one embedding shape, have flat names, and make up at least half of the file's float tensors. Model checkpoints are excluded by their parameter names (`weight`, `bias`, `kernel`, `scale`, `gamma`, `beta`, `time_mix`, `mixer`, and others) and by layer or index segments in their names. A naming scheme outside those lists is not recognised.
- **How it shows up:** a missed bank scores 25 to 30, or 70 when one tensor is flat-named; a checkpoint mistaken for a bank scores 94 (deny in Claude Code, blocked by the git hook).
- **Planned fix:** none decided. Possible approaches are reading the checkpoint's metadata or architecture fields, and extending the exclusion lists as new layouts are found.

### Unnamed tensors with parameter-like or hierarchical names are not treated as embeddings

- **Not covered:** a single embedding saved in safetensors or `.npz` under a name containing a parameter word (`kernel`, `scale`, `beta`, …) or a layer or index segment (`encoder.0.out`, `vec_1_a`).
- **Why:** the same name exclusions that keep model checkpoints out apply to the single-tensor rules.
- **How it shows up:** the file scores 25 (safetensors) or 30 (`.npz`) instead of 70; it is not flagged.
- **Planned fix:** none decided.

### Embedding widths outside the configured list

- **Not covered:** embeddings whose last dimension is not in `embedding_dims` (`128, 192, 256, 384, 512, 640, 768, 1024, 1536, 2048, 3072, 4096`), for example 100, 300, or 1000.
- **Why:** shape is the main signal for unnamed tensors and printed arrays; any width would match ordinary scientific data.
- **How it shows up:** such files score 30 (`.npy`, `.npz`), 25 (safetensors), or 40 (printed floats) and are not flagged. A safetensors tensor named like an embedding (`speaker_embedding`) is still flagged at any width.
- **Planned fix:** none decided; the list can be extended in the ruleset.

### Three or more leading dimensions

- **Not covered:** arrays shaped like `[2, 2, 2, d]`.
- **Why:** an embedding-shaped tensor may have at most two dimensions before the width (`[d]`, `[n, d]`, `[a, b, d]`).
- **How it shows up:** such a `.npy` scores 30 and is not flagged.
- **Planned fix:** none decided.

### Banks of two vectors

- **Not covered:** a file with exactly two identically shaped embedding tensors is not scored as a bank.
- **Why:** the bank rules need at least 3 tensors of one shape (`min_bank = 3`).
- **How it shows up:** the file scores 70 (ask) from the single-tensor rule instead of 94.
- **Planned fix:** none decided.

### Several embeddings of different shapes

- **Not covered:** a file holding embeddings of different widths (for example one 192-wide speaker vector and one 512-wide face vector per person) is not scored as a bank.
- **Why:** a bank is defined as tensors of one identical shape.
- **How it shows up:** the file scores 70 (ask), not 94.
- **Planned fix:** none decided.

### Flat-named float arrays of an embedding width are flagged

- **Not covered (false positive):** ordinary numeric arrays in `.npy` or `.npz` files whose last dimension happens to be an embedding width, such as benchmark or test data.
- **Why:** an unnamed array of an embedding width cannot be told apart from an embedding by its header.
- **How it shows up:** a score of 70 (ask in Claude Code; below the git hook's block threshold of 75). In the evaluation's 55,876 public-repository files, 4 such files were flagged.
- **Planned fix:** none decided.

## Secrets

### Generic secrets with letter-only values

- **Not covered:** a generic `name = "value"` credential whose value contains only letters, `_`, `.`, or `-`.
- **Why:** the generic rule is converted from gitleaks, whose allowlist drops values matching `^[a-zA-Z_.-]+$` as identifiers; the converter keeps it.
- **How it shows up:** no evidence is reported for that line.
- **Planned fix:** none decided.

### Generic secrets under other key names

- **Not covered:** generic credentials whose key name does not end in a credential noun or an uppercase `_KEY`, for example `consumer_key`, `app_key`, or `master_key`.
- **Why:** the generic rule only accepts key names ending in `secret`, `password`, `token`, `credential(s)`, `creds`, `auth`, an `…_key` form such as `api_key` or `access_key`, or an uppercase `[A-Z0-9_]+_KEY`; broader names flagged too many ordinary files.
- **How it shows up:** no evidence is reported; provider-specific rules still find credentials in a provider's own format.
- **Planned fix:** none decided.
