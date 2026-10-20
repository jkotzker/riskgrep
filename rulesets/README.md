# Rulesets

Each subdirectory with a `ruleset.toml` is a ruleset, embedded into the binary at build time. A ruleset holds `*.yar` YARA-X sources and optional `stopwords/<list>.txt` files (one word per line).

## Manifest (`ruleset.toml`)

`id` (a YARA identifier; it becomes the namespace, so rules are keyed `<id>:<rule>`), `version`, `licence`, `description`, `categories`.

## Rule metadata

Every rule needs these `meta:` keys:

| Key | Meaning |
|---|---|
| `category` | Score category the rule contributes to |
| `weight` | -100..=100; positive weights combine by noisy-or, negative weights dampen |
| `tiers` | Optional `"count:weight,..."` (ascending counts); replaces `weight` by match count |
| `family` | Optional group name; weights in a family combine first |
| `family_cap` | Optional 0..=100 ceiling for the family's combined weight |
| `post` | Optional comma-separated post-processors, applied in order |

Post-processors and their arguments:

| `post` | Arguments |
|---|---|
| `span` | `span_regex` (required), `secret_group` (capture group, default 0): narrows the match to the group |
| `entropy` | `min_entropy` (required): drops matches below the Shannon entropy |
| `stopwords` | `stopwords` (required): list name; drops matches containing a listed word |
| `allow_regex` | `allow_regex` (required): drops matches the regex accepts |
| `float_run` | `min_floats` (required): finds maximal runs of at least that many printed floats (separators: commas, whitespace, brackets) in one linear pass. It supplies the evidence ranges itself, so the rule's patterns (any name) are only a cheap trigger |
| `float_array` | `embedding_dims` (required): finds single bracketed arrays (`[...]`, also inside `array([...])` and JSON) holding only floats separated by commas or whitespace, whose element count is in `embedding_dims`; each innermost row of a nested array is judged on its own. Supplies its own evidence ranges, like `float_run` |
| `npy_header` | `min_dim` (required), `embedding_dims` (optional): `.npy` float array with a dimension >= `min_dim`; with `embedding_dims`, also embedding-shaped (below) |
| `npz_members` | `min_dim` (required), `embedding_dims` (optional): `.npz` with such a float member |
| `safetensors_header` | `min_dim` (required), `name_regex`, `embedding_dims`, `exclude_name_regex` (optional): float tensor with such a dimension and, if given, a name matching `name_regex`, an embedding shape, and a name not matching `exclude_name_regex` |

`embedding_dims` is a comma-separated list of widths, e.g. `"128,192,256,512"`. A tensor is embedding-shaped when its last dimension is in the list and at most two dimensions precede it (`[d]`, `[n, d]`, `[a, b, d]`).

## Anchors

Pattern identifiers starting with `$re`, `$hdr`, or `$hit` are evidence anchors: their matches become evidence locations and are refined by the post-processors. Other identifiers are helpers and produce no locations. A rule with no anchor (condition only, for example on the `path` external) yields one evidence item with count 1. Header rules anchor with `$hdr at 0` (or at the fixed header offset).

## Externals

`path` holds the path being scanned, for path heuristics (`path matches /.../i`).

Regexes are compiled without Unicode, so use `(?i)` for ASCII case folding; YARA-X regexes have no lookaround.

## Rule tests (`tests.toml`)

A ruleset directory may hold a `tests.toml`; `riskgrep rules test` runs it against the embedded rulesets. Each `[[case]]` generates a sample file, scans it with only that ruleset enabled, and checks the result:

| Key | Meaning |
|---|---|
| `rule` | Bare rule id the case is about (must exist in the ruleset) |
| `synth` | Generator spec for the sample's content (below) |
| `expect` | A score: the rule must fire and the rule's category must score that (to 0.1). `"none"`: the rule must not fire |
| `path` | Optional. Sample file name, relative to a scratch directory that is the working directory for the scan; this is the path that path rules see. Default `sample.txt` |

Samples are generated at run time from fixed seeds, so nothing sensitive is stored. Positive cases count towards the "rules have a passing positive case" figure that `rules test` prints; the secrets ruleset's generated gitleaks rules are covered only where a generator below can produce a matching sample.

### Generator specs

| Spec | Content |
|---|---|
| `secret:KIND[:SEED]` | `riskgrep_core::synth::fake_secret`, inside a few lines of source code (tokens as `let id = "...";`; block and whole-line kinds as they are). Seed default 7 |
| `npy:DTYPE:DIMS` | `.npy` file, e.g. `npy:<f4:10x192` |
| `npz:DTYPE:DIMS` | `.npz` holding one `.npy` member, e.g. `npz:<f4:4x256` |
| `safetensors:NAME=DTYPE@DIMS[;...]` | safetensors file, e.g. `safetensors:speaker_embedding=F32@1x192;other=F32@1x128` |
| `floats:N:STYLE` | N printed floats; style `python`, `numpy`, or `json` |
| `csv:ROWSxCOLS` | CSV of random floats |
| `der:HEX[:SEED]` | The hex bytes, then 300 random bytes (DER key and key-store headers) |
| `prices:N`, `log:N` | N lines of price-list CSV or log text with small decimals (hard negatives for float rules) |
| `text:LITERAL` | The literal text; `\n` and `\t` are escapes |
