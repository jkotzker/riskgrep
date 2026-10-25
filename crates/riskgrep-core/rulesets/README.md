# Rulesets

Each subdirectory with a `ruleset.toml` is a ruleset, embedded into the binary at build time. A ruleset holds `*.yar` YARA-X sources and optional `stopwords/<list>.txt` files (one word per line).

## Manifest (`ruleset.toml`)

`id` (a YARA identifier; it becomes the namespace, so rules are keyed `<id>:<rule>`), `version`, `licence`, `description`, `categories`.

The compiled-rules cache and the evidence cache are keyed by each enabled ruleset's id and its `ruleset.toml`, `*.yar`, and `stopwords/*.txt` files (with the YARA-X and riskgrep versions and the platform); other files in a ruleset directory do not invalidate them.

Stopword lists are merged by name across the selected rulesets. Two rulesets that ship a list with the same name and different words fail the bundle compile (`stopword list ... differs between rulesets`), so give lists a ruleset-specific name (`secrets_core_*` in `secrets-core`).

## Rule metadata

Every rule needs these `meta:` keys:

| Key | Meaning |
|---|---|
| `category` | Score category the rule contributes to |
| `weight` | -100..=100; positive weights combine by noisy-or, negative weights dampen |
| `tiers` | Optional `"count:weight,..."` (ascending counts); replaces `weight` by match count, so a `weight_overrides` entry for a tiered rule has no effect |
| `family` | Optional group name; weights in a family combine first |
| `family_cap` | Optional 0..=100 ceiling for the family's combined weight. Give every rule of a family the same cap: when the rules that fired carry different caps, the cap of the last of them in evidence order applies (a rule without a cap leaves the family's cap unchanged) |
| `post` | Optional comma-separated post-processors, applied in order |

Keys not listed here and in the post-processor table below are ignored without a warning, so a misspelt optional key (`min_entorpy`) silently leaves the default in place; a misspelt required key fails the load.

Post-processors and their arguments:

| `post` | Arguments |
|---|---|
| `span` | `span_regex` (required), `secret_group` (a capture group index, default 0 for the whole match, or `"first_nonempty"`: the first group that took part in the match and is non-empty, else the whole match, as gitleaks does without `secretGroup`): narrows the match to that part |
| `entropy` | `min_entropy` (required): drops matches below the Shannon entropy |
| `stopwords` | `stopwords` (required): list name; drops matches containing a listed word |
| `allow_regex` | `allow_regex` (required): drops matches the regex accepts |
| `float_run` | `min_floats` (required): finds maximal runs of at least that many printed floats (separators: commas, whitespace, brackets) in one linear pass. It supplies the evidence ranges itself, so the rule's patterns (any name) are only a cheap trigger |
| `float_array` | `embedding_dims` (required): finds single bracketed arrays (`[...]`, also inside `array([...])` and JSON) holding only floats separated by commas or whitespace, whose element count is in `embedding_dims`; each innermost row of a nested array is judged on its own. Supplies its own evidence ranges, like `float_run` |
| `npy_header` | `min_dim` (required), `embedding_dims` (optional): `.npy` float array with a dimension >= `min_dim`; with `embedding_dims`, also embedding-shaped (below) |
| `npz_members` | `min_dim` (required), `embedding_dims`, `exclude_name_regex`, `min_bank`, `min_bank_share` (optional): `.npz` with such a float member and, if given, an embedding shape and a member name (without `.npy`) not matching `exclude_name_regex`; with `min_bank`, at least that many qualifying members of one identical shape (an embedding bank) |
| `safetensors_header` | `min_dim` (required), `name_regex`, `embedding_dims`, `exclude_name_regex`, `min_bank`, `min_bank_share` (optional): float tensor with such a dimension and, if given, a name matching `name_regex`, an embedding shape, and a name not matching `exclude_name_regex`; with `min_bank`, at least that many such tensors of one identical shape |

`min_bank` is at least 2. `min_bank_share` (a percentage, 1 to 99, only with `min_bank`) also requires the bank to make up more than that share of the file's float tensors (`.npz`: float members), counting excluded and differently shaped ones.

`embedding_dims` is a comma-separated list of widths, e.g. `"128,192,256,512"`. A tensor is embedding-shaped when its last dimension is in the list and at most two dimensions precede it (`[d]`, `[n, d]`, `[a, b, d]`).

## Anchors

Pattern identifiers starting with `$re`, `$hdr`, or `$hit` are evidence anchors: their matches become evidence locations and are refined by the post-processors. Other identifiers are helpers and produce no locations. A rule with no anchor (condition only, for example on the `path` external) yields one evidence item with count 1. Header rules anchor with `$hdr at 0` (or at the fixed header offset).

## Externals

`path` holds the path being scanned, for path heuristics (`path matches /.../i`).

Header conditions that read integers (`uint32(0)`, `uint32(4)`) must guard against short files and unrelated data themselves: the safetensors rules check `uint32(4) == 0` (a header length below 2^32), `uint32(0) > 1`, and `uint32(0) + 8 <= filesize` before the post-processor parses the header.

Regexes are compiled without Unicode, so use `(?i)` for ASCII case folding; YARA-X regexes have no lookaround.

UTF-16 and UTF-32 text reaches the rules transcoded to UTF-8, without its byte-order mark, so text patterns need no `wide` modifier, and `filesize` and offsets in conditions refer to the transcoded text. Evidence locations are moved back to byte offsets in the file after the scan.

## Rule tests (`tests.toml`)

A ruleset directory may hold a `tests.toml`; `riskgrep rules test` runs it against the embedded rulesets. Each `[[case]]` generates a sample file, scans it with only that ruleset enabled, and checks the result:

| Key | Meaning |
|---|---|
| `rule` | Bare rule id the case is about (must exist in the ruleset) |
| `synth` | Generator spec for the sample's content (below) |
| `expect` | A score: the rule must fire and the rule's category must score that (to 0.1). `"none"`: the rule must not fire |
| `path` | Optional. Sample file name, relative to a scratch directory that is the working directory for the scan; this is the path that path rules see. Default `sample.txt` |

Samples are generated at run time from fixed seeds, so nothing sensitive is stored. A sample also passes through file classification, so a case whose content classification skips (an unknown binary) has no evidence at all: a `"none"` case passes vacuously for any rule, and a positive case fails. Check that a negative case's content is scanned (for example with `riskgrep scan --format json`, status `scanned`) before relying on it. Positive cases count towards the "rules have a passing positive case" figure that `rules test` prints; the secrets ruleset's generated gitleaks rules are covered only where a generator below can produce a matching sample.

### Generator specs

| Spec | Content |
|---|---|
| `secret:KIND[:SEED]` | `riskgrep_core::synth::fake_secret`, inside a few lines of source code (tokens as `let id = "...";`; block and whole-line kinds as they are). Seed default 7 |
| `keyed:NAME[:SEED]` | `NAME = "<value>"` on one line, with a random 32-character base62 value (the value of `secret:generic_api_key_assignment`); for key-name cases of the generic rule. Seed default 7 |
| `npy:DTYPE:DIMS` | `.npy` file, e.g. `npy:<f4:10x192` |
| `npz:DTYPE:DIMS` | `.npz` holding one `.npy` member, e.g. `npz:<f4:4x256` |
| `safetensors:NAME=DTYPE@DIMS[;...]` | safetensors file, e.g. `safetensors:speaker_embedding=F32@1x192;other=F32@1x128` |
| `floats:N:STYLE` | N printed floats; style `python`, `numpy`, or `json` |
| `csv:ROWSxCOLS` | CSV of random floats |
| `der:HEX[:SEED]` | The hex bytes, then 300 random bytes (DER key and key-store headers) |
| `prices:N`, `log:N` | N lines of price-list CSV or log text with small decimals (hard negatives for float rules) |
| `file:KIND[:SEED]` | Whole-file text from `riskgrep_core::synth::credential_file`: one-time-password URIs, password-manager exports, and two-factor recovery codes, each with a hard-negative variant (kinds in `synth::CREDENTIAL_FILE_KINDS`) |
| `text:LITERAL` | The literal text; `\n` and `\t` are escapes |
