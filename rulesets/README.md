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
| `npy_header` | `min_dim` (required): `.npy` float array with a dimension >= `min_dim` |
| `npz_members` | `min_dim` (required): `.npz` with such a float member |
| `safetensors_header` | `min_dim` (required), `name_regex` (optional): float tensor with such a dimension and, if given, a matching name |

## Anchors

Pattern identifiers starting with `$re`, `$hdr`, or `$hit` are evidence anchors: their matches become evidence locations and are refined by the post-processors. Other identifiers are helpers and produce no locations. A rule with no anchor (condition only, for example on the `path` external) yields one evidence item with count 1. Header rules anchor with `$hdr at 0` (or at the fixed header offset).

## Externals

`path` holds the path being scanned, for path heuristics (`path matches /.../i`).

Regexes are compiled without Unicode, so use `(?i)` for ASCII case folding; YARA-X regexes have no lookaround.
