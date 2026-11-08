// Credential-named keys with hex values: a companion to the converted
// `generic_api_key` in `gitleaks.yar`. Hand-written; the patterns are regexes
// so that no line of this file spells a complete match (the shipped rule
// sources are scanned by a test). Sources compile in file-name order, and this
// file sorts after `gitleaks.yar`, so it can use gitleaks' global path
// allowlist (`gitleaks_global_path_allowlist`) as `generic_api_key` does.
//
// The key names and separators of `generic_api_key` (as the converter rewrites
// them; `UPSTREAM.md`, "Local changes"), with a value of 32 to 128 hex digits
// at entropy 3.0 instead of 3.5: a random 32-character hex value falls below
// 3.5 about once in five and below 3.0 once in 9,468 (exact: all 16^32
// strings counted by digit counts), so without this rule `api_key: <hex>` was
// found about four times in five. The rule applies no stopword list, unlike
// `generic_api_key`: its words that are spelt with hex digits (`dead`, `feed`)
// occur by chance in a random hex value, 1 in 1,151 of 32 digits (measured on
// 3,000,000 values), and a placeholder such as `deadbeef` repeated is already
// below the entropy floor. In the same family as `generic_api_key`, so a value
// both find scores 80. A match is one line.
rule credential_key_hex_value {
  meta:
    category = "secret"
    weight = 80
    family = "credential_assignment"
    family_cap = 80
    line_complete = true
    post = "span,entropy,allow_regex"
    span_regex = "(?i)[\\w.-]{0,50}?(?:secret|passw(?:or)?d|token|credentials?|creds|auth|(?:api|access|private|secret|auth|client|encryption|signing)[_.-]?key|(?-i:[A-Z0-9_]+_KEY))[ \\t'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\" \\t=]{0,5}([0-9A-Fa-f]{32,128})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
    secret_group = 1
    min_entropy = 3.0
    allow_regex = "^<[\\w.:-]{0,40}(?i:public)|^<add[ \\t][^>]*(?i:key|name)[ \\t]*=[ \\t]*[\"'][\\w.:-]{0,40}(?i:public)|^\"[\\w.-]{0,40}(?i:public)|^\\n?[ ]{0,6}[\\w.-]{0,40}(?i:public)[\\w.-]*:|^[^0-9]+$|^[^A-Za-z]+$|^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$|^[A-Za-z0-9+/=_.-]*(?i:0123456|123456789|abcdef|fedcba)|^[A-Za-z0-9+/=_.-]*(?i:\\.(?:pem|key|crt|cer|p12|pfx|jks|keystore|txt|json|ya?ml|xml|conf|cfg|ini|der|asc|gpg|pub)$)|^/(?:bin|etc|home|opt|tmp|usr|var|run|srv|mnt|data|config|app|Users|private)/"
  strings:
    $re = /(?i)[\w.-]{0,50}(?:secret|passw(?:or)?d|token|credentials?|creds|auth|(?:api|access|private|secret|auth|client|encryption|signing)[_.-]?key|(?-i:[A-Z0-9_]+_KEY))[ \t'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'" \t=]{0,5}[0-9A-Fa-f]{32,128}(?:[\x60'"\s;]|\\[nr]|$)/
  condition:
    $re and
    not gitleaks_global_path_allowlist
}
