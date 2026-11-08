// Credentials in configuration files, recognised by the name of the XML
// element, JSON object, or YAML mapping that holds them. Hand-written; the
// patterns are regexes so that no line of this file spells a complete match
// (the shipped rule sources are scanned by a test).
//
// The names are qualified credential words, so that names which hold public
// or non-secret values do not match: `ApiKey`, `EncryptionKey`, and
// `AccessToken` match, `PublicKey`, `PrimaryKey`, a bare `Key` (S3 listings,
// property lists), and `NextToken` (pagination) do not. A name containing
// `public` within its first 40 characters (`PublicSigningKey`,
// `publicEncryptionKeys`) matches nothing: `allow_regex` runs twice, once on
// the whole anchor match before `span` (where its name alternatives, anchored
// at the `<`, `"`, or line start that begins every anchor, drop public names)
// and once on each value after it. The name alternatives cannot match a
// value (they need a `<`, `"`, or `:`, which values never contain), and every
// other alternative is anchored to value characters from the start, so it
// cannot match an anchor's whole match.
//
// A value is a run of 16 to 200 token characters (letters, digits, and
// `+/=_.-`), so templates (`${VAR}`, `{{ var }}`), prose, and short values do
// not match. The post-processors then keep a value only when it has Shannon
// entropy of at least 3.0 (a random 32-character hex value falls below 3.0
// once in 9,468 draws, exact, and below 3.5, `generic_api_key`'s minimum,
// about once in 5), contains no word of `generic_api_key`'s stopword list
// unless the value is made only of hex digits (`stopwords_skip_hex`: `dead`
// and `feed` occur by chance in 1 of 1,151 random 32-digit hex values, while
// a placeholder such as `deadbeef` repeated is below the entropy floor), has
// both a digit and a letter, is not a UUID (key ids and subjects under a
// `Credentials` object are UUIDs), contains no ascending or descending run
// (`0123456`, `abcdef`), and is not a file path.
//
// Weight 80, the same as `generic_api_key`: the evidence is the same kind (a
// credential-named key with a high-entropy literal), and 80 is the secret
// flag threshold (`git.block_at`, `claude_code.ask`). Every rule here is in
// family `credential_assignment` with cap 80, shared with `generic_api_key`
// (the converter's `FAMILIES`), so a value two of them find (`token:` inside
// `credentials:`) scores 80, not the noisy-or 96, which would pass the
// `claude_code` deny threshold of 95.

// ---- XML ---------------------------------------------------------------------
// `<ApiKey>…</ApiKey>`, the layout of Sonarr, Radarr, and the other *arr apps'
// `config.xml`. A match is one line (no part of the pattern matches a line
// feed), and the location is the value alone.
rule xml_credential_element {
  meta:
    category = "secret"
    weight = 80
    family = "credential_assignment"
    family_cap = 80
    line_complete = true
    post = "allow_regex,span,entropy,stopwords,allow_regex"
    span_regex = "(?i)<(?:[\\w.:-]{0,40}(?:api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?key|[\\w.:-]{0,40}(?:access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?token|token|[\\w.:-]{0,40}(?:secret|passw(?:or)?d|passphrase|pwd|psk|credentials?))>[ \\t]*([A-Za-z0-9+/=_.-]{16,200})[ \\t]*</[\\w.:-]{1,80}>"
    secret_group = 1
    min_entropy = 3.0
    stopwords = "secrets_core_generic_api_key"
    stopwords_skip_hex = true
    allow_regex = "^<[\\w.:-]{0,40}(?i:public)|^<add[ \\t][^>]*(?i:key|name)[ \\t]*=[ \\t]*[\"'][\\w.:-]{0,40}(?i:public)|^\"[\\w.-]{0,40}(?i:public)|^\\n?[ ]{0,6}[\\w.-]{0,40}(?i:public)[\\w.-]*:|^[^0-9]+$|^[^A-Za-z]+$|^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$|^[A-Za-z0-9+/=_.-]*(?i:0123456|123456789|abcdef|fedcba)|^[A-Za-z0-9+/=_.-]*(?i:\\.(?:pem|key|crt|cer|p12|pfx|jks|keystore|txt|json|ya?ml|xml|conf|cfg|ini|der|asc|gpg|pub)$)|^/(?:bin|etc|home|opt|tmp|usr|var|run|srv|mnt|data|config|app|Users|private)/"
  strings:
    $re = /<([\w.:-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?key|[\w.:-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?token|token|[\w.:-]{0,40}(secret|passw(or)?d|passphrase|pwd|psk|credentials?))>[ \t]*[A-Za-z0-9+\/=_.-]{16,200}[ \t]*<\/[\w.:-]{1,80}>/ nocase
  condition:
    $re
}

// `<add key="ApiKey" value="…" />`, the .NET `appSettings` layout (`name` in
// place of `key` as `connectionStrings` spells it), with the two attributes in
// either order and adjacent. The same names, exclusions, and value filter as
// `xml_credential_element`; a connection string's embedded `Password=` is a
// different layout and is not read. A match is one line, and the location is
// the value alone.
rule xml_add_key_value {
  meta:
    category = "secret"
    weight = 80
    family = "credential_assignment"
    family_cap = 80
    line_complete = true
    post = "allow_regex,span,entropy,stopwords,allow_regex"
    span_regex = "(?i)<add[ \\t]+(?:key|name)[ \\t]*=[ \\t]*[\"'](?:[\\w.:-]{0,40}(?:api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?key|[\\w.:-]{0,40}(?:access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?token|token|[\\w.:-]{0,40}(?:secret|passw(?:or)?d|passphrase|pwd|psk|credentials?))[\"'][ \\t]+value[ \\t]*=[ \\t]*[\"']([A-Za-z0-9+/=_.-]{16,200})[\"']|<add[ \\t]+value[ \\t]*=[ \\t]*[\"']([A-Za-z0-9+/=_.-]{16,200})[\"'][ \\t]+(?:key|name)[ \\t]*=[ \\t]*[\"'](?:[\\w.:-]{0,40}(?:api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?key|[\\w.:-]{0,40}(?:access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?token|token|[\\w.:-]{0,40}(?:secret|passw(?:or)?d|passphrase|pwd|psk|credentials?))[\"']"
    secret_group = "first_nonempty"
    min_entropy = 3.0
    stopwords = "secrets_core_generic_api_key"
    stopwords_skip_hex = true
    allow_regex = "^<[\\w.:-]{0,40}(?i:public)|^<add[ \\t][^>]*(?i:key|name)[ \\t]*=[ \\t]*[\"'][\\w.:-]{0,40}(?i:public)|^\"[\\w.-]{0,40}(?i:public)|^\\n?[ ]{0,6}[\\w.-]{0,40}(?i:public)[\\w.-]*:|^[^0-9]+$|^[^A-Za-z]+$|^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$|^[A-Za-z0-9+/=_.-]*(?i:0123456|123456789|abcdef|fedcba)|^[A-Za-z0-9+/=_.-]*(?i:\\.(?:pem|key|crt|cer|p12|pfx|jks|keystore|txt|json|ya?ml|xml|conf|cfg|ini|der|asc|gpg|pub)$)|^/(?:bin|etc|home|opt|tmp|usr|var|run|srv|mnt|data|config|app|Users|private)/"
  strings:
    $re = /<add[ \t]+(key|name)[ \t]*=[ \t]*["']([\w.:-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?key|[\w.:-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?token|token|[\w.:-]{0,40}(secret|passw(or)?d|passphrase|pwd|psk|credentials?))["'][ \t]+value[ \t]*=[ \t]*["'][A-Za-z0-9+\/=_.-]{16,200}["']/ nocase
    $rev = /<add[ \t]+value[ \t]*=[ \t]*["'][A-Za-z0-9+\/=_.-]{16,200}["'][ \t]+(key|name)[ \t]*=[ \t]*["']([\w.:-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?key|[\w.:-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?token|token|[\w.:-]{0,40}(secret|passw(or)?d|passphrase|pwd|psk|credentials?))["']/ nocase
  condition:
    any of ($re*)
}

// ---- JSON --------------------------------------------------------------------
// A string member of an object whose name is a credential word, whatever the
// member is called: `{"securityKeys": {"S2_Unauthenticated": "…"}}`, the
// layout Z-Wave JS UI uses for a Z-Wave network's keys. The anchor runs from
// the object's name to the last such member before a brace, and `span` yields
// every member value inside it, each filtered on its own. Members of nested
// objects do not count. Not line_complete: a match spans lines.
rule json_credential_object_member {
  meta:
    category = "secret"
    weight = 80
    family = "credential_assignment"
    family_cap = 80
    post = "allow_regex,span,entropy,stopwords,allow_regex"
    span_regex = "\"[^\"\\r\\n]{1,64}\"[ \\t\\r\\n]*:[ \\t\\r\\n]*\"([A-Za-z0-9+/=_.-]{16,200})\""
    secret_group = 1
    min_entropy = 3.0
    stopwords = "secrets_core_generic_api_key"
    stopwords_skip_hex = true
    allow_regex = "^<[\\w.:-]{0,40}(?i:public)|^<add[ \\t][^>]*(?i:key|name)[ \\t]*=[ \\t]*[\"'][\\w.:-]{0,40}(?i:public)|^\"[\\w.-]{0,40}(?i:public)|^\\n?[ ]{0,6}[\\w.-]{0,40}(?i:public)[\\w.-]*:|^[^0-9]+$|^[^A-Za-z]+$|^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$|^[A-Za-z0-9+/=_.-]*(?i:0123456|123456789|abcdef|fedcba)|^[A-Za-z0-9+/=_.-]*(?i:\\.(?:pem|key|crt|cer|p12|pfx|jks|keystore|txt|json|ya?ml|xml|conf|cfg|ini|der|asc|gpg|pub)$)|^/(?:bin|etc|home|opt|tmp|usr|var|run|srv|mnt|data|config|app|Users|private)/"
  strings:
    $re = /"([\w.-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?keys|[\w.-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?tokens|[\w.-]{0,40}(secrets?|credentials?|creds|passwords|passphrases))"[ \t\r\n]*:[ \t\r\n]*\{[^{}]{0,2000}"[^"\r\n]{1,64}"[ \t\r\n]*:[ \t\r\n]*"[A-Za-z0-9+\/=_.-]{16,200}"/ nocase
  condition:
    $re
}

// ---- YAML --------------------------------------------------------------------
// The same in YAML: a plain or quoted scalar (optionally followed by a
// comment) on a line below a mapping key that is a credential word and
// indented deeper than it (`securityKeys:` then `  S2_Unauthenticated: …`),
// also as a list item's member. One anchor per indentation of the mapping key
// (0, 2, 4, or 6 spaces; YAML indents with spaces only), so the block ends at
// the first non-blank line that is not indented deeper; a key indented
// otherwise is not matched. As in the JSON rule, `span` yields every member
// value inside the anchor, each filtered on its own. Not line_complete: a
// match spans lines.
rule yaml_credential_mapping_member {
  meta:
    category = "secret"
    weight = 80
    family = "credential_assignment"
    family_cap = 80
    post = "allow_regex,span,entropy,stopwords,allow_regex"
    span_regex = "(?m)^[ ]+(?:- )?[\\w.-]{1,64}:[ \\t]+['\"]?([A-Za-z0-9+/=_.-]{16,200})['\"]?[ \\t]*(?:#[^\\r\\n]*)?\\r?$"
    secret_group = 1
    min_entropy = 3.0
    stopwords = "secrets_core_generic_api_key"
    stopwords_skip_hex = true
    allow_regex = "^<[\\w.:-]{0,40}(?i:public)|^<add[ \\t][^>]*(?i:key|name)[ \\t]*=[ \\t]*[\"'][\\w.:-]{0,40}(?i:public)|^\"[\\w.-]{0,40}(?i:public)|^\\n?[ ]{0,6}[\\w.-]{0,40}(?i:public)[\\w.-]*:|^[^0-9]+$|^[^A-Za-z]+$|^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$|^[A-Za-z0-9+/=_.-]*(?i:0123456|123456789|abcdef|fedcba)|^[A-Za-z0-9+/=_.-]*(?i:\\.(?:pem|key|crt|cer|p12|pfx|jks|keystore|txt|json|ya?ml|xml|conf|cfg|ini|der|asc|gpg|pub)$)|^/(?:bin|etc|home|opt|tmp|usr|var|run|srv|mnt|data|config|app|Users|private)/"
  strings:
    $re0 = /(^|\n)([\w.-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?keys|[\w.-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?tokens|[\w.-]{0,40}(secrets?|credentials?|creds|passwords|passphrases)):[ \t]*(#[^\r\n]*)?\r?\n(([ ]+[^\r\n]*)?\r?\n){0,30}[ ]+(- )?[\w.-]{1,64}:[ \t]+['"]?[A-Za-z0-9+\/=_.-]{16,200}['"]?[ \t]*(#[^\r\n]*)?(\r?\n|$)/ nocase
    $re2 = /\n  ([\w.-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?keys|[\w.-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?tokens|[\w.-]{0,40}(secrets?|credentials?|creds|passwords|passphrases)):[ \t]*(#[^\r\n]*)?\r?\n(([ ]{3,}[^\r\n]*)?\r?\n){0,30}[ ]{3,}(- )?[\w.-]{1,64}:[ \t]+['"]?[A-Za-z0-9+\/=_.-]{16,200}['"]?[ \t]*(#[^\r\n]*)?(\r?\n|$)/ nocase
    $re4 = /\n    ([\w.-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?keys|[\w.-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?tokens|[\w.-]{0,40}(secrets?|credentials?|creds|passwords|passphrases)):[ \t]*(#[^\r\n]*)?\r?\n(([ ]{5,}[^\r\n]*)?\r?\n){0,30}[ ]{5,}(- )?[\w.-]{1,64}:[ \t]+['"]?[A-Za-z0-9+\/=_.-]{16,200}['"]?[ \t]*(#[^\r\n]*)?(\r?\n|$)/ nocase
    $re6 = /\n      ([\w.-]{0,40}(api|access|secret|private|auth|client|encryption|decryption|signing|master|network|security|session|app|application|account|admin|shared|license|hmac|aes|psk)[_.-]?keys|[\w.-]{0,40}(access|api|auth|bearer|refresh|session|bot|app|user|personal|private|secret|security|oauth)[_.-]?tokens|[\w.-]{0,40}(secrets?|credentials?|creds|passwords|passphrases)):[ \t]*(#[^\r\n]*)?\r?\n(([ ]{7,}[^\r\n]*)?\r?\n){0,30}[ ]{7,}(- )?[\w.-]{1,64}:[ \t]+['"]?[A-Za-z0-9+\/=_.-]{16,200}['"]?[ \t]*(#[^\r\n]*)?(\r?\n|$)/ nocase
  condition:
    any of ($re*)
}
