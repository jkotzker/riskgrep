// Key-store files, recognised by extension and a DER header, so these binary
// files are scored rather than skipped. PEM private keys are covered by
// gitleaks' `private_key`.

// PKCS #12 (.p12, .pfx). gitleaks' `pkcs12_file` also fires on the name; the
// shared family keeps the pair at this rule's weight.
rule pkcs12_keystore {
  meta:
    category = "secret"
    weight = 90
    family = "pkcs12"
    family_cap = 90
  strings:
    $hdr = { 30 82 }
  condition:
    $hdr at 0 and path matches /\.p(12|fx)$/i
}

// DER-encoded private keys (.der, .key): a SEQUENCE whose first element is
// the version INTEGER, 0 for PKCS#1 and PKCS#8, 1 for SEC1 EC keys. An X.509
// certificate starts SEQUENCE, SEQUENCE and does not match.
rule der_key_file {
  meta:
    category = "secret"
    weight = 90
  strings:
    $hdr = { 30 ( 82 ?? ?? 02 01 00 | 77 02 01 01 | 81 ?? 02 01 01 ) }
  condition:
    $hdr at 0 and path matches /\.(der|key)$/i
}
