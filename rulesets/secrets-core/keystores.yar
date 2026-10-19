// Key-store files, recognised by extension and a DER header (an ASN.1
// SEQUENCE with a two-byte length, `30 82`), so these binary files are scored
// rather than skipped. The classifier hands such files to the engine as known
// binaries. PEM private keys are covered by gitleaks' `private_key`.

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

// DER-encoded private keys (.der, .key).
rule der_key_file {
  meta:
    category = "secret"
    weight = 90
  strings:
    $hdr = { 30 82 }
  condition:
    $hdr at 0 and path matches /\.(der|key)$/i
}
