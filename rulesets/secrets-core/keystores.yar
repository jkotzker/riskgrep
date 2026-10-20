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

// DER-encoded private keys (.der, .key): a SEQUENCE (with a one-byte, `81`,
// or `82` length) whose first element is the version INTEGER, followed by
//   PKCS#1 RSA (and DSA) keys:          02 01 00 02  (version 0, an INTEGER)
//   PKCS#8 PrivateKeyInfo:              02 01 00 30  (version 0, AlgorithmIdentifier)
//   RFC 5958 OneAsymmetricKey v2:       02 01 01 30  (version 1, AlgorithmIdentifier)
//   SEC1 ECPrivateKey (any curve):      02 01 01 04  (version 1, OCTET STRING)
// X.509 certificates, certificate requests, public keys, and signatures start
// SEQUENCE, SEQUENCE or SEQUENCE, INTEGER of another length, and do not match.
rule der_key_file {
  meta:
    category = "secret"
    weight = 90
  strings:
    $hdr = { 30 ( 0? | 1? | 2? | 3? | 4? | 5? | 6? | 7? | 81 ?? | 82 ?? ?? ) 02 01 ( 00 ( 02 | 30 ) | 01 ( 04 | 30 ) ) }
  condition:
    $hdr at 0 and path matches /\.(der|key)$/i
}
