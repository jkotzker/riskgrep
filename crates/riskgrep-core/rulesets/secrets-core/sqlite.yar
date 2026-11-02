// A database whose schema names a credential column: `password_value`,
// `api_key`, `client_secret`, and similar. Hand-written; the name is a regex so
// that no line of this file spells a complete match (the shipped rule sources
// are scanned by a test).
//
// A weak signal: the name says what a column is for, not that it holds a
// secret, and a password column is often a hash or ciphertext. So weight 20, far
// below the flag threshold of 80 whatever the number of such names, enough only
// to lift a finding in the same database a little (80 becomes 84). The rule looks
// only at the region a database's `CREATE` statements are scanned under, so the
// same statement in an ordinary `.sql` file does not fire it. A bare `token` is
// left out: it names search tokens and pagination cursors as often as credentials.

rule sqlite_credential_column {
  meta:
    category = "secret"
    weight = 20
  strings:
    $re = /[\w$]{0,40}(passw(or)?d|passphrase|pwd|secret|api_?key|private_?key|(access|auth|refresh|session)_?token|credential)[\w$]{0,40}/ nocase
  condition:
    path endswith "!/sqlite_schema/sql" and $re
}
