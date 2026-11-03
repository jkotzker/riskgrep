// Well-known key-file and credential-file names, judged by the path alone.
// They need no content, so the Claude Code hook can weigh a `Glob` that
// reveals them (and an MCP tool that lists directories) before anything is
// read. gitleaks' global path allowlist (node_modules, vendored code, lock
// files) applies, as it does to the other path rules.
//
// A name reveals no content, so the weights follow how often the name is a
// secret rather than a fixture or a template:
//   80  names that exist to hold a secret and are rarely anything else; at the
//       ask threshold of the Claude Code hook and the git block threshold
//   40  names that are a certificate or an unrelated file as often as a key;
//       reported, but below both thresholds
// The measurement on the public-repository corpus is in eval/README.md.
//
// The conditions use string operators (`iequals`, `iendswith`, `icontains`),
// not `path matches`: a regex in a condition is compiled by each scanner on
// its first use, and a scanner that handles one file (the git pre-commit
// hook) pays that for every file whatever the name, about 1M to 3M
// instructions per regex per file (measured in eval/README.md, round 9). A
// regex follows a string prefilter only where the string operators cannot
// express the name.

// OpenSSH private keys: the default file names, never the `.pub` half.
rule ssh_private_key_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    (
      path iequals "id_rsa" or path iendswith "/id_rsa" or
      path iequals "id_dsa" or path iendswith "/id_dsa" or
      path iequals "id_ecdsa" or path iendswith "/id_ecdsa" or
      path iequals "id_ecdsa_sk" or path iendswith "/id_ecdsa_sk" or
      path iequals "id_ed25519" or path iendswith "/id_ed25519" or
      path iequals "id_ed25519_sk" or path iendswith "/id_ed25519_sk"
    ) and
    not gitleaks_global_path_allowlist
}

// dotenv files that carry values: `.env`, and the local, production,
// development, and staging variants (including `.env.<name>.local`). Template
// names (`.env.example`, `.env.sample`) are not listed.
rule dotenv_file_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    (
      path iequals ".env" or path iendswith "/.env" or
      path iequals ".env.local" or path iendswith "/.env.local" or
      path iequals ".env.prod" or path iendswith "/.env.prod" or
      path iequals ".env.production" or path iendswith "/.env.production" or
      path iequals ".env.dev" or path iendswith "/.env.dev" or
      path iequals ".env.development" or path iendswith "/.env.development" or
      path iequals ".env.stage" or path iendswith "/.env.stage" or
      path iequals ".env.staging" or path iendswith "/.env.staging" or
      path iequals ".env.secret" or path iendswith "/.env.secret" or
      path iequals ".env.secrets" or path iendswith "/.env.secrets" or
      (
        (path istartswith ".env." or path icontains "/.env.") and
        path iendswith ".local" and
        path matches /(?i)(?:^|\/)\.env\.[a-z]+\.local$/
      )
    ) and
    not gitleaks_global_path_allowlist
}

// AWS shared credentials file. The family keeps it and the bare-name rule
// below from adding up.
rule aws_credentials_file_name {
  meta:
    category = "secret"
    weight = 80
    family = "credentials_file_name"
    family_cap = 80
  condition:
    (path iequals ".aws/credentials" or path iendswith "/.aws/credentials") and
    not gitleaks_global_path_allowlist
}

// A file named exactly `credentials`: Rails, Terraform, and others use the
// name for files that hold no secret.
rule credentials_file_name {
  meta:
    category = "secret"
    weight = 40
    family = "credentials_file_name"
    family_cap = 80
  condition:
    (path iequals "credentials" or path iendswith "/credentials") and
    not gitleaks_global_path_allowlist
}

// Files whose purpose is to hold credentials for a tool: curl and ftp
// (`.netrc`, `_netrc` on Windows), PostgreSQL (`.pgpass`), git
// (`.git-credentials`), and Apache and nginx basic authentication
// (`.htpasswd`).
rule credential_store_file_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    (
      path iequals ".netrc" or path iendswith "/.netrc" or
      path iequals "_netrc" or path iendswith "/_netrc" or
      path iequals ".pgpass" or path iendswith "/.pgpass" or
      path iequals ".git-credentials" or path iendswith "/.git-credentials" or
      path iequals ".htpasswd" or path iendswith "/.htpasswd"
    ) and
    not gitleaks_global_path_allowlist
}

// Java key stores. The content is binary, so a file scan skips most of them;
// the name is what a `Glob` sees.
rule java_keystore_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    (path iendswith ".jks" or path iendswith ".keystore") and
    not gitleaks_global_path_allowlist
}

// PuTTY private keys.
rule putty_private_key_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    path iendswith ".ppk" and
    not gitleaks_global_path_allowlist
}

// GnuPG secret keys: the legacy secret keyring and the key files of the
// gpg-agent store.
rule gpg_secret_key_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    (
      path iequals "secring.gpg" or path iendswith "/secring.gpg" or
      path iequals "secring.pgp" or path iendswith "/secring.pgp" or
      path icontains "/private-keys-v1.d/"
    ) and
    not gitleaks_global_path_allowlist
}

// PEM files hold certificates and public keys as often as private keys (a
// private key in PEM form is found by the content rule `private_key`).
rule pem_file_name {
  meta:
    category = "secret"
    weight = 40
  condition:
    path iendswith ".pem" and
    not gitleaks_global_path_allowlist
}
