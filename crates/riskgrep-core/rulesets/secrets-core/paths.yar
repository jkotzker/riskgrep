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

// OpenSSH private keys: the default file names, never the `.pub` half.
rule ssh_private_key_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    path matches /(?i)(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?$/ and
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
    path matches /(?i)(?:^|\/)\.env(?:\.(?:local|prod(?:uction)?|dev(?:elopment)?|stag(?:e|ing)|secrets?)|\.[a-z]+\.local)?$/ and
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
    path matches /(?i)(?:^|\/)\.aws\/credentials$/ and
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
    path matches /(?i)(?:^|\/)credentials$/ and
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
    path matches /(?i)(?:^|\/)(?:[._]netrc|\.pgpass|\.git-credentials|\.htpasswd)$/ and
    not gitleaks_global_path_allowlist
}

// Java key stores. The content is binary, so a file scan skips most of them;
// the name is what a `Glob` sees.
rule java_keystore_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    path matches /(?i)\.(?:jks|keystore)$/ and
    not gitleaks_global_path_allowlist
}

// PuTTY private keys.
rule putty_private_key_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    path matches /(?i)\.ppk$/ and
    not gitleaks_global_path_allowlist
}

// GnuPG secret keys: the legacy secret keyring and the key files of the
// gpg-agent store.
rule gpg_secret_key_name {
  meta:
    category = "secret"
    weight = 80
  condition:
    path matches /(?i)(?:^|\/)secring\.(?:gpg|pgp)$|\/private-keys-v1\.d\/[^\/]+$/ and
    not gitleaks_global_path_allowlist
}

// PEM files hold certificates and public keys as often as private keys (a
// private key in PEM form is found by the content rule `private_key`).
rule pem_file_name {
  meta:
    category = "secret"
    weight = 40
  condition:
    path matches /(?i)\.pem$/ and
    not gitleaks_global_path_allowlist
}
