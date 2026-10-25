// Encrypted password-vault and keychain files, recognised by magic bytes (or
// bundle file names) so the binary files are scored rather than skipped. The
// contents are encrypted, so the weight is in the ask band, below the deny
// threshold: a whole vault leaving the machine can still be attacked offline.
// 1Password `.1pux` exports and its SQLite database are not covered here
// (zip and SQLite files are not read).

// KeePass: signature 9AA2D903, then B54BFB67 (KDBX 2.x to 4.x) or B54BFB65
// (KDB 1.x).
rule keepass_database {
  meta:
    category = "secret"
    weight = 85
  strings:
    $hdr = { 03 D9 A2 9A ( 65 | 67 ) FB 4B B5 }
  condition:
    $hdr at 0
}

// macOS keychain file (`.keychain`, `.keychain-db`): "kych", version 0x00010000.
rule macos_keychain_file {
  meta:
    category = "secret"
    weight = 85
  strings:
    $hdr = { 6B 79 63 68 00 01 00 00 }
  condition:
    $hdr at 0
}

// Password Safe v3 database: "PWS3" and the `.psafe3` extension.
rule password_safe_database {
  meta:
    category = "secret"
    weight = 85
  strings:
    $hdr = { 50 57 53 33 }
  condition:
    $hdr at 0 and path matches /\.psafe3$/i
}

// 1Password OPVault bundle (a directory named `*.opvault`): the profile,
// folder, and encrypted item band files.
rule opvault_bundle_file {
  meta:
    category = "secret"
    weight = 85
  condition:
    path matches /\.opvault\/default\/(profile|folders|band_[0-9A-F])\.js$/i
}
