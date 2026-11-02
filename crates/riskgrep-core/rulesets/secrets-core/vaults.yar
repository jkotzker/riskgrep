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

// Password Safe v3 database: "PWS3" and either the `.psafe3` extension or
// the layout of the specification (TAG, a 32-byte SALT, then ITER as a 32-bit
// little-endian integer; the specification gives 2,048 as the original
// minimum):
//   https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
// Four letters alone are too common a prefix. The upper bound (2^28) keeps a
// text file that starts with the letters out: four printable characters read
// as an integer above it, and the salt must hold a byte that is not
// printable text. The classifier adds the size check for a file
// without the extension (200 bytes plus whole 16-byte blocks: the fixed
// fields, the EOF block, and the HMAC).
rule password_safe_database {
  meta:
    category = "secret"
    weight = 85
  strings:
    $hdr = { 50 57 53 33 }
  condition:
    $hdr at 0 and (path matches /\.psafe3$/i or (filesize >= 40 and uint32(36) >= 2048 and uint32(36) < 0x10000000 and
        for any i in (4..35) : (uint8(i) < 0x09 or uint8(i) >= 0x80)))
}

// KeePass XML key file (`.keyx`, and `.key` or any name): the root element
// KeyFile, Meta with a Version (1.00, or 2.0 with a Hash on Data), then Key
// and Data. KeePassXC writes and reads the same layout (FileKey.cpp). The key
// is the second factor of a database that uses a key file, so the weight
// matches the database rule.
rule keepass_xml_key_file {
  meta:
    category = "secret"
    weight = 85
  strings:
    $hdr = /<KeyFile>[ \t\r\n]*<Meta>[ \t\r\n]*<Version>[ \t\r\n]*[12]\.[0-9]+[ \t\r\n]*<\/Version>[ \t\r\n]*<\/Meta>[ \t\r\n]*<Key>[ \t\r\n]*<Data[ >]/
  condition:
    $hdr in (0..512)
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
