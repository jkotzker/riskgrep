// Credential files recognised by structure: one-time-password seeds,
// plaintext password-manager exports, and two-factor recovery codes.
// Hand-written; the patterns are regexes so that no line of this file spells
// a complete match (the shipped rule sources are scanned by a test).
//
// Header rows of the exports are matched at offset 0 and need at least one
// data line after them, so an empty import template is not flagged. Evidence
// locations are the structural lines, never the credentials.

// ---- one-time-password seeds -------------------------------------------------
// An `otpauth` URI with a base32 `secret` parameter (Key URI Format, as
// Google Authenticator and RFC 6238 apps read it). The `span` narrows the
// location to the seed and the allowlist drops the public example seeds used
// in one-time-password documentation (JBSWY3DPEHPK3PXP, the base32 of
// "1234567890" and of the RFC 4226 test key, and the pyotp README seed).
rule otpauth_totp_seed {
  meta:
    category = "secret"
    weight = 95
    post = "span,entropy,allow_regex"
    span_regex = "(?i)[?&]secret=([A-Z2-7]{16,})"
    secret_group = 1
    min_entropy = 2.5
    allow_regex = "^(?i:JBSWY3DPEHPK3PXP|(GEZDGNBVGY3TQOJQ)+|BASE32SECRET3232)$"
  strings:
    $re = /otpauth:\/\/(totp|hotp)\/[^ \t\r\n"'<>]{0,200}[?&]secret=[A-Za-z2-7]{16,}/ nocase
  condition:
    $re
}

// Google Authenticator "export accounts" QR payload: every account's seed in
// one base64 protobuf blob.
rule otpauth_migration_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $re = /otpauth-migration:\/\/offline\?data=[A-Za-z0-9%+\/=_-]{40,}/ nocase
  condition:
    $re
}

// ---- plaintext password-manager exports --------------------------------------
// source: LastPass generic CSV format
//   https://community.lastpass.com/kb/articles/40-export-vault-data-from-lastpass-as-a-generic-csv-file
//   (columns url, username, password, totp, extra, name, grouping, fav; some
//   exports omit totp)
rule lastpass_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?url,username,password,(totp,)?extra,name,grouping,fav\r?\n[^\r\n]/ nocase
  condition:
    $hdr at 0
}

// source: observed Chrome, Edge, and Brave exports (name, url, username,
// password, note; older versions omit note). Google documents only that an
// import file starts with url, username, and password columns:
//   https://support.google.com/chrome/answer/13068232
rule chrome_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?name,url,username,password(,note)?\r?\n[^\r\n]/ nocase
  condition:
    $hdr at 0
}

// source: observed Apple Passwords exports (Title, URL, Username, Password,
// Notes, OTPAuth). Apple does not publish the column list; the match ignores
// case because reports differ on the capitalisation of URL.
rule apple_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?title,url,username,password,notes(,otpauth)?\r?\n[^\r\n]/ nocase
  condition:
    $hdr at 0
}

// source: Bitwarden individual-vault CSV
//   https://bitwarden.com/help/condition-bitwarden-import/
// (the organization format starts with collections instead of folder,favorite)
rule bitwarden_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?(folder,favorite|collections),type,name,notes,fields,(reprompt,)?login_uri,login_username,login_password,login_totp\r?\n[^\r\n]/ nocase
  condition:
    $hdr at 0
}

// source: Bitwarden unencrypted JSON export (folders and items, each login
// with username, password, and totp), whose top-level `encrypted` flag is
// false:  https://bitwarden.com/help/condition-bitwarden-import/
rule bitwarden_json_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /"encrypted"[ \t\r\n]*:[ \t\r\n]*false/
    $items = /"items"[ \t\r\n]*:[ \t\r\n]*\[/
    $login = /"login"[ \t\r\n]*:[ \t\r\n]*\{/
    $pw = /"password"[ \t\r\n]*:[ \t\r\n]*"[^"]/
  condition:
    $hdr in (0..200) and $items and $login and $pw
}

// source: 1Password export.data, the JSON member of a 1PUX export, once
// unzipped:  https://support.1password.com/1pux-format/
// (accounts, then vaults, then items whose loginFields carry a field with
// the designation "password")
rule onepassword_json_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /\{[ \t\r\n]*"accounts"[ \t\r\n]*:[ \t\r\n]*\[[ \t\r\n]*\{[ \t\r\n]*"attrs"/
    $vaults = /"vaults"[ \t\r\n]*:/
    $login = /"loginFields"[ \t\r\n]*:/
    $pw = /"designation"[ \t\r\n]*:[ \t\r\n]*"password"/
  condition:
    $hdr in (0..64) and $vaults and $login and $pw
}

// ---- two-factor recovery and backup codes --------------------------------------
// A short file (under 8 KiB) with at least six lines shaped like recovery
// codes and a signal that it is a list of two-factor codes: the file name, or
// a "recovery codes" / "backup codes" heading in the first 512 bytes. The
// `code_lines` post-processor counts the lines in one linear pass (shapes:
// GitHub hex pairs, Google digit pairs, and ten-character alphanumeric codes
// containing a digit, each optionally behind a list number or bullet). No YARA
// pattern describes a code line: patterns without a literal to search for run
// at every offset, which added about 28% to the instructions of a scan of
// small text files (measured with `hyperfine -N --export-json` instruction
// counts, 20 files of 3 KiB).

rule recovery_codes_named_file {
  meta:
    category = "secret"
    weight = 90
    family = "recovery_codes"
    family_cap = 90
    post = "code_lines"
    min_codes = 6
  condition:
    filesize < 8192 and path matches /(?i)(recovery|backup)[-_. ]?codes?/
}

rule recovery_codes_headed_file {
  meta:
    category = "secret"
    weight = 80
    family = "recovery_codes"
    family_cap = 90
    post = "code_lines"
    min_codes = 6
  strings:
    $head = /(recovery|backup)[ \t]+codes/ nocase
  condition:
    filesize < 8192 and $head in (0..512)
}
