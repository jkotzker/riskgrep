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
    span_regex = "(?i)(?:[?&]secret=|%3Fsecret%3D|%26secret%3D)([A-Z2-7]{16,})"
    secret_group = 1
    min_entropy = 2.5
    allow_regex = "^(?i:JBSWY3DPEHPK3PXP|(GEZDGNBVGY3TQOJQ)+|BASE32SECRET3232)$"
  strings:
    $re = /otpauth:\/\/(totp|hotp)\/[^ \t\r\n"'<>]{0,200}[?&]secret=[A-Za-z2-7]{16,}/ nocase
    // The percent-encoded form, as in the data parameter of a QR-code image
    // link: the scheme, the label separator, the `?`, and the `=` are
    // encoded, so the `secret` parameter follows %3F or %26.
    $re_encoded = /otpauth%3A%2F%2F(totp|hotp)%2F[^ \t\r\n"'<>]{0,300}(%3F|%26)secret%3D[A-Za-z2-7]{16,}/ nocase
  condition:
    $re or $re_encoded
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

// ---- more plaintext password-manager exports -----------------------------------
// The JSON-shaped rules require the file to start with `{` (a JSON object,
// after an optional UTF-8 byte order mark), so
// source files and documents that quote a layout are not exports.

// source: 1Password 1PIF (`.1pif`). 1Password does not document the format;
// the record separator line is fixed and read by independent parsers (for
// example Strongbox and 1P2KeePass), and Proton Pass's importer ships a
// sample export. The file is one JSON object per line, each followed by the
// separator line. A record counts when it carries a password: a field with the
// designation "password" (web forms and logins) or a `password` member of
// `secureContents` (password items).
rule onepassword_1pif_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /\*\*\*5642bee8-a5ff-11dc-8314-0800200c9a66\*\*\*/
    $pw_field = /"designation"[ \t]*:[ \t]*"password"/
    $pw_item = /"secureContents"[ \t]*:[ \t]*\{[ \t]*"password"[ \t]*:[ \t]*"[^"]/
  condition:
    (uint8(0) == 0x7B or (uint8(0) == 0xEF and uint8(1) == 0xBB and uint8(2) == 0xBF and uint8(3) == 0x7B)) and $hdr and ($pw_field or $pw_item)
}

// source: Firefox saved logins, "Export Logins" (`logins.csv`); the column
// list is written by LoginExport.sys.mjs in the Firefox source:
//   https://github.com/mozilla/gecko-dev/blob/master/toolkit/components/passwordmgr/LoginExport.sys.mjs
// (url, username, password, httpRealm, formActionOrigin, guid, timeCreated,
// timeLastUsed, timePasswordChanged; every name is quoted, and a spreadsheet
// re-save may remove the quotes)
rule firefox_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?"?url"?,"?username"?,"?password"?,"?httpRealm"?,"?formActionOrigin"?,"?guid"?,"?timeCreated"?,"?timeLastUsed"?,"?timePasswordChanged"?\r?\n[^\r\n]/
  condition:
    $hdr at 0
}

// source: KeePass 2.x "KeePass XML (2.x)" export. The root element is
// KeePassFile (the layout KeePass writes and KeePassXC reads, KeePassFile >
// Root > Group > Entry, each entry holding String elements with a Key and a
// Value); the export keeps values in plain text. An entry counts when its
// Password value is not empty. A KeePass database itself is encrypted
// (`keepass_database`).
rule keepass_xml_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /<KeePassFile[ \t\r\n>]/
    $pw = /<Key>Password<\/Key>[ \t\r\n]*<Value[^>]*>[^<]/
  condition:
    $hdr in (0..512) and $pw
}

// source: KeePass "CSV (1.x)" export, whose column names are read by
// independent importers (for example Padloc and Olares).
rule keepass_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?"?Account"?,"?Login Name"?,"?Password"?,"?Web Site"?,"?Comments"?\r?\n[^\r\n]/
  condition:
    $hdr at 0
}

// source: KeePassXC "Export to CSV", columns written by CsvExporter.cpp in
// the KeePassXC source:
//   https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/CsvExporter.cpp
// (Group, Title, Username, Password, URL, Notes, TOTP, Icon, Last Modified,
// Created; every name is quoted). Tags 2.4.0 to 2.6.2 of that file write
// only the first six columns, through Notes; 2.6.3 adds the other four.
rule keepassxc_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?"?Group"?,"?Title"?,"?Username"?,"?Password"?,"?URL"?,"?Notes"?(,"?TOTP"?,"?Icon"?,"?Last Modified"?,"?Created"?)?\r?\n[^\r\n]/
  condition:
    $hdr at 0
}

// source: Dashlane credentials CSV (`credentials.csv`), observed: the
// columns are those of Bitwarden's Dashlane importer and its sample file
// (username, username2, username3, title, password, note, url, category, then
// otpSecret or otpUrl). No Dashlane documentation of the columns was found.
rule dashlane_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?username,username2,username3,title,password,note,url,category,otp(Secret|Url)\r?\n[^\r\n]/
  condition:
    $hdr at 0
}

// source: Dashlane JSON export, observed: credentials sit in a top-level
// AUTHENTIFIANT array (as Bitwarden's Dashlane JSON importer reads it).
rule dashlane_json_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /"AUTHENTIFIANT"[ \t\r\n]*:[ \t\r\n]*\[/
    $pw = /"password"[ \t\r\n]*:[ \t\r\n]*"[^"]/
  condition:
    (uint8(0) == 0x7B or (uint8(0) == 0xEF and uint8(1) == 0xBB and uint8(2) == 0xBF and uint8(3) == 0x7B)) and $hdr and $pw
}

// source: Keeper JSON export, an array of shared folders and an array of
// records, each record with title, login, password, and login_url:
//   https://docs.keeper.io/user-guides/import-records-1/import-json
// Keeper's CSV export is not covered: the documented column list is not a
// header row in the files Keeper writes.
rule keeper_json_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /"records"[ \t\r\n]*:[ \t\r\n]*\[/
    $login = /"login"[ \t\r\n]*:[ \t\r\n]*"/
    $url = /"login_url"[ \t\r\n]*:/
    $pw = /"password"[ \t\r\n]*:[ \t\r\n]*"[^"]/
  condition:
    (uint8(0) == 0x7B or (uint8(0) == 0xEF and uint8(1) == 0xBB and uint8(2) == 0xBF and uint8(3) == 0x7B)) and $hdr and $login and $url and $pw
}

// source: Proton Pass CSV export. The writer emits the keys of each item in
// a fixed order (type, name, url, autofillUrls, email, username, password,
// note, totp, createTime, modifyTime, vault; earlier versions lack type and
// autofillUrls):
//   https://github.com/ProtonMail/WebClients/blob/main/packages/pass/lib/export/csv.ts
rule protonpass_csv_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /(\xEF\xBB\xBF)?(type,)?name,url,(autofillUrls,)?email,username,password,note,totp,createTime,modifyTime,vault\r?\n[^\r\n]/
  condition:
    $hdr at 0
}

// source: Proton Pass JSON export (the unencrypted ZIP, or the decrypted
// file), observed: version, userId, encrypted (false), and vaults, as
// Bitwarden's Proton Pass importer reads it, with login items whose content
// holds a password.
rule protonpass_json_export {
  meta:
    category = "secret"
    weight = 95
  strings:
    $hdr = /"encrypted"[ \t\r\n]*:[ \t\r\n]*false/
    $vaults = /"vaults"[ \t\r\n]*:[ \t\r\n]*\{/
    $pw = /"password"[ \t\r\n]*:[ \t\r\n]*"[^"]/
  condition:
    (uint8(0) == 0x7B or (uint8(0) == 0xEF and uint8(1) == 0xBB and uint8(2) == 0xBF and uint8(3) == 0x7B)) and $hdr in (0..400) and $vaults in (0..400) and $pw
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
