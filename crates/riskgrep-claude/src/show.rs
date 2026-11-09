//! The masked view as an agent route: the one `Bash` command shape the
//! hook answers `ask` for without analysing it, and the command its reasons
//! suggest.
//!
//! `riskgrep show` prints only masked text or a structural summary, so
//! the user can approve it on a flagged file, but only if the command really
//! runs the trusted `riskgrep` binary with nothing else attached. The
//! exemption from analysis is therefore a whitelist of one shape, and
//! anything else is analysed as any other command:
//!
//! ```text
//! TRUSTED show [--rule-ids] [--lines FIRST:LAST] [--] FILE
//! ```
//!
//! - The command is one line of words separated by spaces or tabs. Each
//!   word is either plain (letters, digits, and `_ . / - + , @ % :`) or
//!   wholly single-quoted without a control character inside. No other
//!   character may appear, so there is no second command, pipe, redirect,
//!   substitution, expansion, assignment, comment, or glob.
//! - The first word is the canonical path of the trusted binary
//!   ([`trusted_riskgrep`]), exactly: a different binary named `riskgrep`,
//!   a relative name found through `PATH`, or a wrapper (`command`, `env`,
//!   `exec`) is not exempt. The command itself cannot define a shell
//!   function to take its place, because no definition can precede it in a
//!   single simple command, and shell state (functions, aliases, exported
//!   variables) does not persist between Claude Code `Bash` calls (measured
//!   with Claude Code 2.1.318). A function named after the trusted path in a
//!   shell startup file can take its place, in bash and in zsh: the exemption
//!   does not cover a shell whose startup files are not the user's own.
//! - The options are `--rule-ids` and `--lines FIRST:LAST`, each at most
//!   once, in any order, then an optional `--`, then exactly one file that
//!   does not start with `-` (unless after `--`).

use std::path::Path;

/// Characters a plain word may hold.
fn plain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"_./-+,@%:".contains(&b)
}

/// The words of `command` when it consists only of plain and wholly
/// single-quoted words, unquoted; `None` for anything else.
fn words(command: &str) -> Option<Vec<String>> {
    let b = command.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b' ' | b'\t' => i += 1,
            b'\'' => {
                let end = i + 1 + b[i + 1..].iter().position(|&c| c == b'\'')?;
                let inner = &command[i + 1..end];
                if inner.chars().any(riskgrep_core::model::needs_escape) {
                    return None;
                }
                // The closing quote must end the word.
                if end + 1 < b.len() && !matches!(b[end + 1], b' ' | b'\t') {
                    return None;
                }
                out.push(inner.to_string());
                i = end + 1;
            }
            c if plain_char(c) => {
                let start = i;
                while i < b.len() && plain_char(b[i]) {
                    i += 1;
                }
                if i < b.len() && !matches!(b[i], b' ' | b'\t') {
                    return None;
                }
                out.push(command[start..i].to_string());
            }
            _ => return None,
        }
    }
    Some(out)
}

fn lines_value(s: &str) -> bool {
    riskgrep_core::show::parse_lines(s).is_ok()
}

/// The binary a command of the exempt shape runs (its first word,
/// unquoted), or `None` when `command` does not have that shape. The caller
/// must still compare the binary with [`trusted_riskgrep`].
pub fn masked_view_binary(command: &str) -> Option<String> {
    let w = words(command)?;
    let (bin, rest) = w.split_first()?;
    let (sub, mut rest) = rest.split_first()?;
    if sub != "show" || !bin.starts_with('/') {
        return None;
    }
    let (mut rule_ids, mut lines) = (false, false);
    loop {
        match rest.first().map(String::as_str) {
            Some("--rule-ids") if !rule_ids => {
                rule_ids = true;
                rest = &rest[1..];
            }
            Some("--lines") if !lines => {
                if !rest.get(1).is_some_and(|v| lines_value(v)) {
                    return None;
                }
                lines = true;
                rest = &rest[2..];
            }
            Some("--") => {
                rest = &rest[1..];
                break;
            }
            Some(f) if f.starts_with('-') => return None,
            _ => break,
        }
    }
    match rest {
        [file] if !file.is_empty() => Some(bin.clone()),
        _ => None,
    }
}

/// Whether `command` is exactly a masked view by the binary at `trusted`.
pub fn is_masked_view(command: &str, trusted: &str) -> bool {
    masked_view_binary(command).is_some_and(|b| b == trusted)
}

/// `s` as one shell word the exemption accepts: plain when it can be,
/// otherwise single-quoted; `None` when it holds a single quote or a
/// character `escape_controls` would escape (a control character, a
/// bidirectional mark, a line separator).
pub fn shell_word(s: &str) -> Option<String> {
    if s.is_empty()
        || s.chars()
            .any(|c| c == '\'' || riskgrep_core::model::needs_escape(c))
    {
        return None;
    }
    if s.bytes().all(plain_char) {
        Some(s.to_string())
    } else {
        Some(format!("'{s}'"))
    }
}

/// The command that shows `file` masked with the binary at `trusted`, in
/// the exempt shape; `None` when either cannot be written as a word.
pub fn masked_view_command(trusted: &str, file: &str) -> Option<String> {
    let bin = shell_word(trusted)?;
    let f = shell_word(file)?;
    let sep = if file.starts_with('-') { "-- " } else { "" };
    Some(format!("{bin} show {sep}{f}"))
}

/// The `riskgrep` binary the hook trusts to show masked views: the regular
/// file named `riskgrep` in the directory of this hook's own executable,
/// after links to the hook are followed. It must not itself be a link,
/// which could point anywhere: in the hook's own directory, whoever can
/// replace it can replace the hook too, so trusting it adds no exposure.
/// `None` when there is none, or its path cannot be written as a shell
/// word.
pub fn trusted_riskgrep() -> Option<String> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    trusted_beside(&exe)
}

/// [`trusted_riskgrep`] for the executable at `exe`.
pub fn trusted_beside(exe: &Path) -> Option<String> {
    let p = exe.parent()?.canonicalize().ok()?.join("riskgrep");
    if !p.is_absolute() || !std::fs::symlink_metadata(&p).ok()?.is_file() {
        return None;
    }
    let s = p.to_str()?.to_string();
    shell_word(&s)?;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "/opt/rg/bin/riskgrep";

    #[test]
    fn exact_shapes_are_exempt() {
        for c in [
            "/opt/rg/bin/riskgrep show a.env",
            "  /opt/rg/bin/riskgrep\tshow   config/a.env  ",
            "/opt/rg/bin/riskgrep show --rule-ids a.env",
            "/opt/rg/bin/riskgrep show --lines 3:9 a.env",
            "/opt/rg/bin/riskgrep show --lines 3:9 --rule-ids a.env",
            "/opt/rg/bin/riskgrep show --rule-ids --lines 1:1 -- -odd.env",
            "/opt/rg/bin/riskgrep show 'my secrets/a b.env'",
            "'/opt/rg/bin/riskgrep' show a.env",
            "/opt/rg/bin/riskgrep show '$HOME;x|y`z`'",
        ] {
            assert!(is_masked_view(c, T), "{c}");
        }
    }

    #[test]
    fn every_other_shape_is_not() {
        for c in [
            "",
            "/opt/rg/bin/riskgrep",
            "/opt/rg/bin/riskgrep show",
            "/opt/rg/bin/riskgrep scan a.env",
            "/opt/rg/bin/riskgrep show a.env b.env",
            "/opt/rg/bin/riskgrep show a.env; cat a.env",
            "/opt/rg/bin/riskgrep show a.env && cat a.env",
            "/opt/rg/bin/riskgrep show a.env | cat",
            "/opt/rg/bin/riskgrep show a.env > out",
            "/opt/rg/bin/riskgrep show < a.env",
            "/opt/rg/bin/riskgrep show a.env &",
            "/opt/rg/bin/riskgrep show $(echo a.env)",
            "/opt/rg/bin/riskgrep show `echo a.env`",
            "/opt/rg/bin/riskgrep show $F",
            "/opt/rg/bin/riskgrep show ~/a.env",
            "/opt/rg/bin/riskgrep show *.env",
            "/opt/rg/bin/riskgrep show a.{env,txt}",
            "/opt/rg/bin/riskgrep show \"a.env\"",
            "/opt/rg/bin/riskgrep show a'.env'",
            "/opt/rg/bin/riskgrep show 'a.env'x",
            "/opt/rg/bin/riskgrep show 'a.env",
            "/opt/rg/bin/riskgrep show a\\.env",
            "/opt/rg/bin/riskgrep show a.env # x",
            "/opt/rg/bin/riskgrep show a.env\ncat a.env",
            "/opt/rg/bin/riskgrep show 'a\nb'",
            "/opt/rg/bin/riskgrep show --lines a.env",
            "/opt/rg/bin/riskgrep show --lines 0:1 a.env",
            "/opt/rg/bin/riskgrep show --lines=1:2 a.env",
            "/opt/rg/bin/riskgrep show --lines 1:2 --lines 1:2 a.env",
            "/opt/rg/bin/riskgrep show --rule-ids --rule-ids a.env",
            "/opt/rg/bin/riskgrep show --category secret a.env",
            "/opt/rg/bin/riskgrep show -x a.env",
            "/opt/rg/bin/riskgrep show -odd.env",
            "/opt/rg/bin/riskgrep show -- a.env b.env",
            "/opt/rg/bin/riskgrep --help show a.env",
            "HOME=/tmp /opt/rg/bin/riskgrep show a.env",
            "env /opt/rg/bin/riskgrep show a.env",
            "command /opt/rg/bin/riskgrep show a.env",
            "exec /opt/rg/bin/riskgrep show a.env",
            "riskgrep show a.env",
            "./riskgrep show a.env",
            "/tmp/riskgrep show a.env",
            "/opt/rg/bin/../bin/riskgrep show a.env",
            "/opt/rg/bin/riskgrep2 show a.env",
            "function /opt/rg/bin/riskgrep { cat \"$2\"; }; /opt/rg/bin/riskgrep show a.env",
            "(/opt/rg/bin/riskgrep show a.env)",
            "/opt/rg/bin/riskgrep show a.env\u{0}",
        ] {
            assert!(!is_masked_view(c, T), "{c:?}");
        }
    }

    #[test]
    fn suggested_commands_are_exempt() {
        for f in [
            "a.env",
            "dir with space/a.env",
            "-dash.env",
            "$x.env",
            "/abs/ü.env",
        ] {
            let c = masked_view_command(T, f).unwrap();
            assert!(is_masked_view(&c, T), "{c}");
        }
        assert_eq!(masked_view_command(T, "a'b"), None);
        assert_eq!(masked_view_command(T, "a\u{1b}b"), None);
        assert_eq!(
            masked_view_command("/x y/riskgrep", "a").as_deref(),
            Some("'/x y/riskgrep' show a")
        );
    }

    #[test]
    fn names_with_hidden_format_characters_get_no_command() {
        for f in [
            "a\u{202e}b.env",
            "a\u{2028}b.env",
            "a\u{2066}b.env",
            "a\n.env",
        ] {
            assert_eq!(
                masked_view_command("/opt/rg/bin/riskgrep", f),
                None,
                "{f:?}"
            );
            let c = format!("/opt/rg/bin/riskgrep show '{f}'");
            assert!(!is_masked_view(&c, "/opt/rg/bin/riskgrep"), "{f:?}");
        }
    }

    #[test]
    fn the_trusted_binary_is_a_regular_file_beside_the_hook() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let hook = bin.join("riskgrep-claude");
        std::fs::write(&hook, b"").unwrap();
        assert_eq!(trusted_beside(&hook), None, "no sibling");
        std::fs::create_dir(bin.join("riskgrep")).unwrap();
        assert_eq!(trusted_beside(&hook), None, "a directory is not trusted");
        std::fs::remove_dir(bin.join("riskgrep")).unwrap();
        // A link would move the trusted binary out of the hook's directory.
        let real = d.path().join("real-riskgrep");
        std::fs::write(&real, b"").unwrap();
        std::os::unix::fs::symlink(&real, bin.join("riskgrep")).unwrap();
        assert_eq!(trusted_beside(&hook), None, "a link is not trusted");
        std::fs::remove_file(bin.join("riskgrep")).unwrap();
        std::fs::write(bin.join("riskgrep"), b"").unwrap();
        let t = trusted_beside(&hook).unwrap();
        assert_eq!(Path::new(&t), bin.canonicalize().unwrap().join("riskgrep"));
    }
}
