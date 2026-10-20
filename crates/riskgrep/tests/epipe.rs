//! Standard output closed by the reader (`riskgrep rules list | head -1`):
//! the process ends quietly with status 0. The read end of the pipe is
//! closed before the binary writes anything, so every write fails with
//! EPIPE.

use std::path::Path;
use std::process::{Command, Stdio};

fn closed_stdout(args: &[&str], home: &Path, cwd: &Path) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_riskgrep"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("GIT_CEILING_DIRECTORIES", cwd.parent().unwrap())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn rules_list_into_a_closed_pipe_exits_quietly() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let (code, stderr) = closed_stdout(&["rules", "list"], home.path(), cwd.path());
    assert_eq!(stderr, "");
    assert_eq!(code, Some(0));
}

#[test]
fn scan_json_into_a_closed_pipe_exits_quietly() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(cwd.path().join("a.txt"), "hello\n").unwrap();
    for format in ["json", "text"] {
        let (code, stderr) = closed_stdout(
            &["scan", "--format", format, "a.txt"],
            home.path(),
            cwd.path(),
        );
        assert_eq!(stderr, "", "{format}");
        assert_eq!(code, Some(0), "{format}");
    }
}
