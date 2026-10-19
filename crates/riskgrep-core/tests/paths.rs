use riskgrep_core::paths::{cache_dir, cache_dir_for};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV: Mutex<()> = Mutex::new(());
fn o(s: &str) -> Option<OsString> {
    Some(OsString::from(s))
}

#[test]
fn empty_or_relative_home_gives_none() {
    for macos in [true, false] {
        assert_eq!(cache_dir_for(o(""), None, macos), None);
        assert_eq!(cache_dir_for(o("relative/dir"), None, macos), None);
        assert_eq!(cache_dir_for(None, None, macos), None);
    }
}

#[test]
fn absolute_home_paths() {
    assert_eq!(
        cache_dir_for(o("/home/u"), None, true),
        Some(PathBuf::from("/home/u/Library/Caches/riskgrep"))
    );
    assert_eq!(
        cache_dir_for(o("/home/u"), None, false),
        Some(PathBuf::from("/home/u/.cache/riskgrep"))
    );
}

#[test]
fn relative_xdg_falls_back_to_home() {
    assert_eq!(
        cache_dir_for(o("/home/u"), o("rel"), false),
        Some(PathBuf::from("/home/u/.cache/riskgrep"))
    );
    assert_eq!(
        cache_dir_for(o("/home/u"), o(""), false),
        Some(PathBuf::from("/home/u/.cache/riskgrep"))
    );
    assert_eq!(
        cache_dir_for(o("/home/u"), o("/x"), false),
        Some(PathBuf::from("/x/riskgrep"))
    );
    assert_eq!(cache_dir_for(None, o("rel"), false), None);
}

#[test]
fn cache_dir_reads_environment() {
    let _g = ENV.lock().unwrap();
    let old = std::env::var_os("HOME");
    std::env::set_var("HOME", "");
    assert_eq!(cache_dir(), None);
    std::env::set_var("HOME", "relative/dir");
    assert_eq!(cache_dir(), None);
    std::env::set_var("HOME", "/abs");
    assert!(cache_dir().unwrap().is_absolute());
    match old {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
}
