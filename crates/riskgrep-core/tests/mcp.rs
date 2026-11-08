//! The shared MCP gating code, driven directly with no agent adapter.

use riskgrep_core::config::Action;
use riskgrep_core::mcp::{self, McpKind, McpPlan, McpTable, McpTool};
use serde_json::json;
use std::path::{Path, PathBuf};

fn tool(kind: McpKind, fields: &[&str]) -> McpTool {
    McpTool {
        paths: fields.iter().map(|f| f.to_string()).collect(),
        kind,
        max_depth: None,
        decision: None,
    }
}

fn decided(action: Action) -> McpTool {
    McpTool {
        paths: Vec::new(),
        kind: McpKind::Read,
        max_depth: None,
        decision: Some(action),
    }
}

fn table(entries: &[(&str, &str, McpTool)]) -> McpTable {
    let mut t = McpTable::default();
    for (s, n, e) in entries {
        t.insert(s, n, e.clone());
    }
    t
}

#[test]
fn paths_reads_strings_and_lists() {
    let cwd = Path::new("/w");
    let f = |v, fields: &[&str]| {
        let fields: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        mcp::paths(&v, &fields, cwd, Some("/h"))
    };
    let p = |s: &str| PathBuf::from(s);
    assert_eq!(f(json!({"path": "a"}), &["path"]), Some(vec![p("/w/a")]));
    assert_eq!(
        f(json!({"paths": ["/x", "~/y"]}), &["paths"]),
        Some(vec![p("/x"), p("/h/y")])
    );
    assert_eq!(f(json!({"b": "x"}), &["a", "b"]), Some(vec![p("/w/x")]));
    assert_eq!(f(json!({"paths": []}), &["paths"]), Some(vec![]));
    // A path is not trimmed.
    assert_eq!(
        f(json!({"path": " a "}), &["path"]),
        Some(vec![p("/w/ a ")])
    );
    assert_eq!(f(json!({"path": "~"}), &["path"]), Some(vec![p("/h")]));
    // `~user` is not expanded, nor `~` without a home.
    assert_eq!(
        f(json!({"path": "~u/x"}), &["path"]),
        Some(vec![p("/w/~u/x")])
    );
    assert_eq!(
        mcp::paths(&json!({"path": "~/x"}), &["path".into()], cwd, None),
        Some(vec![p("/w/~/x")])
    );
    for bad in [
        json!({}),
        json!({"path": 1}),
        json!({"path": ["a", 2]}),
        json!({"path": {"p": "a"}}),
        json!(null),
    ] {
        assert_eq!(f(bad.clone(), &["path"]), None, "{bad}");
    }
}

#[test]
fn entry_prefers_exact_keys_then_key_order() {
    use McpKind::{Names, None as Reads, Read, Walk};
    let t = table(&[
        ("*", "*", tool(Reads, &[])),
        ("*", "read", tool(Walk, &["p"])),
        ("notes", "*", tool(Names, &["p"])),
        ("notes", "open", tool(Read, &["p"])),
        ("db_*", "query", tool(Read, &["q"])),
        ("db_*", "q*", tool(Walk, &["q"])),
    ]);
    let kind = |s, n| t.entry(s, n).map(|e| e.kind);
    // Exact server and tool.
    assert_eq!(kind("notes", "open"), Some(Read));
    // An exact server wins over a pattern server, even with a pattern tool.
    assert_eq!(kind("notes", "read"), Some(Names));
    assert_eq!(kind("notes", "list"), Some(Names));
    // Among pattern servers, an exact tool wins over a pattern tool.
    assert_eq!(kind("db_main", "query"), Some(Read));
    assert_eq!(kind("other", "read"), Some(Walk));
    // Equally specific keys: the first in key order (`*` before `db_*`).
    assert_eq!(kind("db_main", "quit"), Some(Reads));
    assert_eq!(kind("db_main", "drop"), Some(Reads));
    let t = table(&[("db_*", "q*", tool(Walk, &["q"]))]);
    assert_eq!(t.entry("db_main", "quit").map(|e| e.kind), Some(Walk));
    // `*` does not match across a server name.
    assert_eq!(
        table(&[("db", "*", tool(Reads, &[]))]).entry("db_main", "x"),
        None
    );
}

#[test]
fn builtin_entries_are_valid_and_overlay_replaces_by_key() {
    let b = McpTable::builtin();
    assert!(b.problems().is_empty(), "{:?}", b.problems());
    let over = table(&[
        ("filesystem", "read_file", tool(McpKind::Walk, &["path"])),
        ("notes", "open", tool(McpKind::Read, &["file"])),
    ]);
    let t = b.overlay(&over);
    assert_eq!(
        t.entry("filesystem", "read_file").unwrap().kind,
        McpKind::Walk
    );
    assert_eq!(
        t.entry("filesystem", "read_text_file").unwrap().kind,
        McpKind::Read
    );
    assert!(t.entry("notes", "open").is_some());
    // The original is unchanged.
    assert_eq!(
        b.entry("filesystem", "read_file").unwrap().kind,
        McpKind::Read
    );
}

#[test]
fn problems_name_the_entry() {
    let t = table(&[
        ("s", "ok", tool(McpKind::None, &[])),
        ("s", "bad", tool(McpKind::Read, &[])),
        ("s", "blank", tool(McpKind::Names, &[""])),
    ]);
    assert_eq!(
        t.problems(),
        [
            "mcp.servers.\"s\".tools.\"bad\": needs `paths`, the input fields that hold paths",
            "mcp.servers.\"s\".tools.\"blank\": needs `paths`, the input fields that hold paths",
        ]
    );
}

#[test]
fn plan_follows_the_entry_kind() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    std::fs::write(cwd.join("a.txt"), b"x").unwrap();
    std::fs::create_dir(cwd.join("d")).unwrap();
    let mut names = tool(McpKind::Names, &["path"]);
    names.max_depth = Some(1);
    let t = table(&[
        ("s", "read", tool(McpKind::Read, &["path", "paths"])),
        ("s", "walk", tool(McpKind::Walk, &["path"])),
        ("s", "list", names),
        ("s", "write", tool(McpKind::None, &[])),
    ]);
    let plan = |n, v| t.plan("s", n, &v, cwd, None);
    let a = cwd.join("a.txt");
    let d = cwd.join("d");
    // `read` keeps the paths that are files a read would open.
    assert_eq!(
        plan("read", json!({"paths": ["a.txt", "d", "missing"]})),
        McpPlan::Read(vec![a.clone()])
    );
    assert_eq!(plan("read", json!({"path": "d"})), McpPlan::Nothing);
    assert_eq!(plan("read", json!({"paths": []})), McpPlan::Nothing);
    assert_eq!(
        plan("read", json!({"other": "a.txt"})),
        McpPlan::Unresolved(Action::Allow)
    );
    assert_eq!(
        plan("read", json!({"path": 3})),
        McpPlan::Unresolved(Action::Allow)
    );
    // `walk` and `names` keep every path, existing or not.
    assert_eq!(
        plan("walk", json!({"path": "d"})),
        McpPlan::Walk(vec![d.clone()])
    );
    assert_eq!(
        plan("list", json!({"path": "missing"})),
        McpPlan::Names {
            roots: vec![cwd.join("missing")],
            max_depth: Some(1)
        }
    );
    // `none` reads nothing whatever its input; no entry is unresolved.
    assert_eq!(plan("write", json!({"path": 3})), McpPlan::Nothing);
    assert_eq!(
        plan("other", json!({"path": "a.txt"})),
        McpPlan::Unresolved(Action::Allow)
    );
    assert_eq!(
        t.plan("other", "read", &json!({"path": "a.txt"}), cwd, None),
        McpPlan::Unresolved(Action::Allow)
    );
}

#[test]
fn unresolved_follows_on_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    let mut t = table(&[("s", "read", tool(McpKind::Read, &["path"]))]);
    for (setting, want) in [
        (None, Action::Allow),
        (Some(Action::Allow), Action::Allow),
        (Some(Action::Ask), Action::Ask),
        (Some(Action::Deny), Action::Deny),
    ] {
        t.on_unresolved = setting;
        // No entry, and an entry whose field holds no path.
        for (server, name, input) in [
            ("s", "other", json!({"path": "a"})),
            ("x", "read", json!({"path": "a"})),
            ("s", "read", json!({"path": 3})),
            ("s", "read", json!({})),
        ] {
            assert_eq!(
                t.plan(server, name, &input, cwd, None),
                McpPlan::Unresolved(want),
                "{setting:?} {server} {name} {input}"
            );
        }
        // A resolved call is not affected.
        assert_eq!(
            t.plan("s", "read", &json!({"path": "missing"}), cwd, None),
            McpPlan::Nothing
        );
    }
}

#[test]
fn entry_decision_applies_to_its_tools() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    std::fs::write(cwd.join("a.txt"), b"x").unwrap();
    let mut t = table(&[
        ("s", "read", tool(McpKind::Read, &["path"])),
        ("s", "*", decided(Action::Ask)),
        ("s", "shell", decided(Action::Deny)),
        ("q", "*", tool(McpKind::None, &[])),
        ("open", "*", decided(Action::Allow)),
    ]);
    t.on_unresolved = Some(Action::Ask);
    let plan = |s, n, v| t.plan(s, n, &v, cwd, None);
    let a = json!({"path": "a.txt"});
    // A server's `*` entry with a decision covers its tools without an
    // entry of their own, whatever their input; its mapped tools are
    // planned as before.
    assert_eq!(plan("s", "list", a.clone()), McpPlan::Decision(Action::Ask));
    assert_eq!(plan("s", "list", json!(7)), McpPlan::Decision(Action::Ask));
    assert_eq!(
        plan("s", "read", a.clone()),
        McpPlan::Read(vec![cwd.join("a.txt")])
    );
    // A mapped tool whose fields cannot be read follows `on_unresolved`.
    assert_eq!(
        plan("s", "read", json!({"path": 1})),
        McpPlan::Unresolved(Action::Ask)
    );
    // A tool's own entry wins over the server's.
    assert_eq!(
        plan("s", "shell", a.clone()),
        McpPlan::Decision(Action::Deny)
    );
    // `kind = "none"` and `decision = "allow"` both quiet a server that
    // `on_unresolved` would ask about.
    assert_eq!(plan("q", "any", a.clone()), McpPlan::Nothing);
    assert_eq!(
        plan("open", "any", a.clone()),
        McpPlan::Decision(Action::Allow)
    );
    assert_eq!(plan("other", "any", a), McpPlan::Unresolved(Action::Ask));
}

#[test]
fn merge_keeps_on_unresolved_unless_set() {
    let mut base = McpTable::builtin();
    base.on_unresolved = Some(Action::Ask);
    let mut over = table(&[("s", "*", decided(Action::Deny))]);
    assert_eq!(base.overlay(&over).on_unresolved, Some(Action::Ask));
    over.on_unresolved = Some(Action::Allow);
    let t = base.overlay(&over);
    assert_eq!(t.on_unresolved, Some(Action::Allow));
    assert_eq!(t.entry("s", "x").unwrap().decision, Some(Action::Deny));
}
