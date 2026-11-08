//! Claude Code's names for MCP tools, `mcp__<server>__<tool>`, mapped onto
//! the server and tool keys of the shared MCP entries
//! ([`riskgrep_core::mcp`]).

use riskgrep_core::config::Config;
use riskgrep_core::mcp::McpTable;

/// The prefix of every MCP tool name in Claude Code.
pub const PREFIX: &str = "mcp__";

/// The server and tool of MCP tool `name`, split as Claude Code 2.1.318
/// splits it: the server is the text between `mcp__` and the next `__`,
/// and the tool everything after it, which may itself hold `__`. A name
/// with no `__` after the server has an empty tool. `None` for a name
/// that does not start with `mcp__`.
pub fn split(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix(PREFIX)?;
    Some(rest.split_once("__").unwrap_or((rest, "")))
}

/// The server and tool keys of a `claude_code.mcp_tools` key, split as
/// [`split`] splits a name. A key with no `__` after its server part (such
/// as `mcp__*`) covers every tool of the servers it matches when that part
/// holds `*`.
fn alias_key(key: &str) -> Option<(&str, &str)> {
    let (server, tool) = split(key)?;
    if tool.is_empty() && !key.strip_prefix(PREFIX)?.contains("__") && server.contains('*') {
        return Some((server, "*"));
    }
    Some((server, tool))
}

/// The MCP entries Claude Code calls are judged by: the shared `[mcp]`
/// entries with every `claude_code.mcp_tools` entry laid over them, so for
/// the same server and tool key the `claude_code.mcp_tools` entry wins.
pub fn table(cfg: &Config) -> McpTable {
    let mut out = cfg.mcp.clone();
    for (key, entry) in &cfg.claude_code.mcp_tools {
        if let Some((server, tool)) = alias_key(key) {
            out.insert(server, tool, entry.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::mcp::{McpKind, McpTool};

    #[test]
    fn split_matches_claude_code() {
        assert_eq!(split("mcp__fs__read_file"), Some(("fs", "read_file")));
        assert_eq!(split("mcp__plugin_a_b__x__y"), Some(("plugin_a_b", "x__y")));
        assert_eq!(split("mcp__fs"), Some(("fs", "")));
        assert_eq!(split("mcp____t"), Some(("", "t")));
        assert_eq!(split("Read"), None);
    }

    fn entry(kind: McpKind) -> McpTool {
        McpTool {
            paths: vec!["p".into()],
            kind,
            max_depth: None,
        }
    }

    #[test]
    fn alias_entries_lay_over_shared_entries() {
        let mut cfg = Config::default();
        cfg.mcp.insert("notes", "open", entry(McpKind::Walk));
        cfg.mcp.insert("notes", "list", entry(McpKind::Names));
        for (k, kind) in [
            ("mcp__notes__open", McpKind::Read),
            ("mcp__db_*__query", McpKind::None),
            ("mcp__x*", McpKind::Names),
            ("mcp__filesystem__read_file", McpKind::Walk),
        ] {
            cfg.claude_code.mcp_tools.insert(k.into(), entry(kind));
        }
        let t = table(&cfg);
        let kind = |s, tool| t.entry(s, tool).map(|e| e.kind);
        // The alias wins for the same key; other shared entries stay.
        assert_eq!(kind("notes", "open"), Some(McpKind::Read));
        assert_eq!(kind("notes", "list"), Some(McpKind::Names));
        assert_eq!(kind("db_main", "query"), Some(McpKind::None));
        assert_eq!(kind("db_main", "drop"), None);
        assert_eq!(kind("xyz", "anything"), Some(McpKind::Names));
        assert_eq!(kind("filesystem", "read_file"), Some(McpKind::Walk));
        // Built-in entries the alias did not name stay.
        assert_eq!(kind("filesystem", "read_text_file"), Some(McpKind::Read));
    }
}
