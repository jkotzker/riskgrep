//! Claude Code's names for MCP tools, `mcp__<server>__<tool>`, mapped onto
//! the server and tool keys of the shared MCP entries
//! ([`riskgrep_core::mcp`]).

use riskgrep_core::config::Config;
use riskgrep_core::mcp::{wildcard, McpTable, McpTool};

/// The prefix of every MCP tool name in Claude Code.
pub const PREFIX: &str = "mcp__";

/// The server name Claude Code gives Desktop Commander when it is installed
/// as a plugin, `plugin_<plugin>_<server>`.
const DESKTOP_COMMANDER_PLUGIN: &str = "plugin_desktop-commander_desktop-commander";

/// The server and tool of MCP tool `name`, split as Claude Code 2.1.318
/// splits it: the server is the text between `mcp__` and the next `__`,
/// and the tool everything after it, which may itself hold `__`. A name
/// with no `__` after the server has an empty tool. `None` for a name
/// that does not start with `mcp__`.
pub fn split(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix(PREFIX)?;
    Some(rest.split_once("__").unwrap_or((rest, "")))
}

/// The MCP settings Claude Code calls are judged by: the shared `[mcp]`
/// table with `[claude_code.mcp]` laid over it, and the built-in Desktop
/// Commander entries under the server name of its plugin, below any entry
/// the configuration makes for that server and tool. `on_unresolved` is
/// `claude_code.mcp.on_unresolved`, else `mcp.on_unresolved`, else
/// `claude_code.on_unresolved`, which covered MCP tools before the MCP
/// settings existed. `claude_code.mcp_tools` is consulted by [`entry`].
pub fn table(cfg: &Config) -> McpTable {
    let mut out = cfg.mcp.overlay(&cfg.claude_code.mcp);
    if let Some(builtin) = McpTable::builtin().servers.remove("desktop-commander") {
        let tools = &mut out
            .servers
            .entry(DESKTOP_COMMANDER_PLUGIN.to_string())
            .or_default()
            .tools;
        for (tool, entry) in builtin.tools {
            tools.entry(tool).or_insert(entry);
        }
    }
    out.on_unresolved
        .get_or_insert(cfg.claude_code.on_unresolved);
    out
}

/// The entry for MCP tool `name`, with `table` from [`table`]. A
/// `claude_code.mcp_tools` key is matched against the whole name, so a `*`
/// in it can span the `__` between server and tool. In order: the
/// `claude_code.mcp_tools` key equal to `name`; an entry of `table` naming
/// exactly that server and tool; the first `claude_code.mcp_tools` key with
/// `*` in key order that matches; then the patterns of `table`.
pub fn entry<'a>(cfg: &'a Config, table: &'a McpTable, name: &str) -> Option<&'a McpTool> {
    let aliases = &cfg.claude_code.mcp_tools;
    if let Some(e) = aliases.get(name) {
        return Some(e);
    }
    let (server, tool) = split(name)?;
    table
        .servers
        .get(server)
        .and_then(|s| s.tools.get(tool))
        .or_else(|| {
            aliases
                .iter()
                .find(|(k, _)| k.contains('*') && wildcard(k, name))
                .map(|(_, e)| e)
        })
        .or_else(|| table.entry(server, tool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use riskgrep_core::mcp::McpKind;

    #[test]
    fn split_matches_claude_code() {
        assert_eq!(split("mcp__fs__read_file"), Some(("fs", "read_file")));
        assert_eq!(split("mcp__plugin_a_b__x__y"), Some(("plugin_a_b", "x__y")));
        assert_eq!(split("mcp__fs"), Some(("fs", "")));
        assert_eq!(split("mcp____t"), Some(("", "t")));
        assert_eq!(split("Read"), None);
    }

    fn tool(kind: McpKind) -> McpTool {
        McpTool {
            paths: vec!["p".into()],
            kind,
            max_depth: None,
            decision: None,
        }
    }

    #[test]
    fn alias_entries_lay_over_shared_entries() {
        let mut cfg = Config::default();
        cfg.mcp.insert("notes", "open", tool(McpKind::Walk));
        cfg.mcp.insert("notes", "list", tool(McpKind::Names));
        for (k, kind) in [
            ("mcp__notes__open", McpKind::Read),
            ("mcp__db_*__query", McpKind::None),
            ("mcp__x*", McpKind::Names),
            ("mcp__filesystem__read_file", McpKind::Walk),
        ] {
            cfg.claude_code.mcp_tools.insert(k.into(), tool(kind));
        }
        let t = table(&cfg);
        let kind = |name| entry(&cfg, &t, name).map(|e| e.kind);
        // The alias wins for the same name; other shared entries stay.
        assert_eq!(kind("mcp__notes__open"), Some(McpKind::Read));
        assert_eq!(kind("mcp__notes__list"), Some(McpKind::Names));
        assert_eq!(kind("mcp__db_main__query"), Some(McpKind::None));
        assert_eq!(kind("mcp__db_main__drop"), None);
        assert_eq!(kind("mcp__xyz__anything"), Some(McpKind::Names));
        assert_eq!(kind("mcp__filesystem__read_file"), Some(McpKind::Walk));
        // Built-in entries the alias did not name stay.
        assert_eq!(kind("mcp__filesystem__read_text_file"), Some(McpKind::Read));
        assert_eq!(kind("Read"), None);
    }

    #[test]
    fn alias_keys_match_the_whole_name() {
        let mut cfg = Config::default();
        for (k, kind) in [
            ("mcp__*read_file", McpKind::Read),
            ("mcp__*__open", McpKind::Walk),
            ("mcp__notes__*", McpKind::None),
        ] {
            cfg.claude_code.mcp_tools.insert(k.into(), tool(kind));
        }
        let t = table(&cfg);
        let kind = |name| entry(&cfg, &t, name).map(|e| e.kind);
        // A `*` spans the `__` between server and tool.
        assert_eq!(kind("mcp__notes__read_file"), Some(McpKind::Read));
        // The first key in key order wins, whatever names the server.
        assert_eq!(kind("mcp__notes__open"), Some(McpKind::Walk));
        assert_eq!(kind("mcp__notes__list"), Some(McpKind::None));
        assert_eq!(kind("mcp__other__list"), None);
    }

    #[test]
    fn exact_table_entry_comes_before_alias_patterns_and_table_patterns_after() {
        let mut cfg = Config::default();
        cfg.mcp.insert("notes", "open", tool(McpKind::Walk));
        cfg.mcp.insert("notes", "*", tool(McpKind::Names));
        cfg.claude_code
            .mcp_tools
            .insert("mcp__notes__l*".into(), tool(McpKind::None));
        let t = table(&cfg);
        let kind = |name| entry(&cfg, &t, name).map(|e| e.kind);
        assert_eq!(kind("mcp__notes__open"), Some(McpKind::Walk));
        assert_eq!(kind("mcp__notes__list"), Some(McpKind::None));
        assert_eq!(kind("mcp__notes__read"), Some(McpKind::Names));
    }

    #[test]
    fn plugin_server_gets_desktop_commander_entries_below_the_configuration() {
        let mut cfg = Config::default();
        let t = table(&cfg);
        let builtin = McpTable::builtin();
        assert!(!builtin.servers.contains_key(DESKTOP_COMMANDER_PLUGIN));
        assert_eq!(
            t.servers[DESKTOP_COMMANDER_PLUGIN],
            builtin.servers["desktop-commander"]
        );
        // A configured entry stays, and one for the unsuffixed server does
        // not reach the plugin's.
        cfg.mcp
            .insert(DESKTOP_COMMANDER_PLUGIN, "read_file", tool(McpKind::None));
        cfg.mcp
            .insert("desktop-commander", "list_directory", tool(McpKind::None));
        let t = table(&cfg);
        let kind = |tool| t.entry(DESKTOP_COMMANDER_PLUGIN, tool).map(|e| e.kind);
        assert_eq!(kind("read_file"), Some(McpKind::None));
        assert_eq!(kind("list_directory"), Some(McpKind::Names));
    }

    #[test]
    fn on_unresolved_prefers_agent_then_shared_then_shell_setting() {
        use riskgrep_core::config::Action;
        let mut cfg = Config::default();
        assert_eq!(table(&cfg).on_unresolved, Some(Action::Allow));
        // `claude_code.on_unresolved` still covers MCP tools when no MCP
        // setting is made, as it did before `mcp.on_unresolved` existed.
        cfg.claude_code.on_unresolved = Action::Ask;
        assert_eq!(table(&cfg).on_unresolved, Some(Action::Ask));
        cfg.mcp.on_unresolved = Some(Action::Allow);
        assert_eq!(table(&cfg).on_unresolved, Some(Action::Allow));
        cfg.claude_code.mcp.on_unresolved = Some(Action::Deny);
        assert_eq!(table(&cfg).on_unresolved, Some(Action::Deny));
    }

    #[test]
    fn agent_section_entries_lay_over_shared_entries() {
        use riskgrep_core::config::Action;
        let mut cfg = Config::default();
        let decided = |a| McpTool {
            paths: Vec::new(),
            kind: McpKind::Read,
            max_depth: None,
            decision: Some(a),
        };
        cfg.mcp.insert("s", "*", decided(Action::Ask));
        cfg.mcp.insert("s", "x", decided(Action::Ask));
        cfg.claude_code.mcp.insert("s", "*", decided(Action::Deny));
        cfg.claude_code
            .mcp_tools
            .insert("mcp__s__x".into(), decided(Action::Allow));
        cfg.claude_code.mcp.insert("s", "x", decided(Action::Deny));
        let t = table(&cfg);
        let d = |n| entry(&cfg, &t, n).and_then(|e| e.decision);
        assert_eq!(d("mcp__s__y"), Some(Action::Deny));
        // `claude_code.mcp_tools` wins over `[claude_code.mcp]`.
        assert_eq!(d("mcp__s__x"), Some(Action::Allow));
    }
}
