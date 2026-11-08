//! MCP tool gating shared by every agent integration: entries keyed by
//! server and tool name (`[mcp]` in the configuration), the built-in
//! entries, and which paths a call names. An agent's adapter maps its own
//! tool names onto a server and a tool and turns the [`McpPlan`] into its
//! own decision format; nothing here depends on one agent's naming.

use crate::paths::{absolute, expand_tilde, readable_file};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What an MCP tool does with the paths its input names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum McpKind {
    /// Reads each named file; a directory or missing path reads nothing.
    #[default]
    Read,
    /// Reads every file under each named directory (a content search).
    Walk,
    /// Reveals the names of each named path and, for a directory, of the
    /// entries under it; judged by the path rules alone, as `Glob` is.
    Names,
    /// Reads no file; never gets a decision.
    None,
}

/// A tool entry: the input fields that hold a path or a list of paths,
/// and what the tool does with them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTool {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub kind: McpKind,
    /// For `names`: how deep under a directory names are revealed (1: its
    /// entries only). Unbounded when absent.
    pub max_depth: Option<usize>,
}

impl McpTool {
    /// Why the entry is unusable, if it is: a reading kind without fields.
    pub fn problem(&self) -> Option<&'static str> {
        (self.kind != McpKind::None
            && (self.paths.is_empty() || self.paths.iter().any(String::is_empty)))
        .then_some("needs `paths`, the input fields that hold paths")
    }
}

/// A `[mcp.servers."<server>"]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    /// Tool entries keyed by tool name; a key may contain `*`.
    #[serde(default)]
    pub tools: BTreeMap<String, McpTool>,
}

/// MCP entries keyed by server name, then tool name (`[mcp]`). A server
/// or tool key may contain `*`, which matches any run of characters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTable {
    #[serde(default)]
    pub servers: BTreeMap<String, McpServer>,
}

impl McpTable {
    /// `self` with every tool entry of `over` added, replacing an entry
    /// of the same server and tool key.
    pub fn overlay(&self, over: &McpTable) -> McpTable {
        let mut out = self.clone();
        out.merge(over.clone());
        out
    }

    /// Adds every tool entry of `over`, replacing an entry of the same
    /// server and tool key.
    pub fn merge(&mut self, over: McpTable) {
        for (server, s) in over.servers {
            self.servers
                .entry(server)
                .or_default()
                .tools
                .extend(s.tools);
        }
    }

    /// Adds `entry` for `server` and `tool`, replacing one with the same keys.
    pub fn insert(&mut self, server: &str, tool: &str, entry: McpTool) {
        self.servers
            .entry(server.to_string())
            .or_default()
            .tools
            .insert(tool.to_string(), entry);
    }

    /// The entry for `tool` of `server`. An exact server key wins over a
    /// pattern, then an exact tool key over a pattern; among keys equally
    /// specific, the first in key order that matches wins.
    pub fn entry(&self, server: &str, tool: &str) -> Option<&McpTool> {
        let mut best: Option<(u8, &McpTool)> = None;
        for (sk, s) in &self.servers {
            let Some(s_exact) = matches(sk, server) else {
                continue;
            };
            for (tk, t) in &s.tools {
                let Some(t_exact) = matches(tk, tool) else {
                    continue;
                };
                let rank = u8::from(!s_exact) * 2 + u8::from(!t_exact);
                if best.is_none_or(|(r, _)| rank < r) {
                    best = Some((rank, t));
                    if rank == 0 {
                        return Some(t);
                    }
                }
            }
        }
        best.map(|(_, t)| t)
    }

    /// Each entry's location and problem, for configuration errors.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (sk, s) in &self.servers {
            if sk.is_empty() {
                out.push("mcp.servers: a server name is empty".to_string());
            }
            for (tk, t) in &s.tools {
                if tk.is_empty() {
                    out.push(format!("mcp.servers.\"{sk}\": a tool name is empty"));
                } else if let Some(p) = t.problem() {
                    out.push(format!("mcp.servers.\"{sk}\".tools.\"{tk}\": {p}"));
                }
            }
        }
        out
    }

    /// The built-in entries. Field names are from each server's published
    /// input schemas:
    /// - the official filesystem server, `src/filesystem/server.ts` in
    ///   github.com/modelcontextprotocol/servers at commit 6d536b2e
    ///   (2026-10), under the server name `filesystem`;
    /// - Desktop Commander, the input schemas its server reported on
    ///   2026-10-25 (`read_file` and `get_file_info` take `path`,
    ///   `read_multiple_files` takes `paths`, `start_search` and
    ///   `list_directory` take `path`), under `desktop-commander` and under
    ///   `plugin_desktop-commander_desktop-commander`, the server name of
    ///   its Claude Code plugin.
    pub fn builtin() -> McpTable {
        use McpKind::{Names, None as Reads, Read};
        let t = |kind, field: &str, max_depth| McpTool {
            paths: if field.is_empty() {
                Vec::new()
            } else {
                vec![field.to_string()]
            },
            kind,
            max_depth,
        };
        let filesystem = [
            ("read_file", t(Read, "path", None)),
            ("read_text_file", t(Read, "path", None)),
            ("read_media_file", t(Read, "path", None)),
            ("read_multiple_files", t(Read, "paths", None)),
            ("list_directory", t(Names, "path", Some(1))),
            ("list_directory_with_sizes", t(Names, "path", Some(1))),
            ("directory_tree", t(Names, "path", None)),
            ("search_files", t(Names, "path", None)),
            ("get_file_info", t(Reads, "", None)),
            ("list_allowed_directories", t(Reads, "", None)),
            ("write_file", t(Reads, "", None)),
            ("edit_file", t(Reads, "", None)),
            ("create_directory", t(Reads, "", None)),
            ("move_file", t(Reads, "", None)),
        ];
        let desktop_commander = [
            ("read_file", t(Read, "path", None)),
            ("read_multiple_files", t(Read, "paths", None)),
            // A content search too is judged by the names it may reveal:
            // scanning every file under its path does not fit the time
            // budget.
            ("start_search", t(Names, "path", None)),
            ("list_directory", t(Names, "path", None)),
            ("get_file_info", t(Reads, "", None)),
        ];
        let mut out = McpTable::default();
        for (servers, tools) in [
            (&["filesystem"][..], &filesystem[..]),
            (
                &[
                    "desktop-commander",
                    "plugin_desktop-commander_desktop-commander",
                ][..],
                &desktop_commander[..],
            ),
        ] {
            for server in servers {
                for (tool, entry) in tools {
                    out.insert(server, tool, entry.clone());
                }
            }
        }
        out
    }

    /// What a call to `tool` of `server` with input `input` reads, with
    /// relative paths resolved against `cwd` and a leading `~` or `~/`
    /// expanded from `home`.
    pub fn plan(
        &self,
        server: &str,
        tool: &str,
        input: &Value,
        cwd: &Path,
        home: Option<&str>,
    ) -> McpPlan {
        let Some(entry) = self.entry(server, tool) else {
            return McpPlan::Unresolved;
        };
        if entry.kind == McpKind::None {
            return McpPlan::Nothing;
        }
        let Some(paths) = paths(input, &entry.paths, cwd, home) else {
            return McpPlan::Unresolved;
        };
        if paths.is_empty() {
            return McpPlan::Nothing;
        }
        match entry.kind {
            McpKind::Read => {
                let files: Vec<PathBuf> = paths.into_iter().filter_map(readable_file).collect();
                if files.is_empty() {
                    McpPlan::Nothing
                } else {
                    McpPlan::Read(files)
                }
            }
            McpKind::Walk => McpPlan::Walk(paths),
            McpKind::Names | McpKind::None => McpPlan::Names {
                roots: paths,
                max_depth: entry.max_depth,
            },
        }
    }
}

/// What an MCP call reads, from its entry and its input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum McpPlan {
    /// Reads no file: the entry's kind is `none`, its fields hold no path,
    /// or no named path is a file a `read` would open.
    Nothing,
    /// The files cannot be determined: the tool has no entry, or none of
    /// its fields is present, or one holds anything but a string or a list
    /// of strings.
    Unresolved,
    /// Reads these files (kind `read`; each exists and is not a directory).
    Read(Vec<PathBuf>),
    /// Reads the files under these paths (kind `walk`).
    Walk(Vec<PathBuf>),
    /// Reveals the names of these paths and the entries under them (kind
    /// `names`), to `max_depth` levels when set.
    Names {
        roots: Vec<PathBuf>,
        max_depth: Option<usize>,
    },
}

/// The paths in the fields `fields` of `input`, made absolute against
/// `cwd` with a leading `~` or `~/` expanded from `home`, and not trimmed.
/// `None` when they cannot be determined: no listed field is present, or a
/// present one is neither a string nor a list of strings.
pub fn paths(
    input: &Value,
    fields: &[String],
    cwd: &Path,
    home: Option<&str>,
) -> Option<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut found = false;
    for f in fields {
        let Some(v) = input.get(f.as_str()) else {
            continue;
        };
        found = true;
        let items: Vec<&str> = match v {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().map(Value::as_str).collect::<Option<_>>()?,
            _ => return None,
        };
        out.extend(
            items
                .into_iter()
                .map(|p| absolute(&expand_tilde(p, home), cwd)),
        );
    }
    found.then_some(out)
}

/// Whether key `key` matches `name`: `Some(true)` for an exact key,
/// `Some(false)` for a pattern that matches, `None` otherwise.
fn matches(key: &str, name: &str) -> Option<bool> {
    if key == name {
        Some(true)
    } else if key.contains('*') && wildcard(key, name) {
        Some(false)
    } else {
        None
    }
}

/// Whether `name` matches `pat`, where `*` stands for any run of
/// characters and every other character for itself.
pub fn wildcard(pat: &str, name: &str) -> bool {
    let mut parts = pat.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_whole_name() {
        assert!(wildcard("*__read", "a__read"));
        assert!(wildcard("*", ""));
        assert!(wildcard("a*b*c", "abc"));
        assert!(!wildcard("*__read", "a__read_more"));
        assert!(!wildcard("a", "ab"));
        assert!(!wildcard("*ab*ba", "aba"));
    }
}
