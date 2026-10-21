//! The `PreToolUse` hook input read from standard input.

use serde_json::Value;
use std::path::PathBuf;

/// The fields of the hook input RiskGrep uses.
#[derive(Debug, Clone)]
pub struct HookInput {
    pub tool_name: String,
    pub tool_input: Value,
    pub cwd: Option<PathBuf>,
    pub event: Option<String>,
}

impl HookInput {
    /// A string field of `tool_input`.
    pub fn str_field(&self, name: &str) -> Option<&str> {
        self.tool_input.get(name).and_then(Value::as_str)
    }
}

/// The lines a `Read` call asks for: 1-based and inclusive, `last` `None`
/// for the end of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lines {
    pub first: u64,
    pub last: Option<u64>,
}

/// The lines a `Read` call asks for through `offset` and `limit`, or `None`
/// when the whole file must be judged: another tool, neither field given,
/// or either field anything but a positive integer. Claude Code 2.1.301
/// reads `limit` lines starting at line `offset` (1-based; it reads 0 as 1),
/// defaulting `offset` to 1 and `limit` to the end of the file.
pub fn requested_lines(input: &HookInput) -> Option<Lines> {
    if input.tool_name != "Read" {
        return None;
    }
    let obj = input.tool_input.as_object()?;
    let positive = |key: &str| -> Result<Option<u64>, ()> {
        match obj.get(key) {
            None => Ok(None),
            Some(v) => v.as_u64().filter(|&n| n >= 1).map(Some).ok_or(()),
        }
    };
    let (Ok(offset), Ok(limit)) = (positive("offset"), positive("limit")) else {
        return None;
    };
    if offset.is_none() && limit.is_none() {
        return None;
    }
    let first = offset.unwrap_or(1);
    Some(Lines {
        first,
        last: limit.map(|l| first.saturating_add(l - 1)),
    })
}

/// Parses the hook input; an error names what was wrong, never the content.
pub fn parse(bytes: &[u8]) -> Result<HookInput, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| "not valid JSON".to_string())?;
    let obj = v.as_object().ok_or("not a JSON object")?;
    let tool_name = obj
        .get("tool_name")
        .and_then(Value::as_str)
        .ok_or("no tool_name")?
        .to_string();
    Ok(HookInput {
        tool_name,
        tool_input: obj.get("tool_input").cloned().unwrap_or(Value::Null),
        cwd: obj
            .get("cwd")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .map(PathBuf::from),
        event: obj
            .get("hook_event_name")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields() {
        let i = parse(br#"{"tool_name":"Read","tool_input":{"file_path":"/a"},"cwd":"/w","hook_event_name":"PreToolUse"}"#)
            .unwrap();
        assert_eq!(i.tool_name, "Read");
        assert_eq!(i.str_field("file_path"), Some("/a"));
        assert_eq!(i.cwd, Some(PathBuf::from("/w")));
    }

    fn read(tool_input: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: "Read".into(),
            tool_input,
            cwd: None,
            event: None,
        }
    }

    #[test]
    fn requested_lines_from_offset_and_limit() {
        use serde_json::json;
        let lines = |v| requested_lines(&read(v));
        let at = |first, last| Some(Lines { first, last });
        assert_eq!(
            lines(json!({"file_path": "/a", "offset": 1, "limit": 8})),
            at(1, Some(8))
        );
        assert_eq!(
            lines(json!({"file_path": "/a", "offset": 12, "limit": 10})),
            at(12, Some(21))
        );
        // A limit alone starts at line 1; an offset alone runs to the end.
        assert_eq!(
            lines(json!({"file_path": "/a", "limit": 5})),
            at(1, Some(5))
        );
        assert_eq!(lines(json!({"file_path": "/a", "offset": 7})), at(7, None));
        // Neither: the whole file.
        assert_eq!(lines(json!({"file_path": "/a"})), None);
        // Any doubt: the whole file.
        for bad in [
            json!({"offset": 0, "limit": 5}),
            json!({"offset": 3, "limit": 0}),
            json!({"offset": -1}),
            json!({"limit": -4}),
            json!({"offset": 2.0, "limit": 5}),
            json!({"offset": 2.5}),
            json!({"offset": "3", "limit": 5}),
            json!({"offset": null, "limit": 5}),
            json!({"offset": 3, "limit": true}),
            json!({"offset": 1e30}),
        ] {
            assert_eq!(lines(bad.clone()), None, "{bad}");
        }
        // Saturates instead of overflowing.
        assert_eq!(
            lines(json!({"offset": u64::MAX, "limit": u64::MAX})),
            at(u64::MAX, Some(u64::MAX))
        );
    }

    #[test]
    fn requested_lines_only_for_read() {
        use serde_json::json;
        for tool in ["Grep", "Bash", "NotebookRead"] {
            let mut i = read(json!({"file_path": "/a", "offset": 1, "limit": 8}));
            i.tool_name = tool.into();
            assert_eq!(requested_lines(&i), None, "{tool}");
        }
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse(b"nope").is_err());
        assert!(parse(b"[1]").is_err());
        assert!(parse(br#"{"tool_input":{}}"#).is_err());
    }
}
