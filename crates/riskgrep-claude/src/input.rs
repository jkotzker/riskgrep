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

    #[test]
    fn rejects_malformed() {
        assert!(parse(b"nope").is_err());
        assert!(parse(b"[1]").is_err());
        assert!(parse(br#"{"tool_input":{}}"#).is_err());
    }
}
