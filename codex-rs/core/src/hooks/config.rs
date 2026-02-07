use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

use super::executor::command_hook;
use super::types::Hook;

/// Single hook entry from configuration.
#[allow(dead_code)] // Will be used when hook config integration is added
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEntryToml {
    /// The command to execute as argv (program + args).
    pub command: Vec<String>,

    /// Optional timeout in seconds (default: 30).
    #[serde(default = "default_timeout_secs")]
    pub timeout: u64,

    /// Optional matcher pattern for tool-use hooks (glob pattern matching tool name).
    #[serde(default)]
    pub matcher: Option<String>,
}

#[allow(dead_code)] // Will be used when hook config integration is added
fn default_timeout_secs() -> u64 {
    30
}

/// All hook entries grouped by event type.
#[allow(dead_code)] // Will be used when hook config integration is added
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HooksConfigToml {
    #[serde(default)]
    pub after_agent: Vec<HookEntryToml>,

    #[serde(default)]
    pub pre_tool_use: Vec<HookEntryToml>,

    #[serde(default)]
    pub post_tool_use: Vec<HookEntryToml>,

    #[serde(default)]
    pub notification: Vec<HookEntryToml>,

    #[serde(default)]
    pub stop: Vec<HookEntryToml>,

    #[serde(default)]
    pub user_prompt_submit: Vec<HookEntryToml>,
}

/// Convert a single HookEntryToml into a Hook via the command executor.
#[allow(dead_code)] // Will be used when hook config integration is added
pub(super) fn hook_from_entry(entry: &HookEntryToml) -> Hook {
    let timeout = Duration::from_secs(entry.timeout);
    command_hook(entry.command.clone(), timeout)
}

/// Check if a tool name matches a hook's matcher pattern.
/// If matcher is None, the hook matches all tools.
/// Supports simple glob patterns: "*" matches anything, "shell*" matches "shell", "shell_exec", etc.
#[allow(dead_code)] // Will be used when hook config integration is added
pub(super) fn matches_tool(entry: &HookEntryToml, tool_name: &str) -> bool {
    match &entry.matcher {
        None => true,
        Some(pattern) => {
            if pattern == "*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix('*') {
                return tool_name.starts_with(prefix);
            }
            pattern == tool_name
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_hook_entry_deserialize_minimal() {
        let toml_str = r#"
            command = ["./hook.sh"]
        "#;
        let entry: HookEntryToml = toml::from_str(toml_str).unwrap();
        assert_eq!(entry.command, vec!["./hook.sh"]);
        assert_eq!(entry.timeout, 30); // default
        assert_eq!(entry.matcher, None); // default
    }

    #[test]
    fn test_hook_entry_deserialize_full() {
        let toml_str = r#"
            command = ["./pre-tool.sh", "--verbose"]
            timeout = 60
            matcher = "shell*"
        "#;
        let entry: HookEntryToml = toml::from_str(toml_str).unwrap();
        assert_eq!(entry.command, vec!["./pre-tool.sh", "--verbose"]);
        assert_eq!(entry.timeout, 60);
        assert_eq!(entry.matcher, Some("shell*".to_string()));
    }

    #[test]
    fn test_hooks_config_deserialize_empty() {
        let toml_str = "";
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert!(config.after_agent.is_empty());
        assert!(config.pre_tool_use.is_empty());
        assert!(config.post_tool_use.is_empty());
        assert!(config.notification.is_empty());
        assert!(config.stop.is_empty());
        assert!(config.user_prompt_submit.is_empty());
    }

    #[test]
    fn test_hooks_config_deserialize_after_agent() {
        let toml_str = r#"
            [[after_agent]]
            command = ["./hook1.sh"]
            timeout = 45

            [[after_agent]]
            command = ["./hook2.sh"]
        "#;
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert_eq!(config.after_agent.len(), 2);
        assert_eq!(config.after_agent[0].command, vec!["./hook1.sh"]);
        assert_eq!(config.after_agent[0].timeout, 45);
        assert_eq!(config.after_agent[1].command, vec!["./hook2.sh"]);
        assert_eq!(config.after_agent[1].timeout, 30); // default
    }

    #[test]
    fn test_matches_tool_none_matches_all() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 30,
            matcher: None,
        };
        assert!(matches_tool(&entry, "shell"));
        assert!(matches_tool(&entry, "read"));
        assert!(matches_tool(&entry, "write"));
    }

    #[test]
    fn test_matches_tool_exact() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 30,
            matcher: Some("shell".to_string()),
        };
        assert!(matches_tool(&entry, "shell"));
        assert!(!matches_tool(&entry, "shell_exec"));
        assert!(!matches_tool(&entry, "read"));
    }

    #[test]
    fn test_matches_tool_glob_prefix() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 30,
            matcher: Some("shell*".to_string()),
        };
        assert!(matches_tool(&entry, "shell"));
        assert!(matches_tool(&entry, "shell_exec"));
        assert!(matches_tool(&entry, "shell_command"));
        assert!(!matches_tool(&entry, "read"));
    }

    #[test]
    fn test_matches_tool_wildcard() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 30,
            matcher: Some("*".to_string()),
        };
        assert!(matches_tool(&entry, "shell"));
        assert!(matches_tool(&entry, "read"));
        assert!(matches_tool(&entry, "write"));
        assert!(matches_tool(&entry, "anything"));
    }

    #[test]
    fn test_matches_tool_no_match() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 30,
            matcher: Some("read".to_string()),
        };
        assert!(matches_tool(&entry, "read"));
        assert!(!matches_tool(&entry, "write"));
        assert!(!matches_tool(&entry, "read_file"));
    }
}
