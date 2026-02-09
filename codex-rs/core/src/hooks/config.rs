use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use super::executor::command_hook;
use super::types::Hook;

/// Single hook entry from configuration.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct HookEntryToml {
    /// The command to execute as argv (program + args).
    pub command: Vec<String>,

    /// Optional timeout in seconds (default: 600, matching Claude Code).
    #[serde(default = "default_timeout_secs")]
    pub timeout: u64,

    /// Optional regex pattern for tool-use hooks.
    ///
    /// Special values:
    /// - `None`, empty string, or `"*"` matches all tool names
    /// - Any other string is compiled as a regex pattern
    ///
    /// Examples:
    /// - `"^Bash$"` matches exactly "Bash"
    /// - `"mcp__.*__write.*"` matches MCP write tools
    /// - `"shell.*"` matches tool names starting with "shell"
    ///
    /// If regex compilation fails, a warning is logged and the hook won't match any tools.
    #[serde(default)]
    pub matcher: Option<String>,
}

fn default_timeout_secs() -> u64 {
    600
}

/// All hook entries grouped by event type.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct HooksConfigToml {
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

    #[serde(default)]
    pub session_start: Vec<HookEntryToml>,

    #[serde(default)]
    pub session_end: Vec<HookEntryToml>,

    #[serde(default)]
    pub permission_request: Vec<HookEntryToml>,

    #[serde(default)]
    pub post_tool_use_failure: Vec<HookEntryToml>,

    #[serde(default)]
    pub subagent_start: Vec<HookEntryToml>,

    #[serde(default)]
    pub subagent_stop: Vec<HookEntryToml>,

    #[serde(default)]
    pub pre_compact: Vec<HookEntryToml>,

    #[serde(default)]
    pub task_completed: Vec<HookEntryToml>,
}

/// Extract the field that the matcher regex should match against for a given event.
///
/// Different event types have different matchable fields:
/// - PreToolUse/PostToolUse/PostToolUseFailure/PermissionRequest → tool_name
/// - SessionStart → source
/// - SessionEnd → reason
/// - Notification → level (used as notification_type)
/// - SubagentStart/SubagentStop → agent_type
/// - PreCompact → trigger
/// - AfterAgent/UserPromptSubmit/Stop/TaskCompleted → None (matcher not supported)
fn matcher_field_for_event(event: &super::types::HookEvent) -> Option<&str> {
    use super::types::HookEvent;
    match event {
        HookEvent::PreToolUse { event } => Some(&event.tool_name),
        HookEvent::PostToolUse { event } => Some(&event.tool_name),
        HookEvent::PostToolUseFailure { event } => Some(&event.tool_name),
        HookEvent::PermissionRequest { event } => Some(&event.tool_name),
        HookEvent::SessionStart { event } => Some(&event.source),
        HookEvent::SessionEnd { event } => Some(&event.reason),
        HookEvent::Notification { event } => Some(&event.level),
        HookEvent::SubagentStart { event } => Some(&event.agent_type),
        HookEvent::SubagentStop { event } => Some(&event.agent_type),
        HookEvent::PreCompact { event } => Some(&event.trigger),
        HookEvent::AfterAgent { .. }
        | HookEvent::UserPromptSubmit { .. }
        | HookEvent::Stop { .. }
        | HookEvent::TaskCompleted { .. } => None,
    }
}

/// Convert a single HookEntryToml into a Hook via the command executor.
///
/// If the entry has a matcher pattern, the hook will only execute for events
/// whose matchable field matches the regex pattern. Events without matchable
/// fields always execute.
pub(super) fn hook_from_entry(entry: &HookEntryToml) -> Hook {
    let timeout = Duration::from_secs(entry.timeout);
    let inner = command_hook(entry.command.clone(), timeout);
    match &entry.matcher {
        None => inner,
        Some(pattern) if pattern.is_empty() || pattern == "*" => inner,
        Some(pattern) => {
            // Pre-compile the regex once and share it via Arc
            let regex = match Regex::new(pattern) {
                Ok(re) => Some(Arc::new(re)),
                Err(e) => {
                    tracing::warn!(
                        pattern = %pattern,
                        error = %e,
                        "Invalid regex pattern in hook matcher, hook will not match any events"
                    );
                    None
                }
            };

            Hook {
                func: Arc::new(move |payload| {
                    let matchable = matcher_field_for_event(&payload.hook_event);

                    if let Some(name) = matchable {
                        // If regex compilation failed or doesn't match, skip execution
                        if regex.as_ref().is_some_and(|re| re.is_match(name)) {
                            inner.func.clone()(payload)
                        } else {
                            Box::pin(async { super::types::HookResult::default() })
                        }
                    } else {
                        // Events without matchable fields always execute
                        inner.func.clone()(payload)
                    }
                }),
            }
        }
    }
}

/// Check if a tool name matches a regex pattern.
///
/// Special cases:
/// - `None`, empty string, or `"*"` matches all tool names
/// - Any other string is compiled as a regex and matched against the tool name
///
/// Returns false if the regex compilation fails.
#[cfg(test)]
fn matches_pattern(pattern: &str, tool_name: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    match Regex::new(pattern) {
        Ok(re) => re.is_match(tool_name),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    /// Check if a tool name matches a hook entry's matcher pattern.
    /// If matcher is None, the hook matches all tools.
    fn matches_tool(entry: &HookEntryToml, tool_name: &str) -> bool {
        match &entry.matcher {
            None => true,
            Some(pattern) => matches_pattern(pattern, tool_name),
        }
    }

    #[test]
    fn test_hook_entry_deserialize_minimal() {
        let toml_str = r#"
            command = ["./hook.sh"]
        "#;
        let entry: HookEntryToml = toml::from_str(toml_str).unwrap();
        assert_eq!(entry.command, vec!["./hook.sh"]);
        assert_eq!(entry.timeout, 600); // default
        assert_eq!(entry.matcher, None); // default
    }

    #[test]
    fn test_hook_entry_deserialize_full() {
        let toml_str = r#"
            command = ["./pre-tool.sh", "--verbose"]
            timeout = 60
            matcher = "shell.*"
        "#;
        let entry: HookEntryToml = toml::from_str(toml_str).unwrap();
        assert_eq!(entry.command, vec!["./pre-tool.sh", "--verbose"]);
        assert_eq!(entry.timeout, 60);
        assert_eq!(entry.matcher, Some("shell.*".to_string()));
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
        assert!(config.session_start.is_empty());
        assert!(config.session_end.is_empty());
        assert!(config.permission_request.is_empty());
        assert!(config.post_tool_use_failure.is_empty());
        assert!(config.subagent_start.is_empty());
        assert!(config.subagent_stop.is_empty());
        assert!(config.pre_compact.is_empty());
        assert!(config.task_completed.is_empty());
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
        assert_eq!(config.after_agent[1].timeout, 600); // default
    }

    #[test]
    fn test_matches_tool_none_matches_all() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 600,
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
            timeout: 600,
            matcher: Some("^shell$".to_string()),
        };
        assert!(matches_tool(&entry, "shell"));
        assert!(!matches_tool(&entry, "shell_exec"));
        assert!(!matches_tool(&entry, "read"));
    }

    #[test]
    fn test_matches_tool_regex_prefix() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 600,
            matcher: Some("shell.*".to_string()),
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
            timeout: 600,
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
            timeout: 600,
            matcher: Some("^read$".to_string()),
        };
        assert!(matches_tool(&entry, "read"));
        assert!(!matches_tool(&entry, "write"));
        assert!(!matches_tool(&entry, "read_file"));
    }

    #[test]
    fn test_hooks_config_deserialize_pre_tool_use() {
        let toml_str = r#"
            [[pre_tool_use]]
            command = ["./validate-tool.sh"]
            timeout = 10
            matcher = "bash.*"

            [[pre_tool_use]]
            command = ["./log-tool.sh", "--verbose"]
            matcher = "*"
        "#;
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert_eq!(config.pre_tool_use.len(), 2);
        assert_eq!(config.pre_tool_use[0].command, vec!["./validate-tool.sh"]);
        assert_eq!(config.pre_tool_use[0].timeout, 10);
        assert_eq!(config.pre_tool_use[0].matcher, Some("bash.*".to_string()));
        assert_eq!(
            config.pre_tool_use[1].command,
            vec!["./log-tool.sh", "--verbose"]
        );
        assert_eq!(config.pre_tool_use[1].matcher, Some("*".to_string()));
    }

    #[test]
    fn test_hooks_config_full_deserialize() {
        let toml_str = r#"
            [[after_agent]]
            command = ["./notify.sh"]

            [[pre_tool_use]]
            command = ["./pre-tool.sh"]
            matcher = "^bash$"

            [[post_tool_use]]
            command = ["./post-tool.sh"]

            [[notification]]
            command = ["./notify-desktop.sh"]

            [[stop]]
            command = ["./cleanup.sh"]

            [[user_prompt_submit]]
            command = ["./log-prompt.sh"]
        "#;
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert_eq!(config.after_agent.len(), 1);
        assert_eq!(config.pre_tool_use.len(), 1);
        assert_eq!(config.post_tool_use.len(), 1);
        assert_eq!(config.notification.len(), 1);
        assert_eq!(config.stop.len(), 1);
        assert_eq!(config.user_prompt_submit.len(), 1);
    }

    #[test]
    fn test_matches_tool_mcp_pattern() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 600,
            matcher: Some("mcp__.*__write.*".to_string()),
        };
        assert!(matches_tool(&entry, "mcp__memory__write_note"));
        assert!(matches_tool(&entry, "mcp__storage__write_file"));
        assert!(matches_tool(&entry, "mcp__db__write_record"));
        assert!(!matches_tool(&entry, "mcp__memory__read_note"));
        assert!(!matches_tool(&entry, "read"));
    }

    #[test]
    fn test_matches_tool_exact_with_anchors() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 600,
            matcher: Some("^Bash$".to_string()),
        };
        assert!(matches_tool(&entry, "Bash"));
        assert!(!matches_tool(&entry, "bash"));
        assert!(!matches_tool(&entry, "BashScript"));
        assert!(!matches_tool(&entry, "MyBash"));
    }

    #[test]
    fn test_matches_tool_empty_string_matches_all() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 600,
            matcher: Some("".to_string()),
        };
        assert!(matches_tool(&entry, "anything"));
        assert!(matches_tool(&entry, "Bash"));
        assert!(matches_tool(&entry, "mcp__memory__write"));
    }

    #[test]
    fn test_matches_tool_invalid_regex() {
        let entry = HookEntryToml {
            command: vec!["./hook.sh".to_string()],
            timeout: 600,
            matcher: Some("[invalid(".to_string()),
        };
        // Invalid regex should not match anything
        assert!(!matches_tool(&entry, "anything"));
        assert!(!matches_tool(&entry, "Bash"));
    }

    #[test]
    fn test_hooks_config_deserialize_new_events() {
        let toml_str = r#"
            [[session_start]]
            command = ["./on-start.sh"]
            matcher = "cli"

            [[session_end]]
            command = ["./on-end.sh"]

            [[permission_request]]
            command = ["./on-permission.sh"]
            matcher = "^Bash$"

            [[post_tool_use_failure]]
            command = ["./on-failure.sh"]

            [[subagent_start]]
            command = ["./on-subagent.sh"]
            matcher = "researcher.*"

            [[subagent_stop]]
            command = ["./on-subagent-stop.sh"]

            [[pre_compact]]
            command = ["./on-compact.sh"]
            matcher = "auto"

            [[task_completed]]
            command = ["./on-task-done.sh"]
        "#;
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert_eq!(config.session_start.len(), 1);
        assert_eq!(config.session_end.len(), 1);
        assert_eq!(config.permission_request.len(), 1);
        assert_eq!(config.post_tool_use_failure.len(), 1);
        assert_eq!(config.subagent_start.len(), 1);
        assert_eq!(config.subagent_stop.len(), 1);
        assert_eq!(config.pre_compact.len(), 1);
        assert_eq!(config.task_completed.len(), 1);
    }

    #[tokio::test]
    async fn test_hook_from_entry_creates_working_hook() {
        let entry = HookEntryToml {
            command: vec!["echo".to_string(), "test".to_string()],
            timeout: 5,
            matcher: None,
        };

        let hook = hook_from_entry(&entry);

        // Create a minimal payload to test hook execution
        use super::super::types::HookEvent;
        use super::super::types::HookEventAfterAgent;
        use super::super::types::HookPayload;
        use chrono::TimeZone;
        use chrono::Utc;
        use codex_protocol::ThreadId;
        use std::path::PathBuf;

        let hook_event = HookEvent::AfterAgent {
            event: HookEventAfterAgent {
                thread_id: ThreadId::new(),
                turn_id: "test".to_string(),
                input_messages: vec!["test".to_string()],
                last_assistant_message: None,
            },
        };
        let payload = HookPayload {
            session_id: ThreadId::new(),
            cwd: PathBuf::from("/tmp"),
            triggered_at: Utc
                .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            hook_event_name: hook_event.hook_event_name().to_string(),
            transcript_path: None,
            permission_mode: "on-request".to_string(),
            hook_event,
        };

        // Hook should execute without panicking
        let result = hook.execute(&payload).await;

        // command_hook returns Proceed on success
        use super::super::types::HookOutcome;
        assert_eq!(result.outcome, HookOutcome::Proceed);
    }
}
