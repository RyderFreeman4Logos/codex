use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use super::executor::command_hook;
use super::types::Hook;

/// Command specification supporting both shell string and argv formats.
///
/// - Shell string: `command = "bash ./check.sh"` → executed via `sh -c "bash ./check.sh"`
/// - Argv array: `command = ["bash", "./check.sh"]` → executed directly
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum CommandSpec {
    /// Shell command string, executed via `sh -c` (or `cmd /C` on Windows).
    Shell(String),
    /// Explicit argv array, executed directly.
    Argv(Vec<String>),
}

impl Default for CommandSpec {
    fn default() -> Self {
        Self::Argv(Vec::new())
    }
}

/// Single hook entry from configuration (legacy/internal format).
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct HookEntryToml {
    /// The command to execute, either as a shell string or argv array.
    pub command: CommandSpec,

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

/// Single command in a matcher group (new grouped format).
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct HookCommandToml {
    /// The command to execute, either as a shell string or argv array.
    pub command: CommandSpec,

    /// Optional timeout in seconds (default: 600, matching Claude Code).
    #[serde(default = "default_timeout_secs")]
    pub timeout: u64,
}

/// Matcher group with optional pattern and multiple commands.
///
/// Supports both new grouped format and old flat format for backward compatibility:
///
/// New format (recommended):
/// ```toml
/// [[pre_tool_use]]
/// matcher = "^Bash$"
///
/// [[pre_tool_use.commands]]
/// command = ["./hook1.sh"]
/// timeout = 30
///
/// [[pre_tool_use.commands]]
/// command = ["./hook2.sh"]
/// ```
///
/// Old format (backward compatible):
/// ```toml
/// [[pre_tool_use]]
/// command = ["./hook.sh"]
/// timeout = 60
/// matcher = "^Bash$"
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct MatcherGroupToml {
    /// Optional regex pattern for event matching (same semantics as before).
    ///
    /// Special values:
    /// - `None`, empty string, or `"*"` matches all events
    /// - Any other string is compiled as a regex pattern
    #[serde(default)]
    pub matcher: Option<String>,

    /// Handler commands in this group (new grouped format).
    #[serde(default)]
    pub commands: Vec<HookCommandToml>,

    /// Single command (old flat format, for backward compatibility).
    /// If present, this group is treated as a single-command group.
    #[serde(default)]
    pub command: Option<CommandSpec>,

    /// Timeout for the command (old flat format, applies when `command` is present).
    #[serde(default = "default_timeout_secs")]
    pub timeout: u64,
}

fn default_timeout_secs() -> u64 {
    600
}

/// All hook entries grouped by event type.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct HooksConfigToml {
    /// When `true`, all hooks are disabled regardless of per-event entries.
    #[serde(default)]
    pub disable_all_hooks: bool,

    #[serde(default)]
    pub after_agent: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub pre_tool_use: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub post_tool_use: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub notification: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub stop: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub user_prompt_submit: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub session_start: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub session_end: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub permission_request: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub post_tool_use_failure: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub subagent_start: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub subagent_stop: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub pre_compact: Vec<MatcherGroupToml>,

    #[serde(default)]
    pub task_completed: Vec<MatcherGroupToml>,
}

impl HooksConfigToml {
    /// Merge hooks from another config layer (appending, not overwriting).
    ///
    /// Hooks from `other` are appended after `self`'s hooks for each event.
    /// If either layer has `disable_all_hooks: true`, the merged result also disables all hooks.
    pub fn merge_from(&mut self, other: HooksConfigToml) {
        self.disable_all_hooks = self.disable_all_hooks || other.disable_all_hooks;
        self.after_agent.extend(other.after_agent);
        self.pre_tool_use.extend(other.pre_tool_use);
        self.post_tool_use.extend(other.post_tool_use);
        self.notification.extend(other.notification);
        self.stop.extend(other.stop);
        self.user_prompt_submit.extend(other.user_prompt_submit);
        self.session_start.extend(other.session_start);
        self.session_end.extend(other.session_end);
        self.permission_request.extend(other.permission_request);
        self.post_tool_use_failure.extend(other.post_tool_use_failure);
        self.subagent_start.extend(other.subagent_start);
        self.subagent_stop.extend(other.subagent_stop);
        self.pre_compact.extend(other.pre_compact);
        self.task_completed.extend(other.task_completed);
    }
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

/// Convert a MatcherGroupToml into a Vec<Hook>.
///
/// Supports both formats:
/// - Old flat format: if `command` field is present, produce a single hook
/// - New grouped format: if `commands` array is present, produce one hook per command
/// - If both are empty, produce no hooks
///
/// All hooks in the group share the same matcher pattern.
pub(super) fn hooks_from_group(group: &MatcherGroupToml) -> Vec<Hook> {
    // Old flat format: command field is present
    if let Some(ref cmd) = group.command {
        let entry = HookEntryToml {
            command: cmd.clone(),
            timeout: group.timeout,
            matcher: group.matcher.clone(),
        };
        return vec![hook_from_entry(&entry)];
    }

    // New grouped format: commands array
    group
        .commands
        .iter()
        .map(|hook_cmd| {
            let entry = HookEntryToml {
                command: hook_cmd.command.clone(),
                timeout: hook_cmd.timeout,
                matcher: group.matcher.clone(),
            };
            hook_from_entry(&entry)
        })
        .collect()
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

    /// Check if a tool name matches a matcher group's matcher pattern.
    /// If matcher is None, the hook matches all tools.
    fn matches_tool(group: &MatcherGroupToml, tool_name: &str) -> bool {
        match &group.matcher {
            None => true,
            Some(pattern) => matches_pattern(pattern, tool_name),
        }
    }

    #[test]
    fn test_matcher_group_deserialize_old_flat_minimal() {
        let toml_str = r#"
            command = ["./hook.sh"]
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(
            group.command,
            Some(CommandSpec::Argv(vec!["./hook.sh".to_string()]))
        );
        assert_eq!(group.timeout, 600); // default
        assert_eq!(group.matcher, None); // default
        assert!(group.commands.is_empty());
    }

    #[test]
    fn test_matcher_group_deserialize_old_flat_full() {
        let toml_str = r#"
            command = ["./pre-tool.sh", "--verbose"]
            timeout = 60
            matcher = "shell.*"
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(
            group.command,
            Some(CommandSpec::Argv(vec![
                "./pre-tool.sh".to_string(),
                "--verbose".to_string()
            ]))
        );
        assert_eq!(group.timeout, 60);
        assert_eq!(group.matcher, Some("shell.*".to_string()));
        assert!(group.commands.is_empty());
    }

    #[test]
    fn test_matcher_group_deserialize_old_flat_shell_string() {
        let toml_str = r#"
            command = "bash ./check.sh"
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(
            group.command,
            Some(CommandSpec::Shell("bash ./check.sh".to_string()))
        );
        assert_eq!(group.timeout, 600);
        assert_eq!(group.matcher, None);
        assert!(group.commands.is_empty());
    }

    #[test]
    fn test_matcher_group_deserialize_old_flat_shell_with_options() {
        let toml_str = r#"
            command = "echo hello world"
            timeout = 30
            matcher = "^Bash$"
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(
            group.command,
            Some(CommandSpec::Shell("echo hello world".to_string()))
        );
        assert_eq!(group.timeout, 30);
        assert_eq!(group.matcher, Some("^Bash$".to_string()));
        assert!(group.commands.is_empty());
    }

    #[test]
    fn test_matcher_group_deserialize_new_grouped_single_command() {
        let toml_str = r#"
            matcher = "^Bash$"

            [[commands]]
            command = ["./hook.sh"]
            timeout = 30
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(group.matcher, Some("^Bash$".to_string()));
        assert_eq!(group.command, None);
        assert_eq!(group.commands.len(), 1);
        assert_eq!(
            group.commands[0].command,
            CommandSpec::Argv(vec!["./hook.sh".to_string()])
        );
        assert_eq!(group.commands[0].timeout, 30);
    }

    #[test]
    fn test_matcher_group_deserialize_new_grouped_multiple_commands() {
        let toml_str = r#"
            matcher = "^Bash$"

            [[commands]]
            command = ["./hook1.sh"]
            timeout = 30

            [[commands]]
            command = ["./hook2.sh"]
            timeout = 60
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(group.matcher, Some("^Bash$".to_string()));
        assert_eq!(group.command, None);
        assert_eq!(group.commands.len(), 2);
        assert_eq!(
            group.commands[0].command,
            CommandSpec::Argv(vec!["./hook1.sh".to_string()])
        );
        assert_eq!(group.commands[0].timeout, 30);
        assert_eq!(
            group.commands[1].command,
            CommandSpec::Argv(vec!["./hook2.sh".to_string()])
        );
        assert_eq!(group.commands[1].timeout, 60);
    }

    #[test]
    fn test_matcher_group_deserialize_new_grouped_no_matcher() {
        let toml_str = r#"
            [[commands]]
            command = ["./hook.sh"]
        "#;
        let group: MatcherGroupToml = toml::from_str(toml_str).unwrap();
        assert_eq!(group.matcher, None);
        assert_eq!(group.command, None);
        assert_eq!(group.commands.len(), 1);
        assert_eq!(
            group.commands[0].command,
            CommandSpec::Argv(vec!["./hook.sh".to_string()])
        );
        assert_eq!(group.commands[0].timeout, 600); // default
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
    fn test_hooks_config_deserialize_after_agent_old_format() {
        let toml_str = r#"
            [[after_agent]]
            command = ["./hook1.sh"]
            timeout = 45

            [[after_agent]]
            command = ["./hook2.sh"]
        "#;
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert_eq!(config.after_agent.len(), 2);
        assert_eq!(
            config.after_agent[0].command,
            Some(CommandSpec::Argv(vec!["./hook1.sh".to_string()]))
        );
        assert_eq!(config.after_agent[0].timeout, 45);
        assert_eq!(
            config.after_agent[1].command,
            Some(CommandSpec::Argv(vec!["./hook2.sh".to_string()]))
        );
        assert_eq!(config.after_agent[1].timeout, 600); // default
    }

    #[test]
    fn test_matches_tool_none_matches_all() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: None,
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "shell"));
        assert!(matches_tool(&group, "read"));
        assert!(matches_tool(&group, "write"));
    }

    #[test]
    fn test_matches_tool_exact() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("^shell$".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "shell"));
        assert!(!matches_tool(&group, "shell_exec"));
        assert!(!matches_tool(&group, "read"));
    }

    #[test]
    fn test_matches_tool_regex_prefix() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("shell.*".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "shell"));
        assert!(matches_tool(&group, "shell_exec"));
        assert!(matches_tool(&group, "shell_command"));
        assert!(!matches_tool(&group, "read"));
    }

    #[test]
    fn test_matches_tool_wildcard() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("*".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "shell"));
        assert!(matches_tool(&group, "read"));
        assert!(matches_tool(&group, "write"));
        assert!(matches_tool(&group, "anything"));
    }

    #[test]
    fn test_matches_tool_no_match() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("^read$".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "read"));
        assert!(!matches_tool(&group, "write"));
        assert!(!matches_tool(&group, "read_file"));
    }

    #[test]
    fn test_hooks_config_deserialize_pre_tool_use_old_format() {
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
        assert_eq!(
            config.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./validate-tool.sh".to_string()]))
        );
        assert_eq!(config.pre_tool_use[0].timeout, 10);
        assert_eq!(config.pre_tool_use[0].matcher, Some("bash.*".to_string()));
        assert_eq!(
            config.pre_tool_use[1].command,
            Some(CommandSpec::Argv(vec![
                "./log-tool.sh".to_string(),
                "--verbose".to_string()
            ]))
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
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("mcp__.*__write.*".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "mcp__memory__write_note"));
        assert!(matches_tool(&group, "mcp__storage__write_file"));
        assert!(matches_tool(&group, "mcp__db__write_record"));
        assert!(!matches_tool(&group, "mcp__memory__read_note"));
        assert!(!matches_tool(&group, "read"));
    }

    #[test]
    fn test_matches_tool_exact_with_anchors() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("^Bash$".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "Bash"));
        assert!(!matches_tool(&group, "bash"));
        assert!(!matches_tool(&group, "BashScript"));
        assert!(!matches_tool(&group, "MyBash"));
    }

    #[test]
    fn test_matches_tool_empty_string_matches_all() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("".to_string()),
            commands: Vec::new(),
        };
        assert!(matches_tool(&group, "anything"));
        assert!(matches_tool(&group, "Bash"));
        assert!(matches_tool(&group, "mcp__memory__write"));
    }

    #[test]
    fn test_matches_tool_invalid_regex() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 600,
            matcher: Some("[invalid(".to_string()),
            commands: Vec::new(),
        };
        // Invalid regex should not match anything
        assert!(!matches_tool(&group, "anything"));
        assert!(!matches_tool(&group, "Bash"));
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

    #[test]
    fn test_hooks_from_group_old_flat_format() {
        let group = MatcherGroupToml {
            command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
            timeout: 30,
            matcher: Some("^Bash$".to_string()),
            commands: Vec::new(),
        };
        let hooks = hooks_from_group(&group);
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn test_hooks_from_group_new_grouped_format_single() {
        let group = MatcherGroupToml {
            command: None,
            timeout: 600,
            matcher: Some("^Bash$".to_string()),
            commands: vec![HookCommandToml {
                command: CommandSpec::Argv(vec!["./hook.sh".to_string()]),
                timeout: 30,
            }],
        };
        let hooks = hooks_from_group(&group);
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn test_hooks_from_group_new_grouped_format_multiple() {
        let group = MatcherGroupToml {
            command: None,
            timeout: 600,
            matcher: Some("^Bash$".to_string()),
            commands: vec![
                HookCommandToml {
                    command: CommandSpec::Argv(vec!["./hook1.sh".to_string()]),
                    timeout: 30,
                },
                HookCommandToml {
                    command: CommandSpec::Argv(vec!["./hook2.sh".to_string()]),
                    timeout: 60,
                },
            ],
        };
        let hooks = hooks_from_group(&group);
        assert_eq!(hooks.len(), 2);
    }

    #[test]
    fn test_hooks_from_group_empty() {
        let group = MatcherGroupToml {
            command: None,
            timeout: 600,
            matcher: Some("^Bash$".to_string()),
            commands: Vec::new(),
        };
        let hooks = hooks_from_group(&group);
        assert_eq!(hooks.len(), 0);
    }

    #[test]
    fn test_hooks_config_mixed_format() {
        let toml_str = r#"
            # Old flat format
            [[pre_tool_use]]
            command = ["./old-hook.sh"]
            matcher = "^Bash$"

            # New grouped format
            [[pre_tool_use]]
            matcher = "^Read$"

            [[pre_tool_use.commands]]
            command = ["./new-hook1.sh"]

            [[pre_tool_use.commands]]
            command = ["./new-hook2.sh"]
        "#;
        let config: HooksConfigToml = toml::from_str(toml_str).unwrap();
        assert_eq!(config.pre_tool_use.len(), 2);

        // First group: old flat format
        assert_eq!(
            config.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./old-hook.sh".to_string()]))
        );
        assert_eq!(config.pre_tool_use[0].matcher, Some("^Bash$".to_string()));
        assert!(config.pre_tool_use[0].commands.is_empty());

        // Second group: new grouped format
        assert_eq!(config.pre_tool_use[1].command, None);
        assert_eq!(config.pre_tool_use[1].matcher, Some("^Read$".to_string()));
        assert_eq!(config.pre_tool_use[1].commands.len(), 2);
    }

    #[tokio::test]
    async fn test_hook_from_entry_creates_working_hook() {
        let entry = HookEntryToml {
            command: CommandSpec::Argv(vec!["echo".to_string(), "test".to_string()]),
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

    #[test]
    fn test_merge_from_appends_hooks() {
        let mut base = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./base-hook.sh".to_string()])),
                timeout: 600,
                matcher: Some("^Bash$".to_string()),
                commands: Vec::new(),
            }],
            after_agent: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./base-after.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        let other = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./other-hook.sh".to_string()])),
                timeout: 600,
                matcher: Some("^Read$".to_string()),
                commands: Vec::new(),
            }],
            post_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./post-hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        base.merge_from(other);

        // pre_tool_use should have both hooks (base first, then other)
        assert_eq!(base.pre_tool_use.len(), 2);
        assert_eq!(
            base.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./base-hook.sh".to_string()]))
        );
        assert_eq!(
            base.pre_tool_use[1].command,
            Some(CommandSpec::Argv(vec!["./other-hook.sh".to_string()]))
        );

        // after_agent should only have base hook (no new hooks from other)
        assert_eq!(base.after_agent.len(), 1);
        assert_eq!(
            base.after_agent[0].command,
            Some(CommandSpec::Argv(vec!["./base-after.sh".to_string()]))
        );

        // post_tool_use should only have other's hook
        assert_eq!(base.post_tool_use.len(), 1);
        assert_eq!(
            base.post_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./post-hook.sh".to_string()]))
        );
    }

    #[test]
    fn test_merge_from_disable_all_hooks() {
        let mut base = HooksConfigToml {
            disable_all_hooks: false,
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        let other = HooksConfigToml {
            disable_all_hooks: true,
            ..Default::default()
        };

        base.merge_from(other);

        assert!(base.disable_all_hooks);
    }

    #[test]
    fn test_merge_from_both_disable_all_hooks() {
        let mut base = HooksConfigToml {
            disable_all_hooks: true,
            ..Default::default()
        };

        let other = HooksConfigToml {
            disable_all_hooks: false,
            ..Default::default()
        };

        base.merge_from(other);

        // Should remain true (logical OR)
        assert!(base.disable_all_hooks);
    }

    #[test]
    fn test_merge_from_empty_base() {
        let mut base = HooksConfigToml::default();

        let other = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        base.merge_from(other);

        assert_eq!(base.pre_tool_use.len(), 1);
        assert_eq!(
            base.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./hook.sh".to_string()]))
        );
    }

    #[test]
    fn test_merge_from_empty_other() {
        let mut base = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        let other = HooksConfigToml::default();

        base.merge_from(other);

        // Should remain unchanged
        assert_eq!(base.pre_tool_use.len(), 1);
        assert_eq!(
            base.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./hook.sh".to_string()]))
        );
    }

    #[test]
    fn test_merge_from_order_preservation() {
        let mut global = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./global-hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        let project = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./project-hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        let local = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./local-hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };

        // Merge in order: global -> project -> local
        global.merge_from(project);
        global.merge_from(local);

        // Hooks should run in order: global, project, local
        assert_eq!(global.pre_tool_use.len(), 3);
        assert_eq!(
            global.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./global-hook.sh".to_string()]))
        );
        assert_eq!(
            global.pre_tool_use[1].command,
            Some(CommandSpec::Argv(vec!["./project-hook.sh".to_string()]))
        );
        assert_eq!(
            global.pre_tool_use[2].command,
            Some(CommandSpec::Argv(vec!["./local-hook.sh".to_string()]))
        );
    }
}
