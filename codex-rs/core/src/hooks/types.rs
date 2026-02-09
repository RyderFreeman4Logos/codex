use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::DateTime;
use chrono::SecondsFormat;
use chrono::Utc;
use codex_protocol::ThreadId;
use futures::future::BoxFuture;
use serde::Serialize;
use serde::Serializer;
use serde_json::Value as JsonValue;

pub(crate) type HookFn =
    Arc<dyn for<'a> Fn(&'a HookPayload) -> BoxFuture<'a, HookResult> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Hook {
    pub(crate) func: HookFn,
    pub(crate) is_async: bool,
    /// When true, this hook only fires once per session.
    pub(crate) once: bool,
    /// Optional status message for UI display during execution.
    pub(crate) status_message: Option<String>,
}

impl Default for Hook {
    fn default() -> Self {
        Self {
            func: Arc::new(|_| Box::pin(async { HookResult::default() })),
            is_async: false,
            once: false,
            status_message: None,
        }
    }
}

impl Hook {
    pub(super) async fn execute(&self, payload: &HookPayload) -> HookResult {
        (self.func)(payload).await
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookPayload {
    pub(crate) session_id: ThreadId,
    pub(crate) cwd: PathBuf,
    #[serde(serialize_with = "serialize_triggered_at")]
    pub(crate) triggered_at: DateTime<Utc>,
    /// PascalCase event name matching Claude Code's wire protocol.
    pub(crate) hook_event_name: String,
    /// Path to the session transcript file, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) transcript_path: Option<PathBuf>,
    /// Current permission/approval mode (e.g. "on-request", "never").
    pub(crate) permission_mode: String,
    #[serde(flatten)]
    pub(crate) hook_event: HookEvent,
    /// Path to env file for SessionStart hooks to write KEY=VALUE pairs.
    #[serde(skip)]
    pub(crate) env_file_path: Option<PathBuf>,
}

impl HookPayload {
    pub(crate) fn new(
        session_id: ThreadId,
        cwd: PathBuf,
        hook_event: HookEvent,
        transcript_path: Option<PathBuf>,
        permission_mode: String,
    ) -> Self {
        Self {
            session_id,
            cwd,
            triggered_at: Utc::now(),
            hook_event_name: hook_event.hook_event_name().to_string(),
            transcript_path,
            permission_mode,
            hook_event,
            env_file_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventAfterAgent {
    pub thread_id: ThreadId,
    pub turn_id: String,
    pub input_messages: Vec<String>,
    pub last_assistant_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventPreToolUse {
    pub tool_name: String,
    pub tool_input: JsonValue,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventPostToolUse {
    pub tool_name: String,
    /// Called `tool_response` in Claude Code wire protocol (was `tool_output`).
    #[serde(rename = "tool_response")]
    pub tool_output: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventStop {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventUserPromptSubmit {
    /// Called `prompt` in Claude Code wire protocol (was `user_message`).
    #[serde(rename = "prompt")]
    pub user_message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventNotification {
    pub message: String,
    pub level: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventSessionStart {
    /// How the session was started (e.g. "cli", "api", "ide").
    pub source: String,
    /// Model name used for the session.
    pub model: String,
    /// Agent type (e.g. "codex", "claude-code").
    pub agent_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventSessionEnd {
    /// Reason the session ended (e.g. "user_exit", "max_turns", "error").
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventPermissionRequest {
    /// Tool name for which permission is requested.
    pub tool_name: String,
    /// The tool input/arguments as JSON.
    pub tool_input: JsonValue,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventPostToolUseFailure {
    /// Tool name that failed.
    pub tool_name: String,
    /// Error message or output from the failed tool.
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventSubagentStart {
    /// Type of sub-agent being started.
    pub agent_type: String,
    /// Task description or identifier.
    pub task: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventSubagentStop {
    /// Type of sub-agent being stopped.
    pub agent_type: String,
    /// Reason for stopping.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventPreCompact {
    /// What triggered the compact (e.g. "auto", "user", "context_limit").
    pub trigger: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct HookEventTaskCompleted {
    /// Summary of the completed task.
    pub summary: String,
}

fn serialize_triggered_at<S>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", rename_all = "PascalCase")]
pub(crate) enum HookEvent {
    AfterAgent {
        #[serde(flatten)]
        event: HookEventAfterAgent,
    },
    PreToolUse {
        #[serde(flatten)]
        event: HookEventPreToolUse,
    },
    PostToolUse {
        #[serde(flatten)]
        event: HookEventPostToolUse,
    },
    #[allow(dead_code)] // Integration point in codex.rs agent loop requires separate PR.
    Stop {
        #[serde(flatten)]
        event: HookEventStop,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    UserPromptSubmit {
        #[serde(flatten)]
        event: HookEventUserPromptSubmit,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    Notification {
        #[serde(flatten)]
        event: HookEventNotification,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    SessionStart {
        #[serde(flatten)]
        event: HookEventSessionStart,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    SessionEnd {
        #[serde(flatten)]
        event: HookEventSessionEnd,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    PermissionRequest {
        #[serde(flatten)]
        event: HookEventPermissionRequest,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    PostToolUseFailure {
        #[serde(flatten)]
        event: HookEventPostToolUseFailure,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    SubagentStart {
        #[serde(flatten)]
        event: HookEventSubagentStart,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    SubagentStop {
        #[serde(flatten)]
        event: HookEventSubagentStop,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    PreCompact {
        #[serde(flatten)]
        event: HookEventPreCompact,
    },
    #[allow(dead_code)] // Integration point requires architectural changes.
    TaskCompleted {
        #[serde(flatten)]
        event: HookEventTaskCompleted,
    },
}

impl HookEvent {
    /// Returns the PascalCase event name matching Claude Code's wire protocol.
    pub(crate) fn hook_event_name(&self) -> &'static str {
        match self {
            Self::AfterAgent { .. } => "AfterAgent",
            Self::PreToolUse { .. } => "PreToolUse",
            Self::PostToolUse { .. } => "PostToolUse",
            Self::Stop { .. } => "Stop",
            Self::UserPromptSubmit { .. } => "UserPromptSubmit",
            Self::Notification { .. } => "Notification",
            Self::SessionStart { .. } => "SessionStart",
            Self::SessionEnd { .. } => "SessionEnd",
            Self::PermissionRequest { .. } => "PermissionRequest",
            Self::PostToolUseFailure { .. } => "PostToolUseFailure",
            Self::SubagentStart { .. } => "SubagentStart",
            Self::SubagentStop { .. } => "SubagentStop",
            Self::PreCompact { .. } => "PreCompact",
            Self::TaskCompleted { .. } => "TaskCompleted",
        }
    }

    /// Whether this event type supports blocking (exit code 2 → Block).
    ///
    /// Non-blockable events treat exit code 2 as a warning and proceed.
    /// Per Claude Code spec, only the following events are blockable:
    /// PreToolUse, UserPromptSubmit, PermissionRequest, Stop.
    pub(crate) fn is_blockable(&self) -> bool {
        matches!(
            self,
            Self::PreToolUse { .. }
                | Self::UserPromptSubmit { .. }
                | Self::PermissionRequest { .. }
                | Self::Stop { .. }
        )
    }
}

/// Outcome of a hook execution that determines how the agent should proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HookOutcome {
    /// Hook completed; proceed with the operation normally.
    Proceed,
    /// Hook requests blocking the operation (e.g. deny a tool call).
    Block { message: Option<String> },
    /// Hook requests modifying the input or output content.
    Modify { content: String },
}

/// Metadata from hook command output that is orthogonal to the decision.
///
/// These fields are parsed from the hook's stdout JSON but are not part
/// of the proceed/block/modify decision flow. They are collected by the
/// aggregation layer (HookAggregateEffect) for downstream processing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HookOutputMeta {
    /// System message to inject into the conversation.
    pub system_message: Option<String>,
    /// Override the stop reason for Stop events.
    pub stop_reason: Option<String>,
    /// Whether to suppress the tool output from display.
    pub suppress_output: Option<bool>,
}

/// Combined result from a single hook execution: the decision + any metadata.
#[derive(Debug, Clone)]
pub(crate) struct HookResult {
    pub outcome: HookOutcome,
    pub meta: HookOutputMeta,
    /// Environment variables set by the hook via CLAUDE_ENV_FILE.
    pub env_vars: HashMap<String, String>,
}

impl Default for HookResult {
    fn default() -> Self {
        Self {
            outcome: HookOutcome::Proceed,
            meta: HookOutputMeta::default(),
            env_vars: HashMap::new(),
        }
    }
}

impl From<HookOutcome> for HookResult {
    fn from(outcome: HookOutcome) -> Self {
        Self {
            outcome,
            meta: HookOutputMeta::default(),
            env_vars: HashMap::new(),
        }
    }
}

/// Final action decided by the hook aggregation layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectAction {
    /// Continue with the operation normally.
    Proceed,
    /// Block the operation with a reason message.
    Block { reason: String },
    /// Stop processing further hooks but proceed with the operation.
    /// Maps to the Claude Code "skip" decision: remaining hooks are skipped
    /// but the operation itself is not blocked.
    #[allow(dead_code)] // Will be used when skip decision is wired up.
    StopProcessing,
}

/// Aggregated effect from running all matching hooks for an event.
///
/// Produced by the registry after running every hook registered for an event
/// and combining their individual outcomes. Carries the final action decision
/// plus any metadata collected from hook command outputs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HookAggregateEffect {
    /// The final action: proceed, block, or stop processing.
    pub action: EffectAction,
    /// System messages collected from hook outputs (injected into conversation).
    pub system_messages: Vec<String>,
    /// Additional context strings from hook outputs.
    #[allow(dead_code)] // Will be populated when additional_context field is wired up.
    pub additional_context: Vec<String>,
    /// Modified content from a Modify decision (raw string).
    /// When set, the caller should apply this as the new tool input/arguments.
    pub modified_content: Option<String>,
    /// Whether to suppress tool output display (any hook can set this).
    pub suppress_output: bool,
    /// Override stop reason for Stop events (last writer wins).
    pub stop_reason: Option<String>,
    /// Status messages collected from hooks that provide them.
    pub status_messages: Vec<String>,
    /// Accumulated environment variables from all hooks (later hooks override earlier ones for same key).
    pub env_vars: HashMap<String, String>,
}

impl Default for HookAggregateEffect {
    fn default() -> Self {
        Self {
            action: EffectAction::Proceed,
            system_messages: Vec::new(),
            additional_context: Vec::new(),
            modified_content: None,
            suppress_output: false,
            stop_reason: None,
            status_messages: Vec::new(),
            env_vars: HashMap::new(),
        }
    }
}

impl HookAggregateEffect {
    /// Create a Block effect with a reason.
    #[allow(dead_code)] // Convenience constructor; direct construction is also valid.
    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            action: EffectAction::Block {
                reason: reason.into(),
            },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::TimeZone;
    use chrono::Utc;
    use codex_protocol::ThreadId;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::HookEvent;
    use super::HookEventAfterAgent;
    use super::HookPayload;

    #[test]
    fn hook_payload_serializes_stable_wire_shape() {
        let session_id = ThreadId::new();
        let thread_id = ThreadId::new();
        let hook_event = HookEvent::AfterAgent {
            event: HookEventAfterAgent {
                thread_id,
                turn_id: "turn-1".to_string(),
                input_messages: vec!["hello".to_string()],
                last_assistant_message: Some("hi".to_string()),
            },
        };
        let payload = HookPayload {
            session_id,
            cwd: PathBuf::from("tmp"),
            triggered_at: Utc
                .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            hook_event_name: hook_event.hook_event_name().to_string(),
            transcript_path: None,
            permission_mode: "on-request".to_string(),
            hook_event,
            env_file_path: None,
        };

        let actual = serde_json::to_value(payload).expect("serialize hook payload");
        let expected = json!({
            "session_id": session_id.to_string(),
            "cwd": "tmp",
            "triggered_at": "2025-01-01T00:00:00Z",
            "hook_event_name": "AfterAgent",
            "permission_mode": "on-request",
            "event_type": "AfterAgent",
            "thread_id": thread_id.to_string(),
            "turn_id": "turn-1",
            "input_messages": ["hello"],
            "last_assistant_message": "hi",
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_payload_with_transcript_path_serializes() {
        let session_id = ThreadId::new();
        let hook_event = HookEvent::PreToolUse {
            event: super::HookEventPreToolUse {
                tool_name: "bash".to_string(),
                tool_input: json!({}),
            },
        };
        let payload = HookPayload {
            session_id,
            cwd: PathBuf::from("/tmp"),
            triggered_at: Utc
                .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
                .single()
                .expect("valid timestamp"),
            hook_event_name: hook_event.hook_event_name().to_string(),
            transcript_path: Some(PathBuf::from("/tmp/transcript.jsonl")),
            permission_mode: "never".to_string(),
            hook_event,
            env_file_path: None,
        };

        let actual = serde_json::to_value(payload).expect("serialize");
        assert_eq!(actual["hook_event_name"], "PreToolUse");
        assert_eq!(actual["transcript_path"], "/tmp/transcript.jsonl");
        assert_eq!(actual["permission_mode"], "never");
    }

    #[test]
    fn hook_event_pre_tool_use_serializes_with_flattened_fields() {
        use super::HookEventPreToolUse;

        let hook_event = HookEvent::PreToolUse {
            event: HookEventPreToolUse {
                tool_name: "bash".to_string(),
                tool_input: json!({"command": "ls"}),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize pre_tool_use event");
        let expected = json!({
            "event_type": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_post_tool_use_serializes_correctly() {
        use super::HookEventPostToolUse;

        let hook_event = HookEvent::PostToolUse {
            event: HookEventPostToolUse {
                tool_name: "bash".to_string(),
                tool_output: "file1.txt\nfile2.txt".to_string(),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize post_tool_use event");
        let expected = json!({
            "event_type": "PostToolUse",
            "tool_name": "bash",
            "tool_response": "file1.txt\nfile2.txt",
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_stop_serializes_correctly() {
        use super::HookEventStop;

        let hook_event = HookEvent::Stop {
            event: HookEventStop {
                reason: "max_tokens_reached".to_string(),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize stop event");
        let expected = json!({
            "event_type": "Stop",
            "reason": "max_tokens_reached",
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_user_prompt_submit_serializes_correctly() {
        use super::HookEventUserPromptSubmit;

        let hook_event = HookEvent::UserPromptSubmit {
            event: HookEventUserPromptSubmit {
                user_message: "Help me debug this code".to_string(),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize user_prompt_submit event");
        let expected = json!({
            "event_type": "UserPromptSubmit",
            "prompt": "Help me debug this code",
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_notification_serializes_correctly() {
        use super::HookEventNotification;

        let hook_event = HookEvent::Notification {
            event: HookEventNotification {
                message: "Build completed successfully".to_string(),
                level: "info".to_string(),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize notification event");
        let expected = json!({
            "event_type": "Notification",
            "message": "Build completed successfully",
            "level": "info",
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_session_start_serializes_correctly() {
        use super::HookEventSessionStart;

        let hook_event = HookEvent::SessionStart {
            event: HookEventSessionStart {
                source: "cli".to_string(),
                model: "claude-opus-4-6".to_string(),
                agent_type: "codex".to_string(),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize session_start event");
        let expected = json!({
            "event_type": "SessionStart",
            "source": "cli",
            "model": "claude-opus-4-6",
            "agent_type": "codex",
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_permission_request_serializes_correctly() {
        use super::HookEventPermissionRequest;

        let hook_event = HookEvent::PermissionRequest {
            event: HookEventPermissionRequest {
                tool_name: "Edit".to_string(),
                tool_input: json!({"file_path": "/tmp/test.txt", "content": "new content"}),
            },
        };

        let actual = serde_json::to_value(&hook_event).expect("serialize permission_request event");
        let expected = json!({
            "event_type": "PermissionRequest",
            "tool_name": "Edit",
            "tool_input": {"file_path": "/tmp/test.txt", "content": "new content"},
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn hook_event_post_tool_use_failure_serializes_correctly() {
        use super::HookEventPostToolUseFailure;

        let hook_event = HookEvent::PostToolUseFailure {
            event: HookEventPostToolUseFailure {
                tool_name: "Bash".to_string(),
                error: "Command failed with exit code 1".to_string(),
            },
        };

        let actual =
            serde_json::to_value(&hook_event).expect("serialize post_tool_use_failure event");
        let expected = json!({
            "event_type": "PostToolUseFailure",
            "tool_name": "Bash",
            "error": "Command failed with exit code 1",
        });

        assert_eq!(actual, expected);
    }
}
