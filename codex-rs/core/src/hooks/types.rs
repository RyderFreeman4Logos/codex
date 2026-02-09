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
    Arc<dyn for<'a> Fn(&'a HookPayload) -> BoxFuture<'a, HookOutcome> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Hook {
    pub(crate) func: HookFn,
}

impl Default for Hook {
    fn default() -> Self {
        Self {
            func: Arc::new(|_| Box::pin(async { HookOutcome::Proceed })),
        }
    }
}

impl Hook {
    pub(super) async fn execute(&self, payload: &HookPayload) -> HookOutcome {
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
}
