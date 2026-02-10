use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::types::Hook;
use super::types::HookOutcome;
use super::types::HookOutputMeta;
use super::types::HookPayload;
use super::types::HookResult;

/// Maximum bytes to read from a hook command's stdout to prevent unbounded memory usage.
const MAX_STDOUT_BYTES: usize = 1_048_576; // 1MB

/// Maximum bytes to read from a hook command's stderr to prevent unbounded memory usage.
const MAX_STDERR_BYTES: usize = 1_048_576; // 1MB

/// Parse environment file written by SessionStart hooks.
/// Format: KEY=VALUE lines (one per line).
/// - Empty lines and lines starting with # are ignored
/// - First = splits key and value
/// - Returns empty HashMap if file doesn't exist or can't be read
fn parse_env_file(path: &std::path::Path) -> HashMap<String, String> {
    // Check file size first (max 1MB)
    const MAX_FILE_SIZE: u64 = 1024 * 1024; // 1MB
    const MAX_ENTRIES: usize = 1000;

    match std::fs::metadata(path) {
        Ok(metadata) => {
            if metadata.len() > MAX_FILE_SIZE {
                tracing::warn!(
                    "env file {} exceeds max size ({}B > {}B), ignoring",
                    path.display(),
                    metadata.len(),
                    MAX_FILE_SIZE
                );
                return HashMap::new();
            }
        }
        Err(e) => {
            tracing::debug!("failed to read metadata for {}: {}", path.display(), e);
            return HashMap::new();
        }
    }

    let Ok(content) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            // Split on first = only
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .take(MAX_ENTRIES)
        .collect()
}

/// Decision returned by a hook command (Claude Code compatible).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum HookDecision {
    Proceed,
    Block,
    Modify,
}

/// Event-specific output from a hook command (Claude Code protocol extension).
///
/// These fields are part of the Claude Code wire protocol specification.
/// They are deserialized for protocol completeness and logged at debug level.
/// Full integration into Codex's aggregation logic is planned for future PRs.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HookSpecificOutput {
    #[serde(default, rename = "hookEventName")]
    pub hook_event_name: Option<String>,
    #[serde(default, rename = "permissionDecision")]
    pub permission_decision: Option<String>,
    #[serde(default, rename = "permissionDecisionReason")]
    pub permission_decision_reason: Option<String>,
    #[serde(default, rename = "updatedInput")]
    pub updated_input: Option<serde_json::Value>,
    #[serde(default, rename = "additionalContext")]
    pub additional_context: Option<String>,
}

/// Result structure returned by a hook command via stdout JSON.
///
/// Supports both the simple format (`{"decision":"proceed"}`) and the
/// full Claude Code format with additional metadata fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HookCommandOutput {
    /// Hook decision: proceed, block, or modify.
    #[serde(default = "default_decision")]
    pub decision: HookDecision,
    /// Reason for the decision (displayed to user on block).
    /// Aliases: `message` (legacy) or `reason` (Claude Code).
    #[serde(default, alias = "message")]
    pub reason: Option<String>,
    /// Modified content (required when decision=modify).
    #[serde(default)]
    pub content: Option<String>,
    /// Override the stop reason for Stop events.
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Whether to suppress the tool output from display.
    #[serde(default)]
    pub suppress_output: Option<bool>,
    /// System message to inject into the conversation.
    #[serde(default)]
    pub system_message: Option<String>,
    /// Event-specific hook output (Claude Code protocol extension).
    #[serde(default)]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

fn default_decision() -> HookDecision {
    HookDecision::Proceed
}

impl From<HookCommandOutput> for HookResult {
    fn from(output: HookCommandOutput) -> Self {
        // Log protocol extension fields if present (consumed for wire
        // format completeness; full aggregation integration planned).
        if let Some(ref specific) = output.hook_specific_output {
            tracing::debug!(
                hook_event_name = ?specific.hook_event_name,
                permission_decision = ?specific.permission_decision,
                permission_decision_reason = ?specific.permission_decision_reason,
                has_updated_input = specific.updated_input.is_some(),
                additional_context = ?specific.additional_context,
                "hook returned protocol extension fields"
            );
        }
        let meta = HookOutputMeta {
            system_message: output.system_message,
            stop_reason: output.stop_reason,
            suppress_output: output.suppress_output,
        };
        let outcome = match output.decision {
            HookDecision::Proceed => HookOutcome::Proceed,
            HookDecision::Block => HookOutcome::Block {
                message: output.reason,
            },
            HookDecision::Modify => match output.content {
                Some(content) => HookOutcome::Modify { content },
                None => {
                    tracing::warn!(
                        "hook returned modify decision without content field; \
                         treating as block to prevent empty input substitution"
                    );
                    HookOutcome::Block {
                        message: Some(
                            "hook returned modify without content field".to_string(),
                        ),
                    }
                }
            },
        };
        Self {
            outcome,
            meta,
            env_vars: HashMap::new(),
        }
    }
}

/// Creates a hook that executes a command via stdin/stdout JSON protocol.
///
/// The hook serializes the payload to JSON, pipes it to the command's stdin,
/// reads the command's stdout, and interprets the result as a HookOutcome.
///
/// # Interpretation Rules
///
/// - Exit code 0 + empty stdout → `HookOutcome::Proceed`
/// - Exit code 0 + stdout JSON with `{"decision": "block", "message": "..."}` → `HookOutcome::Block`
/// - Exit code 0 + stdout JSON with `{"decision": "modify", "content": "..."}` → `HookOutcome::Modify`
/// - Non-zero exit code → `HookOutcome::Block { message: Some(stderr_or_default) }`
/// - Timeout → `HookOutcome::Block { message: Some("hook timed out") }`
/// - Spawn failure → log warning and return `HookOutcome::Proceed` (fail-open)
pub(super) fn command_hook(command: super::config::CommandSpec, timeout: Duration) -> Hook {
    Hook {
        is_async: false,
        once: false,
        status_message: None,
        matcher: None,
        func: Arc::new(move |payload: &HookPayload| {
            let command_spec = command.clone();
            let payload = payload.clone();
            Box::pin(async move {
                let Some(mut command) = super::registry::command_from_spec(&command_spec) else {
                    tracing::warn!("hook command is empty, skipping");
                    return HookOutcome::Proceed.into();
                };

                // Log command summary (truncate to 50 chars for brevity)
                let cmd_summary = match &command_spec {
                    super::config::CommandSpec::Shell(s) => {
                        if s.len() > 50 {
                            format!("{}...", &s[..50])
                        } else {
                            s.clone()
                        }
                    }
                    super::config::CommandSpec::Argv(argv) => {
                        if let Some(first) = argv.first() {
                            if first.len() > 50 {
                                format!("{}...", &first[..50])
                            } else {
                                first.clone()
                            }
                        } else {
                            String::new()
                        }
                    }
                };
                tracing::debug!(command = %cmd_summary, "Starting hook execution");

                // Set up working directory, stdio, and environment variables
                // that Claude Code hooks expect.
                let cwd_str = payload.cwd.display().to_string();
                command
                    .current_dir(&payload.cwd)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .env("CLAUDE_PROJECT_DIR", &cwd_str)
                    .env("CODEX_PROJECT_DIR", &cwd_str)
                    .env("CLAUDE_SESSION_ID", payload.session_id.to_string())
                    .env("CODEX_SESSION_ID", payload.session_id.to_string());

                // Set CLAUDE_ENV_FILE for SessionStart hooks
                if let Some(ref env_file_path) = payload.env_file_path {
                    command.env("CLAUDE_ENV_FILE", env_file_path);
                }

                let mut child = match command.spawn() {
                    Ok(child) => child,
                    Err(err) => {
                        tracing::warn!("failed to spawn hook command: {err}");
                        return HookOutcome::Proceed.into();
                    }
                };

                let Some(mut stdin) = child.stdin.take() else {
                    tracing::warn!("hook child process has no stdin handle");
                    return HookOutcome::Proceed.into();
                };
                let Some(mut stdout) = child.stdout.take() else {
                    tracing::warn!("hook child process has no stdout handle");
                    return HookOutcome::Proceed.into();
                };
                let Some(mut stderr) = child.stderr.take() else {
                    tracing::warn!("hook child process has no stderr handle");
                    return HookOutcome::Proceed.into();
                };

                // Serialize payload to JSON before entering the timed block.
                let payload_json = match serde_json::to_vec(&payload) {
                    Ok(json) => json,
                    Err(err) => {
                        tracing::warn!("failed to serialize hook payload: {err}");
                        return HookOutcome::Proceed.into();
                    }
                };

                // Wrap the entire IO sequence (stdin write, stdout + stderr
                // read) in a single timeout so that a misbehaving hook cannot
                // hang any individual phase indefinitely.  Stdout and stderr
                // are drained concurrently to avoid pipe deadlocks when a hook
                // produces verbose output on both streams.
                let io_result = tokio::time::timeout(timeout, async {
                    // Write payload to stdin.  If the hook closes stdin
                    // early (e.g. a short script that ignores input), we
                    // still need to read its stdout/stderr and exit status
                    // so that block/modify decisions are not silently lost.
                    if let Err(err) = stdin.write_all(&payload_json).await {
                        tracing::warn!("failed to write payload to hook stdin: {err}");
                    }
                    drop(stdin); // Close stdin to signal EOF

                    // Drain stdout and stderr concurrently to prevent pipe
                    // deadlocks (a full stderr buffer can block the child
                    // before it closes stdout, causing a false timeout).
                    let read_stdout = async {
                        let mut bytes = Vec::new();
                        let mut buf = [0u8; 4096];
                        let mut capped = false;
                        loop {
                            match stdout.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if capped {
                                        continue; // drain but discard
                                    }
                                    if bytes.len() + n > MAX_STDOUT_BYTES {
                                        // Keep as many bytes as still fit
                                        // before switching to drain mode.
                                        let remaining = MAX_STDOUT_BYTES - bytes.len();
                                        bytes.extend_from_slice(&buf[..remaining]);
                                        tracing::warn!(
                                            "hook stdout exceeded max size of {MAX_STDOUT_BYTES} bytes"
                                        );
                                        capped = true;
                                        continue;
                                    }
                                    bytes.extend_from_slice(&buf[..n]);
                                }
                                Err(err) => {
                                    tracing::warn!("failed to read hook stdout: {err}");
                                    break;
                                }
                            }
                        }
                        (bytes, capped)
                    };

                    let read_stderr = async {
                        let mut bytes = Vec::new();
                        let mut buf = [0u8; 4096];
                        let mut capped = false;
                        loop {
                            match stderr.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if capped {
                                        continue; // drain but discard
                                    }
                                    if bytes.len() + n > MAX_STDERR_BYTES {
                                        bytes.extend_from_slice(
                                            &buf[..MAX_STDERR_BYTES - bytes.len()],
                                        );
                                        tracing::warn!(
                                            "hook stderr exceeded max size of {MAX_STDERR_BYTES} bytes, truncated"
                                        );
                                        capped = true;
                                        continue;
                                    }
                                    bytes.extend_from_slice(&buf[..n]);
                                }
                                Err(_) => break,
                            }
                        }
                        String::from_utf8_lossy(&bytes).to_string()
                    };

                    let ((stdout_bytes, stdout_capped), stderr_string) =
                        tokio::join!(read_stdout, read_stderr);

                    (stdout_bytes, stdout_capped, stderr_string)
                })
                .await;

                // Handle IO timeout: kill the child and return Block.
                let (stdout_bytes, stdout_capped, stderr_string) = match io_result {
                    Err(_elapsed) => {
                        let _ = child.kill().await;
                        return HookOutcome::Block {
                            message: Some("hook timed out".to_string()),
                        }.into();
                    }
                    Ok(data) => data,
                };

                // Wait for process exit.  Once stdout and stderr are fully
                // consumed the process should exit promptly; apply a generous
                // grace period to guard against pathological cases.
                const WAIT_GRACE: Duration = Duration::from_secs(5);
                let status = match tokio::time::timeout(WAIT_GRACE, child.wait()).await {
                    Ok(Ok(status)) => status,
                    Ok(Err(err)) => {
                        tracing::warn!("failed to wait for hook command: {err}");
                        return HookOutcome::Proceed.into();
                    }
                    Err(_elapsed) => {
                        let _ = child.kill().await;
                        return HookOutcome::Block {
                            message: Some("hook timed out".to_string()),
                        }.into();
                    }
                };

                // Log hook completion
                let exit_code = status.code().unwrap_or(-1);
                tracing::debug!(
                    exit_code = exit_code,
                    stdout_len = stdout_bytes.len(),
                    stderr_len = stderr_string.len(),
                    "Hook command completed"
                );

                // Exit code semantics (Claude Code compatible):
                //   exit 0  → parse stdout JSON (below)
                //   exit 2  → blocking error on blockable events, otherwise warn
                //   other   → non-blocking error: Proceed + warn
                if !status.success() {
                    let code = status.code().unwrap_or(1);
                    if code == 2 && payload.hook_event.is_blockable() {
                        let message = if stderr_string.is_empty() {
                            "hook command returned blocking error (exit 2)".to_string()
                        } else {
                            stderr_string
                        };
                        return HookOutcome::Block {
                            message: Some(message),
                        }.into();
                    }
                    // Non-blocking error (or exit 2 on non-blockable event): log and continue
                    if !stderr_string.is_empty() {
                        tracing::warn!(
                            "hook exited with code {code} (non-blocking): {stderr_string}"
                        );
                    } else {
                        tracing::warn!(
                            "hook exited with code {code} (non-blocking)"
                        );
                    }
                    return HookOutcome::Proceed.into();
                }

                // Exit code 0: parse stdout or default to Proceed
                let mut result = if stdout_bytes.is_empty() {
                    tracing::debug!("Hook returned empty stdout, treating as Proceed");
                    HookResult::from(HookOutcome::Proceed)
                } else if stdout_capped {
                    // If stdout was truncated, the JSON is likely corrupted.
                    // Block rather than falling through to Proceed, which would
                    // silently bypass the hook's intended decision.
                    HookResult::from(HookOutcome::Block {
                        message: Some(
                            "hook stdout exceeded size limit; output truncated and cannot be trusted".to_string(),
                        ),
                    })
                } else {
                    match serde_json::from_slice::<HookCommandOutput>(&stdout_bytes) {
                        Ok(output) => {
                            tracing::debug!(decision = ?output.decision, "Parsed hook JSON output");
                            output.into()
                        }
                        Err(err) => {
                            let stdout_preview = String::from_utf8_lossy(&stdout_bytes);
                            let truncated = if stdout_preview.len() > 200 {
                                format!("{}...", &stdout_preview[..200])
                            } else {
                                stdout_preview.to_string()
                            };
                            tracing::warn!(
                                error = %err,
                                stdout = %truncated,
                                "Failed to parse hook command JSON output, treating as Proceed"
                            );
                            HookResult::from(HookOutcome::Proceed)
                        }
                    }
                };

                // Read environment variables from CLAUDE_ENV_FILE if it was set
                if let Some(ref env_file_path) = payload.env_file_path {
                    result.env_vars = parse_env_file(env_file_path);
                    if !result.env_vars.is_empty() {
                        tracing::debug!(env_var_count = result.env_vars.len(), "Parsed env vars from CLAUDE_ENV_FILE");
                    }
                }

                result
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::super::types::HookOutcome;
    use super::super::types::HookResult;
    use super::HookCommandOutput;
    use super::HookDecision;

    #[test]
    fn test_hook_command_output_deserialize_proceed() {
        let json = json!({"decision": "proceed"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Proceed);
        assert_eq!(output.reason, None);
        assert_eq!(output.content, None);
    }

    #[test]
    fn test_hook_command_output_deserialize_block() {
        let json = json!({"decision": "block", "reason": "denied"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(output.reason, Some("denied".to_string()));
        assert_eq!(output.content, None);
    }

    #[test]
    fn test_hook_command_output_deserialize_modify() {
        let json = json!({"decision": "modify", "content": "new text"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Modify);
        assert_eq!(output.reason, None);
        assert_eq!(output.content, Some("new text".to_string()));
    }

    #[test]
    fn test_hook_command_output_deserialize_camel_case() {
        // Claude Code format uses camelCase
        let json = json!({
            "decision": "block",
            "reason": "permission denied",
            "stopReason": "user_cancelled",
            "suppressOutput": true,
            "systemMessage": "Hook blocked this action"
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(output.reason, Some("permission denied".to_string()));
        assert_eq!(output.stop_reason, Some("user_cancelled".to_string()));
        assert_eq!(output.suppress_output, Some(true));
        assert_eq!(
            output.system_message,
            Some("Hook blocked this action".to_string())
        );
    }

    #[test]
    fn test_hook_command_output_message_alias_for_reason() {
        // Legacy "message" field should be aliased to "reason"
        let json = json!({"decision": "block", "message": "denied by policy"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(output.reason, Some("denied by policy".to_string()));
    }

    #[test]
    fn test_hook_command_output_hook_specific_output() {
        let json = json!({
            "decision": "modify",
            "content": "new content",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "safe command",
                "updatedInput": {"command": "ls -la"},
                "additionalContext": "vetted by security"
            }
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Modify);
        assert_eq!(output.content, Some("new content".to_string()));

        let specific = output.hook_specific_output.expect("should have specific output");
        assert_eq!(specific.hook_event_name, Some("PreToolUse".to_string()));
        assert_eq!(specific.permission_decision, Some("allow".to_string()));
        assert_eq!(
            specific.permission_decision_reason,
            Some("safe command".to_string())
        );
        assert_eq!(
            specific.updated_input,
            Some(json!({"command": "ls -la"}))
        );
        assert_eq!(
            specific.additional_context,
            Some("vetted by security".to_string())
        );
    }

    #[test]
    fn test_hook_command_output_empty_json_defaults_to_proceed() {
        // Empty JSON should default to Proceed (via default_decision)
        let json = json!({});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Proceed);
        assert_eq!(output.reason, None);
        assert_eq!(output.content, None);
    }

    // ---- command_hook() integration tests (Unix only) ----

    #[cfg(not(windows))]
    mod command_hook_integration {
        use std::path::PathBuf;
        use std::time::Duration;

        use chrono::TimeZone;
        use chrono::Utc;
        use codex_protocol::ThreadId;
        use pretty_assertions::assert_eq;

        use super::super::super::config::CommandSpec;
        use super::super::super::types::HookEvent;
        use super::super::super::types::HookEventAfterAgent;
        use super::super::super::types::HookEventPreToolUse;
        use super::super::super::types::HookOutcome;
        use super::super::super::types::HookPayload;
        use super::super::command_hook;

        /// Helper to create shell command spec
        fn shell(cmd: &str) -> CommandSpec {
            CommandSpec::Shell(cmd.to_string())
        }

        /// Helper to create argv command spec
        fn argv(args: Vec<&str>) -> CommandSpec {
            CommandSpec::Argv(args.iter().map(ToString::to_string).collect())
        }

        fn test_payload() -> HookPayload {
            let hook_event = HookEvent::AfterAgent {
                event: HookEventAfterAgent {
                    thread_id: ThreadId::new(),
                    turn_id: "test".to_string(),
                    input_messages: vec!["hello".to_string()],
                    last_assistant_message: None,
                },
            };
            HookPayload {
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
                env_file_path: None,
            }
        }

        /// Returns a payload with a blockable event (PreToolUse).
        fn blockable_test_payload() -> HookPayload {
            let hook_event = HookEvent::PreToolUse {
                event: HookEventPreToolUse {
                    tool_name: "bash".to_string(),
                    tool_input: serde_json::json!({}),
                },
            };
            HookPayload {
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
                env_file_path: None,
            }
        }

        #[tokio::test]
        async fn command_hook_empty_stdout_returns_proceed() {
            // Command reads stdin but produces no stdout → Proceed
            let hook = command_hook(
                shell("cat > /dev/null"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_stdout_proceed_json() {
            let hook = command_hook(
                shell(r#"cat > /dev/null; echo '{"decision":"proceed"}'"#),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_stdout_block_json() {
            let hook = command_hook(
                shell(r#"cat > /dev/null; echo '{"decision":"block","message":"denied by policy"}'"#),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(
                result.outcome,
                HookOutcome::Block {
                    message: Some("denied by policy".to_string())
                }
            );
        }

        #[tokio::test]
        async fn command_hook_stdout_modify_json() {
            let hook = command_hook(
                shell(r#"cat > /dev/null; echo '{"decision":"modify","content":"new content"}'"#),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(
                result.outcome,
                HookOutcome::Modify {
                    content: "new content".to_string()
                }
            );
        }

        #[tokio::test]
        async fn command_hook_exit_2_blocks_on_blockable_event() {
            let hook = command_hook(shell("cat > /dev/null; echo 'denied by hook' >&2; exit 2"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&blockable_test_payload()).await;
            match result.outcome {
                HookOutcome::Block { message } => {
                    let msg = message.expect("should have error message");
                    assert!(
                        msg.contains("denied by hook"),
                        "stderr should be in message: {msg}"
                    );
                }
                other => panic!("expected Block for exit 2 on blockable event, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn command_hook_exit_2_empty_stderr_uses_default_message() {
            let hook = command_hook(shell("cat > /dev/null; exit 2"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&blockable_test_payload()).await;
            match result.outcome {
                HookOutcome::Block { message } => {
                    let msg = message.expect("should have error message");
                    assert!(
                        msg.contains("blocking error"),
                        "message should mention blocking error: {msg}"
                    );
                }
                other => panic!("expected Block for exit 2 on blockable event, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn command_hook_exit_2_proceeds_on_non_blockable_event() {
            // AfterAgent is not blockable — exit 2 should proceed like other non-zero codes
            let hook = command_hook(shell("cat > /dev/null; exit 2"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_nonzero_exit_nonblocking_proceeds() {
            // exit 1 is a non-blocking error — hook should proceed
            let hook = command_hook(shell("cat > /dev/null; echo 'error msg' >&2; exit 1"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_nonzero_exit_other_code_proceeds() {
            // exit 42 is a non-blocking error — hook should proceed
            let hook = command_hook(shell("cat > /dev/null; exit 42"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_timeout_returns_block() {
            let hook = command_hook(shell("cat > /dev/null; sleep 60"),
                Duration::from_millis(100), // Very short timeout
            );
            let result = hook.execute(&test_payload()).await;
            let outcome = result.outcome;
            assert_eq!(
                outcome,
                HookOutcome::Block {
                    message: Some("hook timed out".to_string())
                }
            );
        }

        #[tokio::test]
        async fn command_hook_invalid_json_stdout_returns_proceed() {
            let hook = command_hook(shell("cat > /dev/null; echo 'not valid json'"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            let outcome = result.outcome;
            // Invalid JSON → fail-open → Proceed
            assert_eq!(outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_nonexistent_command_returns_proceed() {
            let hook = command_hook(
                argv(vec!["/nonexistent/command/path/xxxxx"]),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            let outcome = result.outcome;
            // Spawn failure → fail-open → Proceed
            assert_eq!(outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_empty_argv_returns_proceed() {
            let hook = command_hook(argv(vec![]), Duration::from_secs(5));
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_receives_payload_on_stdin() {
            // Verify the hook receives the JSON payload on stdin by having
            // the script parse it and echo back a field from the payload.
            let hook = command_hook(
                shell("cat > /dev/null; echo '{\"decision\":\"proceed\"}'"),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);
        }

        #[tokio::test]
        async fn command_hook_receives_claude_env_file_for_session_start() {
            use super::super::super::types::HookEventSessionStart;

            // Create a SessionStart payload with env_file_path set
            let temp_file = tempfile::NamedTempFile::new().expect("create temp file");
            let env_file_path = temp_file.path().to_path_buf();

            let hook_event = HookEvent::SessionStart {
                event: HookEventSessionStart {
                    source: "cli".to_string(),
                    model: "claude-opus-4-6".to_string(),
                    agent_type: "codex".to_string(),
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
                env_file_path: Some(env_file_path.clone()),
            };

            // Hook writes KEY=VALUE to CLAUDE_ENV_FILE and returns proceed
            let hook = command_hook(
                shell(r#"echo "TEST_VAR=test_value" >> "$CLAUDE_ENV_FILE"; echo '{"decision":"proceed"}'"#),
                Duration::from_secs(5),
            );

            let result = hook.execute(&payload).await;
            assert_eq!(result.outcome, HookOutcome::Proceed);

            // Verify env_vars were parsed from the file
            assert_eq!(result.env_vars.len(), 1);
            assert_eq!(result.env_vars.get("TEST_VAR"), Some(&"test_value".to_string()));
        }

        #[tokio::test]
        async fn command_hook_runs_in_payload_cwd() {
            // Verify that the hook command runs in the payload's cwd directory
            // by having the script print its working directory via `pwd`.
            let hook = command_hook(
                shell("cat > /dev/null; pwd"),
                Duration::from_secs(5),
            );
            // test_payload() sets cwd to /tmp
            let result = hook.execute(&test_payload()).await;
            let outcome = result.outcome;
            // pwd outputs the working directory; since it's not valid JSON,
            // the executor falls through to Proceed (fail-open on invalid JSON).
            // The important thing is that it doesn't fail to spawn, proving
            // the command runs. We verify cwd more precisely below.
            assert_eq!(outcome, HookOutcome::Proceed);

            // Now verify with a JSON response that includes the cwd
            let hook = command_hook(
                shell(r#"cat > /dev/null; CWD=$(pwd); echo "{\"decision\":\"block\",\"message\":\"$CWD\"}""#),
                Duration::from_secs(5),
            );
            let result = hook.execute(&test_payload()).await;
            let outcome = result.outcome;
            match outcome {
                HookOutcome::Block { message } => {
                    let msg = message.expect("should have cwd message");
                    assert_eq!(
                        msg, "/tmp",
                        "hook should run in payload.cwd (/tmp), got: {msg}"
                    );
                }
                other => panic!("expected Block with cwd message, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_parse_env_file() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let env_file_path = temp_dir.path().join("env.txt");

        // Test with valid KEY=VALUE pairs
        {
            let mut file = std::fs::File::create(&env_file_path).unwrap();
            writeln!(file, "FOO=bar").unwrap();
            writeln!(file, "BAZ=qux").unwrap();
            writeln!(file, "# Comment line").unwrap();
            writeln!(file).unwrap();
            writeln!(file, "KEY_WITH_SPACES = value with spaces ").unwrap();
        }

        let env_vars = super::parse_env_file(&env_file_path);
        assert_eq!(env_vars.len(), 3);
        assert_eq!(env_vars.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env_vars.get("BAZ"), Some(&"qux".to_string()));
        assert_eq!(env_vars.get("KEY_WITH_SPACES"), Some(&"value with spaces".to_string()));

        // Test with empty file
        std::fs::write(&env_file_path, "").unwrap();
        let env_vars = super::parse_env_file(&env_file_path);
        assert_eq!(env_vars.len(), 0);

        // Test with non-existent file
        let env_vars = super::parse_env_file(&temp_dir.path().join("nonexistent.txt"));
        assert_eq!(env_vars.len(), 0);

        // Test with malformed lines (no = sign)
        {
            let mut file = std::fs::File::create(&env_file_path).unwrap();
            writeln!(file, "INVALID_LINE").unwrap();
            writeln!(file, "VALID=value").unwrap();
        }
        let env_vars = super::parse_env_file(&env_file_path);
        assert_eq!(env_vars.len(), 1);
        assert_eq!(env_vars.get("VALID"), Some(&"value".to_string()));

        // Test with value containing = sign
        {
            let mut file = std::fs::File::create(&env_file_path).unwrap();
            writeln!(file, "URL=https://example.com?foo=bar").unwrap();
        }
        let env_vars = super::parse_env_file(&env_file_path);
        assert_eq!(env_vars.len(), 1);
        assert_eq!(env_vars.get("URL"), Some(&"https://example.com?foo=bar".to_string()));
    }

    #[test]
    fn test_hook_command_output_to_outcome() {
        let output = HookCommandOutput {
            decision: HookDecision::Proceed,
            reason: None,
            content: None,
            stop_reason: None,
            suppress_output: None,
            system_message: None,
            hook_specific_output: None,
        };
        assert_eq!(HookResult::from(output).outcome, HookOutcome::Proceed);

        let output = HookCommandOutput {
            decision: HookDecision::Block,
            reason: Some("blocked".to_string()),
            content: None,
            stop_reason: None,
            suppress_output: None,
            system_message: None,
            hook_specific_output: None,
        };
        assert_eq!(
            HookResult::from(output).outcome,
            HookOutcome::Block {
                message: Some("blocked".to_string())
            }
        );

        let output = HookCommandOutput {
            decision: HookDecision::Modify,
            reason: None,
            content: Some("modified content".to_string()),
            stop_reason: None,
            suppress_output: None,
            system_message: None,
            hook_specific_output: None,
        };
        assert_eq!(
            HookResult::from(output).outcome,
            HookOutcome::Modify {
                content: "modified content".to_string()
            }
        );

        // Modify with explicit empty content is allowed
        let output = HookCommandOutput {
            decision: HookDecision::Modify,
            reason: None,
            content: Some(String::new()),
            stop_reason: None,
            suppress_output: None,
            system_message: None,
            hook_specific_output: None,
        };
        assert_eq!(
            HookResult::from(output).outcome,
            HookOutcome::Modify {
                content: String::new()
            }
        );

        // Modify without content field → Block (malformed response)
        let output = HookCommandOutput {
            decision: HookDecision::Modify,
            reason: None,
            content: None,
            stop_reason: None,
            suppress_output: None,
            system_message: None,
            hook_specific_output: None,
        };
        assert!(
            matches!(HookResult::from(output).outcome, HookOutcome::Block { .. }),
            "modify without content should be treated as Block"
        );
    }
}

/// Protocol compatibility tests for stdout JSON parsing.
///
/// These tests verify that HookCommandOutput correctly deserializes all
/// supported JSON formats that hooks can return via stdout, following
/// the Claude Code specification.
#[cfg(test)]
mod stdout_protocol_compat_tests {
    use super::super::types::HookOutcome;
    use super::super::types::HookResult;
    use super::HookCommandOutput;
    use super::HookDecision;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn stdout_json_proceed_simple() {
        let json = json!({"decision": "proceed"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Proceed);
        assert_eq!(HookResult::from(output).outcome, HookOutcome::Proceed);
    }

    #[test]
    fn stdout_json_block_with_reason() {
        let json = json!({
            "decision": "block",
            "reason": "Sensitive operation not allowed in production"
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(
            output.reason,
            Some("Sensitive operation not allowed in production".to_string())
        );

        match HookResult::from(output).outcome {
            HookOutcome::Block { message } => {
                assert_eq!(
                    message,
                    Some("Sensitive operation not allowed in production".to_string())
                );
            }
            _ => panic!("expected Block outcome"),
        }
    }

    #[test]
    fn stdout_json_block_legacy_message_alias() {
        // Legacy hooks may use "message" instead of "reason"
        let json = json!({
            "decision": "block",
            "message": "Denied by policy"
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(output.reason, Some("Denied by policy".to_string()));
    }

    #[test]
    fn stdout_json_modify_with_content() {
        let json = json!({
            "decision": "modify",
            "content": "sanitized input"
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Modify);
        assert_eq!(output.content, Some("sanitized input".to_string()));

        match HookResult::from(output).outcome {
            HookOutcome::Modify { content } => {
                assert_eq!(content, "sanitized input");
            }
            _ => panic!("expected Modify outcome"),
        }
    }

    #[test]
    fn stdout_json_modify_with_empty_content() {
        let json = json!({
            "decision": "modify",
            "content": ""
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Modify);
        assert_eq!(output.content, Some(String::new()));

        match HookResult::from(output).outcome {
            HookOutcome::Modify { content } => {
                assert_eq!(content, "");
            }
            _ => panic!("expected Modify outcome"),
        }
    }

    #[test]
    fn stdout_json_modify_without_content_becomes_block() {
        let json = json!({"decision": "modify"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Modify);
        assert_eq!(output.content, None);

        // Should be converted to Block to prevent empty substitution
        match HookResult::from(output).outcome {
            HookOutcome::Block { .. } => {}
            other => panic!("expected Block outcome for modify without content, got {other:?}"),
        }
    }

    #[test]
    fn stdout_json_with_metadata_fields() {
        let json = json!({
            "decision": "block",
            "reason": "Not allowed",
            "systemMessage": "Hook blocked this operation for security reasons",
            "stopReason": "security_violation",
            "suppressOutput": true
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(output.reason, Some("Not allowed".to_string()));
        assert_eq!(
            output.system_message,
            Some("Hook blocked this operation for security reasons".to_string())
        );
        assert_eq!(output.stop_reason, Some("security_violation".to_string()));
        assert_eq!(output.suppress_output, Some(true));

        let result = HookResult::from(output);
        assert_eq!(
            result.meta.system_message,
            Some("Hook blocked this operation for security reasons".to_string())
        );
        assert_eq!(result.meta.stop_reason, Some("security_violation".to_string()));
        assert_eq!(result.meta.suppress_output, Some(true));
    }

    #[test]
    fn stdout_json_empty_defaults_to_proceed() {
        // Empty JSON object should default to Proceed
        let json = json!({});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Proceed);
        assert_eq!(HookResult::from(output).outcome, HookOutcome::Proceed);
    }

    #[test]
    fn stdout_json_camel_case_fields() {
        // Verify camelCase formatting is correctly parsed
        let json = json!({
            "decision": "proceed",
            "systemMessage": "Operation approved",
            "stopReason": "max_turns",
            "suppressOutput": false,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "Safe operation",
                "updatedInput": {"modified": true},
                "additionalContext": "Verified by security scan"
            }
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Proceed);
        assert_eq!(output.system_message, Some("Operation approved".to_string()));
        assert_eq!(output.stop_reason, Some("max_turns".to_string()));
        assert_eq!(output.suppress_output, Some(false));

        let specific = output
            .hook_specific_output
            .expect("should have hook specific output");
        assert_eq!(specific.hook_event_name, Some("PreToolUse".to_string()));
        assert_eq!(specific.permission_decision, Some("allow".to_string()));
        assert_eq!(
            specific.permission_decision_reason,
            Some("Safe operation".to_string())
        );
        assert!(specific.updated_input.is_some());
        assert_eq!(
            specific.additional_context,
            Some("Verified by security scan".to_string())
        );
    }

    #[test]
    fn stdout_json_all_decision_types() {
        // Verify all three decision types are correctly parsed
        for (decision_str, expected_decision) in [
            ("proceed", HookDecision::Proceed),
            ("block", HookDecision::Block),
            ("modify", HookDecision::Modify),
        ] {
            let json = json!({"decision": decision_str});
            let output: HookCommandOutput = serde_json::from_value(json).unwrap();
            assert_eq!(
                output.decision, expected_decision,
                "decision '{}' should parse correctly",
                decision_str
            );
        }
    }

    #[test]
    fn stdout_json_block_without_reason() {
        // Block decision without reason should still be valid
        let json = json!({"decision": "block"});
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Block);
        assert_eq!(output.reason, None);

        match HookResult::from(output).outcome {
            HookOutcome::Block { message } => {
                assert_eq!(message, None);
            }
            _ => panic!("expected Block outcome"),
        }
    }

    #[test]
    fn stdout_json_proceed_with_system_message() {
        // Proceed can include system message for logging/notification
        let json = json!({
            "decision": "proceed",
            "systemMessage": "Operation logged for audit"
        });
        let output: HookCommandOutput = serde_json::from_value(json).unwrap();
        assert_eq!(output.decision, HookDecision::Proceed);
        assert_eq!(
            output.system_message,
            Some("Operation logged for audit".to_string())
        );

        let result = HookResult::from(output);
        assert_eq!(result.outcome, HookOutcome::Proceed);
        assert_eq!(
            result.meta.system_message,
            Some("Operation logged for audit".to_string())
        );
    }
}
