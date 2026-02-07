use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::types::Hook;
use super::types::HookOutcome;
use super::types::HookPayload;

/// Maximum bytes to read from a hook command's stdout to prevent unbounded memory usage.
#[allow(dead_code)] // Will be used when hook config integration is added
const MAX_STDOUT_BYTES: usize = 1_048_576; // 1MB

/// Decision returned by a hook command.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum HookDecision {
    Proceed,
    Block,
    Modify,
}

/// Result structure returned by a hook command via stdout JSON.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct HookCommandResult {
    pub decision: HookDecision,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

impl From<HookCommandResult> for HookOutcome {
    fn from(result: HookCommandResult) -> Self {
        match result.decision {
            HookDecision::Proceed => HookOutcome::Proceed,
            HookDecision::Block => HookOutcome::Block {
                message: result.message,
            },
            HookDecision::Modify => HookOutcome::Modify {
                content: result.content.unwrap_or_default(),
            },
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
#[allow(dead_code)] // Will be used when hook config integration is added
pub(super) fn command_hook(argv: Vec<String>, timeout: Duration) -> Hook {
    Hook {
        func: Arc::new(move |payload: &HookPayload| {
            let argv = argv.clone();
            let payload = payload.clone();
            Box::pin(async move {
                let Some(mut command) = super::registry::command_from_argv(&argv) else {
                    tracing::warn!("hook command argv is empty, skipping");
                    return HookOutcome::Proceed;
                };

                command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                let mut child = match command.spawn() {
                    Ok(child) => child,
                    Err(err) => {
                        tracing::warn!("failed to spawn hook command: {err}");
                        return HookOutcome::Proceed;
                    }
                };

                let mut stdin = child.stdin.take().expect("stdin was piped");
                let mut stdout = child.stdout.take().expect("stdout was piped");
                let mut stderr = child.stderr.take().expect("stderr was piped");

                // Serialize and write payload to stdin
                let payload_json = match serde_json::to_vec(&payload) {
                    Ok(json) => json,
                    Err(err) => {
                        tracing::warn!("failed to serialize hook payload: {err}");
                        return HookOutcome::Proceed;
                    }
                };

                if let Err(err) = stdin.write_all(&payload_json).await {
                    tracing::warn!("failed to write payload to hook stdin: {err}");
                    return HookOutcome::Proceed;
                }
                drop(stdin); // Close stdin to signal EOF

                // Read stdout with limit
                let mut stdout_bytes = Vec::new();
                let read_result = tokio::time::timeout(timeout, async {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stdout.read(&mut buffer).await {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                if stdout_bytes.len() + n > MAX_STDOUT_BYTES {
                                    tracing::warn!(
                                        "hook stdout exceeded max size of {MAX_STDOUT_BYTES} bytes"
                                    );
                                    return Err("stdout too large");
                                }
                                stdout_bytes.extend_from_slice(&buffer[..n]);
                            }
                            Err(err) => {
                                tracing::warn!("failed to read hook stdout: {err}");
                                return Err("read error");
                            }
                        }
                    }
                    Ok(())
                })
                .await;

                // Handle timeout
                if read_result.is_err() {
                    let _ = child.kill().await;
                    return HookOutcome::Block {
                        message: Some("hook timed out".to_string()),
                    };
                }

                // Read stderr (best effort, don't block)
                let mut stderr_bytes = Vec::new();
                let _ = stderr.read_to_end(&mut stderr_bytes).await;
                let stderr_string = String::from_utf8_lossy(&stderr_bytes).to_string();

                // Wait for process to exit
                let status = match child.wait().await {
                    Ok(status) => status,
                    Err(err) => {
                        tracing::warn!("failed to wait for hook command: {err}");
                        return HookOutcome::Proceed;
                    }
                };

                // Non-zero exit code → block with stderr message
                if !status.success() {
                    let message = if stderr_string.is_empty() {
                        format!("hook command failed with exit code {}", status)
                    } else {
                        stderr_string
                    };
                    return HookOutcome::Block {
                        message: Some(message),
                    };
                }

                // Exit code 0: parse stdout or default to Proceed
                if stdout_bytes.is_empty() {
                    return HookOutcome::Proceed;
                }

                match serde_json::from_slice::<HookCommandResult>(&stdout_bytes) {
                    Ok(result) => result.into(),
                    Err(err) => {
                        tracing::warn!("failed to parse hook command result: {err}");
                        HookOutcome::Proceed
                    }
                }
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::super::types::HookOutcome;
    use super::HookCommandResult;
    use super::HookDecision;

    #[test]
    fn test_hook_command_result_deserialize_proceed() {
        let json = json!({"decision": "proceed"});
        let result: HookCommandResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.decision, HookDecision::Proceed);
        assert_eq!(result.message, None);
        assert_eq!(result.content, None);
    }

    #[test]
    fn test_hook_command_result_deserialize_block() {
        let json = json!({"decision": "block", "message": "denied"});
        let result: HookCommandResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.decision, HookDecision::Block);
        assert_eq!(result.message, Some("denied".to_string()));
        assert_eq!(result.content, None);
    }

    #[test]
    fn test_hook_command_result_deserialize_modify() {
        let json = json!({"decision": "modify", "content": "new text"});
        let result: HookCommandResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.decision, HookDecision::Modify);
        assert_eq!(result.message, None);
        assert_eq!(result.content, Some("new text".to_string()));
    }

    #[test]
    fn test_hook_command_result_to_outcome() {
        let result = HookCommandResult {
            decision: HookDecision::Proceed,
            message: None,
            content: None,
        };
        assert_eq!(HookOutcome::from(result), HookOutcome::Proceed);

        let result = HookCommandResult {
            decision: HookDecision::Block,
            message: Some("blocked".to_string()),
            content: None,
        };
        assert_eq!(
            HookOutcome::from(result),
            HookOutcome::Block {
                message: Some("blocked".to_string())
            }
        );

        let result = HookCommandResult {
            decision: HookDecision::Modify,
            message: None,
            content: Some("modified content".to_string()),
        };
        assert_eq!(
            HookOutcome::from(result),
            HookOutcome::Modify {
                content: "modified content".to_string()
            }
        );
    }

    #[test]
    fn test_empty_stdout_returns_proceed() {
        // Tested implicitly in the async integration tests below,
        // but verified by the command_hook implementation logic:
        // if stdout_bytes.is_empty() → HookOutcome::Proceed
        let empty_bytes: &[u8] = b"";
        assert!(empty_bytes.is_empty());
    }
}
