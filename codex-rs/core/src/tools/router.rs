use crate::client_common::tools::ToolSpec;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::function_tool::FunctionCallError;
use crate::hooks::EffectAction;
use crate::hooks::HookEvent;
use crate::hooks::HookEventPostToolUse;
use crate::hooks::HookEventPostToolUseFailure;
use crate::hooks::HookEventPreToolUse;
use crate::hooks::HookPayload;
use crate::sandboxing::SandboxPermissions;
use crate::tools::context::SharedTurnDiffTracker;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::registry::ConfiguredToolSpec;
use crate::tools::registry::ToolRegistry;
use crate::tools::spec::ToolsConfig;
use crate::tools::spec::build_specs;
use codex_protocol::dynamic_tools::DynamicToolSpec;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::LocalShellAction;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::models::ShellToolCallParams;
use rmcp::model::Tool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;

/// Map internal tool names to Claude Code compatible names for hook payloads.
///
/// Claude Code uses PascalCase tool names (e.g. `Bash`, `Read`, `Write`),
/// while Codex uses snake_case internally (e.g. `local_shell`).  This mapping
/// ensures hook scripts see the same names regardless of which agent they run
/// under.
fn hook_tool_name(internal_name: &str) -> String {
    match internal_name {
        // All shell execution variants map to "Bash"
        "local_shell" | "shell" | "container.exec" | "shell_command" | "exec_command" => {
            "Bash".to_string()
        }
        // File-reading tools map to "Read"
        "read_file" | "view_image" => "Read".to_string(),
        // File-writing / stdin-piping tools map to "Write"
        "write_stdin" => "Write".to_string(),
        // Patch-based editing maps to "Edit"
        "apply_patch" => "Edit".to_string(),
        // Search tools
        "grep_files" => "Grep".to_string(),
        "list_dir" => "ListDir".to_string(),
        // Other tools (MCP, custom, function tools) pass through unchanged
        other => other.to_string(),
    }
}

#[derive(Clone, Debug)]
pub struct ToolCall {
    pub tool_name: String,
    pub call_id: String,
    pub payload: ToolPayload,
}

pub struct ToolRouter {
    registry: ToolRegistry,
    specs: Vec<ConfiguredToolSpec>,
}

impl ToolRouter {
    pub fn from_config(
        config: &ToolsConfig,
        mcp_tools: Option<HashMap<String, Tool>>,
        dynamic_tools: &[DynamicToolSpec],
    ) -> Self {
        let builder = build_specs(config, mcp_tools, dynamic_tools);
        let (specs, registry) = builder.build();

        Self { registry, specs }
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.specs
            .iter()
            .map(|config| config.spec.clone())
            .collect()
    }

    pub fn tool_supports_parallel(&self, tool_name: &str) -> bool {
        self.specs
            .iter()
            .filter(|config| config.supports_parallel_tool_calls)
            .any(|config| config.spec.name() == tool_name)
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn build_tool_call(
        session: &Session,
        item: ResponseItem,
    ) -> Result<Option<ToolCall>, FunctionCallError> {
        match item {
            ResponseItem::FunctionCall {
                name,
                arguments,
                call_id,
                ..
            } => {
                if let Some((server, tool)) = session.parse_mcp_tool_name(&name).await {
                    Ok(Some(ToolCall {
                        tool_name: name,
                        call_id,
                        payload: ToolPayload::Mcp {
                            server,
                            tool,
                            raw_arguments: arguments,
                        },
                    }))
                } else {
                    Ok(Some(ToolCall {
                        tool_name: name,
                        call_id,
                        payload: ToolPayload::Function { arguments },
                    }))
                }
            }
            ResponseItem::CustomToolCall {
                name,
                input,
                call_id,
                ..
            } => Ok(Some(ToolCall {
                tool_name: name,
                call_id,
                payload: ToolPayload::Custom { input },
            })),
            ResponseItem::LocalShellCall {
                id,
                call_id,
                action,
                ..
            } => {
                let call_id = call_id
                    .or(id)
                    .ok_or(FunctionCallError::MissingLocalShellCallId)?;

                match action {
                    LocalShellAction::Exec(exec) => {
                        let params = ShellToolCallParams {
                            command: exec.command,
                            workdir: exec.working_directory,
                            timeout_ms: exec.timeout_ms,
                            sandbox_permissions: Some(SandboxPermissions::UseDefault),
                            prefix_rule: None,
                            justification: None,
                        };
                        Ok(Some(ToolCall {
                            tool_name: "local_shell".to_string(),
                            call_id,
                            payload: ToolPayload::LocalShell { params },
                        }))
                    }
                }
            }
            _ => Ok(None),
        }
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn dispatch_tool_call(
        &self,
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        tracker: SharedTurnDiffTracker,
        call: ToolCall,
    ) -> Result<ResponseInputItem, FunctionCallError> {
        let ToolCall {
            tool_name,
            call_id,
            mut payload,
        } = call;
        let payload_outputs_custom = matches!(payload, ToolPayload::Custom { .. });
        let failure_call_id = call_id.clone();

        // Extract structured tool input for hooks (preserves shell arg
        // boundaries and workdir overrides, unlike log_payload()).
        let tool_input = payload.hook_input();
        let hook_name = hook_tool_name(&tool_name);

        // --- PreToolUse hook ---
        let pre_outcome = session
            .hooks()
            .dispatch(HookPayload::new(
                session.conversation_id,
                turn.cwd.clone(),
                HookEvent::PreToolUse {
                    event: HookEventPreToolUse {
                        tool_name: hook_name.clone(),
                        tool_input: tool_input.clone(),
                    },
                },
                None,
                turn.approval_policy.to_string(),
            ))
            .await;

        // Emit Warning events for any system messages from hooks.
        for msg in &pre_outcome.system_messages {
            session
                .send_event(
                    &turn,
                    codex_protocol::protocol::EventMsg::Warning(
                        codex_protocol::protocol::WarningEvent {
                            message: format!("[hook] {msg}"),
                        },
                    ),
                )
                .await;
        }

        match pre_outcome.action {
            EffectAction::Proceed => {
                // If a hook returned Modify, apply the modified content.
                if let Some(content) = pre_outcome.modified_content {
                    match &mut payload {
                        ToolPayload::Function { arguments } => {
                            *arguments = content;
                        }
                        ToolPayload::Mcp { raw_arguments, .. } => {
                            *raw_arguments = content;
                        }
                        ToolPayload::Custom { input } => {
                            *input = content;
                        }
                        ToolPayload::LocalShell { .. } => {
                            // Modifying shell command structure from a hook is
                            // not safely supported.  Block the call so the
                            // hook's policy intent is not silently bypassed.
                            return Ok(Self::failure_response(
                                failure_call_id,
                                payload_outputs_custom,
                                FunctionCallError::ToolCallBlocked(
                                    "pre_tool_use hook returned Modify for local_shell which is not supported; blocking execution".to_string(),
                                ),
                            ));
                        }
                    }
                }
            }
            EffectAction::Block { reason } => {
                return Ok(Self::failure_response(
                    failure_call_id,
                    payload_outputs_custom,
                    FunctionCallError::ToolCallBlocked(reason),
                ));
            }
        }

        // Capture tool input for PostToolUse hook before payload is moved.
        let tool_input_for_hook = payload.hook_input();

        let invocation = ToolInvocation {
            session: Arc::clone(&session),
            turn: Arc::clone(&turn),
            tracker,
            call_id,
            tool_name: tool_name.clone(),
            payload,
        };

        let mut dispatched_failure = false;
        let result = match self.registry.dispatch(invocation).await {
            Ok(response) => Ok(response),
            Err(FunctionCallError::Fatal(message)) => Err(FunctionCallError::Fatal(message)),
            Err(err) => {
                dispatched_failure = true;
                // Dispatch PostToolUseFailure hook (non-blockable).
                session
                    .hooks()
                    .dispatch(HookPayload::new(
                        session.conversation_id,
                        turn.cwd.clone(),
                        HookEvent::PostToolUseFailure {
                            event: HookEventPostToolUseFailure {
                                tool_name: hook_name.clone(),
                                error: err.to_string(),
                            },
                        },
                        None,
                        turn.approval_policy.to_string(),
                    ))
                    .await;

                Ok(Self::failure_response(
                    failure_call_id,
                    payload_outputs_custom,
                    err,
                ))
            }
        };

        // MCP tool failures arrive as Ok(McpToolCallOutput { result: Err(..) })
        // or Ok(McpToolCallOutput { result: Ok(CallToolResult { is_error: Some(true) }) }).
        // Detect these and dispatch PostToolUseFailure for them too.
        if !dispatched_failure
            && let Ok(ref response) = result
            && let Some(error_msg) = Self::extract_mcp_error(response)
        {
            dispatched_failure = true;
            session
                .hooks()
                .dispatch(HookPayload::new(
                    session.conversation_id,
                    turn.cwd.clone(),
                    HookEvent::PostToolUseFailure {
                        event: HookEventPostToolUseFailure {
                            tool_name: hook_name.clone(),
                            error: error_msg,
                        },
                    },
                    None,
                    turn.approval_policy.to_string(),
                ))
                .await;
        }

        // --- PostToolUse hook (only for successful invocations) ---
        // Awaited inline so hooks can inspect/modify tool output and inject
        // system messages.  PostToolUse is non-blockable so a Block decision
        // from the hook is treated as a warning.
        if !dispatched_failure
            && let Ok(ref response) = result
        {
                let tool_output = Self::extract_output_text(response);
                let post_outcome = session
                    .hooks()
                    .dispatch(HookPayload::new(
                        session.conversation_id,
                        turn.cwd.clone(),
                        HookEvent::PostToolUse {
                            event: HookEventPostToolUse {
                                tool_name: hook_name,
                                tool_input: tool_input_for_hook,
                                tool_output,
                            },
                        },
                        None,
                        turn.approval_policy.to_string(),
                    ))
                    .await;

                // Emit Warning events for any system messages from post-tool hooks.
                for msg in &post_outcome.system_messages {
                    session
                        .send_event(
                            &turn,
                            codex_protocol::protocol::EventMsg::Warning(
                                codex_protocol::protocol::WarningEvent {
                                    message: format!("[hook] {msg}"),
                                },
                            ),
                        )
                        .await;
                }

                // PostToolUse is non-blockable; a Block decision is informational only.
                if let EffectAction::Block { reason } = &post_outcome.action {
                    tracing::warn!("post_tool_use hook returned block (non-blocking): {reason}");
                }

                if post_outcome.suppress_output {
                    tracing::info!("post_tool_use hook requested output suppression");
                    return Ok(Self::suppressed_response(response));
                }
        }

        result
    }

    /// Check if the response is an MCP error and return the error message if so.
    ///
    /// MCP tool failures arrive as `Ok(McpToolCallOutput { result: Err(..) })` or
    /// `Ok(McpToolCallOutput { result: Ok(CallToolResult { is_error: Some(true), .. }) })`.
    fn extract_mcp_error(item: &ResponseInputItem) -> Option<String> {
        match item {
            ResponseInputItem::McpToolCallOutput { result, .. } => match result {
                Err(err) => Some(err.clone()),
                Ok(ctr) if ctr.is_error == Some(true) => {
                    let payload: codex_protocol::models::FunctionCallOutputPayload = ctr.into();
                    Some(payload.body.to_text().unwrap_or_else(|| "MCP tool error".to_string()))
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Extract a textual preview from a `ResponseInputItem` for the PostToolUse hook.
    fn extract_output_text(item: &ResponseInputItem) -> String {
        match item {
            ResponseInputItem::FunctionCallOutput { output, .. } => {
                output.body.to_text().unwrap_or_default()
            }
            ResponseInputItem::McpToolCallOutput { result, .. } => match result {
                Ok(ctr) => {
                    let payload: codex_protocol::models::FunctionCallOutputPayload = ctr.into();
                    payload.body.to_text().unwrap_or_default()
                }
                Err(err) => err.clone(),
            },
            ResponseInputItem::CustomToolCallOutput { output, .. } => output.clone(),
            _ => String::new(),
        }
    }

    /// Replace tool output with a suppression notice when a PostToolUse hook
    /// requests output suppression.
    fn suppressed_response(original: &ResponseInputItem) -> ResponseInputItem {
        const MSG: &str = "[output suppressed by hook]";
        match original {
            ResponseInputItem::FunctionCallOutput { call_id, output } => {
                ResponseInputItem::FunctionCallOutput {
                    call_id: call_id.clone(),
                    output: codex_protocol::models::FunctionCallOutputPayload {
                        body: FunctionCallOutputBody::Text(MSG.to_string()),
                        success: output.success,
                    },
                }
            }
            ResponseInputItem::McpToolCallOutput { call_id, result } => {
                let success = match result {
                    Ok(ctr) => Some(ctr.is_error != Some(true)),
                    Err(_) => Some(false),
                };
                ResponseInputItem::FunctionCallOutput {
                    call_id: call_id.clone(),
                    output: codex_protocol::models::FunctionCallOutputPayload {
                        body: FunctionCallOutputBody::Text(MSG.to_string()),
                        success,
                    },
                }
            }
            ResponseInputItem::CustomToolCallOutput { call_id, .. } => {
                ResponseInputItem::CustomToolCallOutput {
                    call_id: call_id.clone(),
                    output: MSG.to_string(),
                }
            }
            // Non-tool response items pass through unchanged.
            other => other.clone(),
        }
    }

    fn failure_response(
        call_id: String,
        payload_outputs_custom: bool,
        err: FunctionCallError,
    ) -> ResponseInputItem {
        let message = err.to_string();
        if payload_outputs_custom {
            ResponseInputItem::CustomToolCallOutput {
                call_id,
                output: message,
            }
        } else {
            ResponseInputItem::FunctionCallOutput {
                call_id,
                output: codex_protocol::models::FunctionCallOutputPayload {
                    body: FunctionCallOutputBody::Text(message),
                    success: Some(false),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_tool_name_shell_variants() {
        // All shell execution variants should map to "Bash"
        assert_eq!(hook_tool_name("local_shell"), "Bash");
        assert_eq!(hook_tool_name("shell"), "Bash");
        assert_eq!(hook_tool_name("container.exec"), "Bash");
        assert_eq!(hook_tool_name("shell_command"), "Bash");
        assert_eq!(hook_tool_name("exec_command"), "Bash");
    }

    #[test]
    fn test_hook_tool_name_builtin_mappings() {
        // Built-in file/search tools map to Claude Code PascalCase names
        assert_eq!(hook_tool_name("read_file"), "Read");
        assert_eq!(hook_tool_name("view_image"), "Read");
        assert_eq!(hook_tool_name("write_stdin"), "Write");
        assert_eq!(hook_tool_name("apply_patch"), "Edit");
        assert_eq!(hook_tool_name("grep_files"), "Grep");
        assert_eq!(hook_tool_name("list_dir"), "ListDir");
    }

    #[test]
    fn test_hook_tool_name_passthrough() {
        // MCP tools should pass through with their full qualified names
        assert_eq!(hook_tool_name("mcp__server__tool"), "mcp__server__tool");

        // Custom tools should pass through
        assert_eq!(hook_tool_name("custom_tool"), "custom_tool");
    }

    #[test]
    fn test_hook_input_local_shell() {
        let payload = ToolPayload::LocalShell {
            params: ShellToolCallParams {
                command: vec!["ls".to_string(), "-la".to_string()],
                workdir: Some("/tmp".into()),
                timeout_ms: Some(5000),
                sandbox_permissions: Some(SandboxPermissions::UseDefault),
                prefix_rule: None,
                justification: None,
            },
        };

        let input = payload.hook_input();
        assert!(input.is_object());

        // Should contain command field as array
        assert_eq!(
            input.get("command"),
            Some(&serde_json::json!(["ls", "-la"]))
        );

        // Should contain workdir field
        assert_eq!(
            input.get("workdir"),
            Some(&serde_json::json!("/tmp"))
        );

        // Should contain timeout_ms field
        assert_eq!(
            input.get("timeout_ms"),
            Some(&serde_json::json!(5000))
        );
    }

    #[test]
    fn test_hook_input_local_shell_minimal() {
        let payload = ToolPayload::LocalShell {
            params: ShellToolCallParams {
                command: vec!["echo".to_string(), "test".to_string()],
                workdir: None,
                timeout_ms: None,
                sandbox_permissions: Some(SandboxPermissions::UseDefault),
                prefix_rule: None,
                justification: None,
            },
        };

        let input = payload.hook_input();
        assert!(input.is_object());

        // Should contain command field
        assert_eq!(
            input.get("command"),
            Some(&serde_json::json!(["echo", "test"]))
        );

        // workdir and timeout_ms should not be present when None
        assert_eq!(input.get("workdir"), None);
        assert_eq!(input.get("timeout_ms"), None);
    }

    #[test]
    fn test_hook_input_function_valid_json() {
        let payload = ToolPayload::Function {
            arguments: r#"{"path": "/tmp/test.txt", "mode": "read"}"#.to_string(),
        };

        let input = payload.hook_input();

        // Function arguments should be parsed as JSON object
        assert!(input.is_object());
        assert_eq!(
            input.get("path"),
            Some(&serde_json::json!("/tmp/test.txt"))
        );
        assert_eq!(
            input.get("mode"),
            Some(&serde_json::json!("read"))
        );
    }

    #[test]
    fn test_hook_input_function_invalid_json() {
        let payload = ToolPayload::Function {
            arguments: "not valid json".to_string(),
        };

        let input = payload.hook_input();

        // Invalid JSON should fallback to string
        assert_eq!(input, serde_json::json!("not valid json"));
    }

    #[test]
    fn test_hook_input_custom_valid_json() {
        let payload = ToolPayload::Custom {
            input: r#"{"action": "patch", "content": "diff"}"#.to_string(),
        };

        let input = payload.hook_input();

        // Custom input should be parsed as JSON object
        assert!(input.is_object());
        assert_eq!(
            input.get("action"),
            Some(&serde_json::json!("patch"))
        );
    }

    #[test]
    fn test_hook_input_custom_invalid_json() {
        let payload = ToolPayload::Custom {
            input: "plain text input".to_string(),
        };

        let input = payload.hook_input();

        // Invalid JSON should fallback to string
        assert_eq!(input, serde_json::json!("plain text input"));
    }

    #[test]
    fn test_hook_input_mcp_valid_json() {
        let payload = ToolPayload::Mcp {
            server: "test-server".to_string(),
            tool: "test-tool".to_string(),
            raw_arguments: r#"{"key": "value", "number": 42}"#.to_string(),
        };

        let input = payload.hook_input();

        // MCP arguments should be parsed as JSON object
        assert!(input.is_object());
        assert_eq!(
            input.get("key"),
            Some(&serde_json::json!("value"))
        );
        assert_eq!(
            input.get("number"),
            Some(&serde_json::json!(42))
        );
    }

    #[test]
    fn test_hook_input_mcp_invalid_json() {
        let payload = ToolPayload::Mcp {
            server: "test-server".to_string(),
            tool: "test-tool".to_string(),
            raw_arguments: "invalid".to_string(),
        };

        let input = payload.hook_input();

        // Invalid JSON should fallback to string
        assert_eq!(input, serde_json::json!("invalid"));
    }
}
