use crate::client_common::tools::ToolSpec;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::function_tool::FunctionCallError;
use crate::hooks::HookEvent;
use crate::hooks::HookEventPostToolUse;
use crate::hooks::HookEventPostToolUseFailure;
use crate::hooks::HookEventPreToolUse;
use crate::hooks::EffectAction;
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
        "local_shell" => "Bash".to_string(),
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
            EffectAction::Proceed | EffectAction::StopProcessing => {
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

        let invocation = ToolInvocation {
            session: Arc::clone(&session),
            turn: Arc::clone(&turn),
            tracker,
            call_id,
            tool_name: tool_name.clone(),
            payload,
        };

        let result = match self.registry.dispatch(invocation).await {
            Ok(response) => Ok(response),
            Err(FunctionCallError::Fatal(message)) => Err(FunctionCallError::Fatal(message)),
            Err(err) => {
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

        // --- PostToolUse hook ---
        // Awaited inline so hooks can inspect/modify tool output and inject
        // system messages.  PostToolUse is non-blockable so a Block decision
        // from the hook is treated as a warning.
        if let Ok(ref response) = result {
            let tool_output = Self::extract_output_text(response);
            let post_outcome = session
                .hooks()
                .dispatch(HookPayload::new(
                    session.conversation_id,
                    turn.cwd.clone(),
                    HookEvent::PostToolUse {
                        event: HookEventPostToolUse {
                            tool_name: hook_name,
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
            }
        }

        result
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
