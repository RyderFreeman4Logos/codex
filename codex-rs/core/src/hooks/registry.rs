use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::process::Command;
use tokio::sync::Semaphore;

use super::config::hooks_from_group;
use super::types::EffectAction;
use super::types::Hook;
use super::types::HookAggregateEffect;
use super::types::HookEvent;
use super::types::HookOutcome;
use super::types::HookPayload;
use super::types::HookResult;
use super::user_notification::notify_hook;
use crate::config::Config;

/// Maximum number of hooks that can execute concurrently.
const MAX_CONCURRENT_HOOKS: usize = 10;

#[derive(Clone)]
pub(crate) struct Hooks {
    after_agent: Vec<Hook>,
    pre_tool_use: Vec<Hook>,
    post_tool_use: Vec<Hook>,
    session_start: Vec<Hook>,
    session_end: Vec<Hook>,
    post_tool_use_failure: Vec<Hook>,
    /// Semaphore to limit concurrent hook executions.
    semaphore: Arc<Semaphore>,
    /// Tracks which once-hooks have already fired (event_name + hook_index).
    once_fired: Arc<Mutex<HashSet<String>>>,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            after_agent: Vec::new(),
            pre_tool_use: Vec::new(),
            post_tool_use: Vec::new(),
            session_start: Vec::new(),
            session_end: Vec::new(),
            post_tool_use_failure: Vec::new(),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HOOKS)),
            once_fired: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

fn get_notify_hook(config: &Config) -> Option<Hook> {
    config
        .notify
        .as_ref()
        .filter(|argv| !argv.is_empty() && !argv[0].is_empty())
        .map(|argv| notify_hook(argv.clone()))
}

// Hooks are arbitrary, user-specified functions that are deterministically
// executed after specific events in the Codex lifecycle.
impl Hooks {
    // new creates a new Hooks instance from config.
    // For legacy compatibility, if config.notify is set, it will be added to
    // the after_agent hooks. New-style hooks from [hooks] config section are
    // appended after legacy hooks.
    pub(crate) fn new(config: &Config) -> Self {
        let hooks_config = &config.hooks;

        if hooks_config.disable_all_hooks {
            tracing::info!("All hooks disabled via disable_all_hooks config");
            return Self::default();
        }

        let mut after_agent: Vec<Hook> = get_notify_hook(config).into_iter().collect();
        after_agent.extend(
            hooks_config
                .after_agent
                .iter()
                .flat_map(hooks_from_group),
        );

        let pre_tool_use: Vec<Hook> = hooks_config
            .pre_tool_use
            .iter()
            .flat_map(hooks_from_group)
            .collect();
        let post_tool_use: Vec<Hook> = hooks_config
            .post_tool_use
            .iter()
            .flat_map(hooks_from_group)
            .collect();
        let session_start: Vec<Hook> = hooks_config
            .session_start
            .iter()
            .flat_map(hooks_from_group)
            .collect();
        let session_end: Vec<Hook> = hooks_config
            .session_end
            .iter()
            .flat_map(hooks_from_group)
            .collect();
        let post_tool_use_failure: Vec<Hook> = hooks_config
            .post_tool_use_failure
            .iter()
            .flat_map(hooks_from_group)
            .collect();

        // Log hook counts for events that have hooks
        if !after_agent.is_empty() {
            tracing::info!(event = "after_agent", count = after_agent.len(), "Hooks loaded");
        }
        if !pre_tool_use.is_empty() {
            tracing::info!(event = "pre_tool_use", count = pre_tool_use.len(), "Hooks loaded");
        }
        if !post_tool_use.is_empty() {
            tracing::info!(event = "post_tool_use", count = post_tool_use.len(), "Hooks loaded");
        }
        if !session_start.is_empty() {
            tracing::info!(event = "session_start", count = session_start.len(), "Hooks loaded");
        }
        if !session_end.is_empty() {
            tracing::info!(event = "session_end", count = session_end.len(), "Hooks loaded");
        }
        if !post_tool_use_failure.is_empty() {
            tracing::info!(event = "post_tool_use_failure", count = post_tool_use_failure.len(), "Hooks loaded");
        }

        Self {
            after_agent,
            pre_tool_use,
            post_tool_use,
            session_start,
            session_end,
            post_tool_use_failure,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_HOOKS)),
            once_fired: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn hooks_for_event(&self, hook_event: &HookEvent) -> &[Hook] {
        match hook_event {
            HookEvent::AfterAgent { .. } => &self.after_agent,
            HookEvent::PreToolUse { .. } => &self.pre_tool_use,
            HookEvent::PostToolUse { .. } => &self.post_tool_use,
            HookEvent::SessionStart { .. } => &self.session_start,
            HookEvent::SessionEnd { .. } => &self.session_end,
            HookEvent::PostToolUseFailure { .. } => &self.post_tool_use_failure,
        }
    }

    /// Dispatch hooks for the given event and return the aggregate effect.
    ///
    /// Hooks are separated into sync and async execution:
    ///
    /// - **Sync hooks** (is_async=false): Executed **in parallel** (up to
    ///   [`MAX_CONCURRENT_HOOKS`] concurrently) and their results are
    ///   aggregated in **config order** to ensure deterministic output.
    ///
    /// - **Async hooks** (is_async=true): Spawned as fire-and-forget tasks
    ///   via `tokio::spawn`. Their results are ignored and do NOT affect
    ///   the aggregate effect. Logged at debug level when complete.
    ///
    /// - **Once hooks** (once=true): Only execute once per session. Tracked
    ///   by event name + hook index. Skipped on subsequent dispatches.
    ///
    /// Aggregation rules for sync hooks:
    /// - If any hook returns `Block`, the final action is `Block` (first
    ///   Block in config order wins for the reason message).
    /// - If any hook returns `Modify`, the last `Modify` in config order
    ///   wins and is stored in [`HookAggregateEffect::modified_content`].
    /// - System messages, stop reasons, status messages, and suppress_output
    ///   flags are collected from all hooks in config order.
    /// - Otherwise the action is `Proceed`.
    pub(crate) async fn dispatch(&self, hook_payload: HookPayload) -> HookAggregateEffect {
        let hooks = self.hooks_for_event(&hook_payload.hook_event);
        if hooks.is_empty() {
            return HookAggregateEffect::default();
        }

        let event_name = &hook_payload.hook_event_name;
        tracing::debug!(event = %event_name, hook_count = hooks.len(), "Dispatching hooks");

        let is_session_start = matches!(hook_payload.hook_event, HookEvent::SessionStart { .. });

        // Filter hooks based on once tracking and separate sync/async.
        let mut sync_hooks_with_idx = Vec::new();
        let mut async_hooks_with_idx = Vec::new();

        for (idx, hook) in hooks.iter().enumerate() {
            // Check matcher BEFORE once tracking — a non-matching event must
            // not consume the once slot so the hook can still fire later when
            // a matching event arrives.
            if !hook.matches_event(&hook_payload.hook_event) {
                tracing::debug!(event = %event_name, hook_idx = idx, "Skipping hook (matcher did not match)");
                continue;
            }

            // Check if this is a once-hook that has already fired.
            if hook.once {
                let once_key = format!("{event_name}:{idx}");
                let Ok(mut fired) = self.once_fired.lock() else {
                    tracing::warn!("Once-fired mutex poisoned, skipping once check");
                    continue;
                };
                if fired.contains(&once_key) {
                    // Skip this hook, it's already fired.
                    tracing::debug!(event = %event_name, hook_idx = idx, "Skipping once-hook (already fired)");
                    continue;
                }
                // Mark as fired — only reached after matcher confirmed a match.
                fired.insert(once_key);
            }

            let hook_type = if hook.is_async { "async" } else { "sync" };
            tracing::debug!(
                event = %event_name,
                hook_idx = idx,
                hook_type = hook_type,
                once = hook.once,
                "Executing hook"
            );

            if hook.is_async {
                async_hooks_with_idx.push((idx, hook));
            } else {
                sync_hooks_with_idx.push((idx, hook));
            }
        }

        // Spawn async hooks as fire-and-forget tasks, throttled by the
        // same semaphore to prevent unbounded concurrent processes.
        for (_idx, hook) in async_hooks_with_idx {
            let hook = hook.clone();
            let payload = hook_payload.clone();
            let sem = self.semaphore.clone();
            tokio::spawn(async move {
                let Ok(_permit) = sem.acquire_owned().await else {
                    tracing::warn!(
                        event = %payload.hook_event_name,
                        "Async hook semaphore closed, skipping"
                    );
                    return;
                };
                let result = hook.execute(&payload).await;
                tracing::debug!(
                    event = %payload.hook_event_name,
                    outcome = ?result.outcome,
                    "Async hook completed"
                );
            });
        }

        // Execute sync hooks concurrently with semaphore-based throttling.
        if sync_hooks_with_idx.is_empty() {
            return HookAggregateEffect::default();
        }

        let semaphore = &self.semaphore;
        let payload_ref = &hook_payload;

        // For SessionStart, each hook gets its own env file to avoid
        // concurrent writes to a shared temp file.
        let results: Vec<(usize, HookResult)> = if is_session_start {
            // Create per-hook env files so concurrent hooks don't clobber each other.
            let mut env_file_guards: Vec<Option<tempfile::NamedTempFile>> =
                Vec::with_capacity(sync_hooks_with_idx.len());
            let mut per_hook_payloads: Vec<HookPayload> =
                Vec::with_capacity(sync_hooks_with_idx.len());

            for _ in &sync_hooks_with_idx {
                let mut p = hook_payload.clone();
                match tempfile::NamedTempFile::new() {
                    Ok(file) => {
                        p.env_file_path = Some(file.path().to_path_buf());
                        env_file_guards.push(Some(file));
                    }
                    Err(err) => {
                        tracing::warn!("failed to create per-hook env file: {err}");
                        env_file_guards.push(None);
                    }
                }
                per_hook_payloads.push(p);
            }

            let payloads_ref = &per_hook_payloads;
            futures::future::join_all(
                sync_hooks_with_idx
                    .iter()
                    .enumerate()
                    .map(|(i, (idx, hook))| async move {
                        let Ok(_permit) = semaphore.acquire().await else {
                            return (*idx, HookResult::default());
                        };
                        (*idx, hook.execute(&payloads_ref[i]).await)
                    }),
            )
            .await
            // env_file_guards dropped here, cleaning up temp files
        } else {
            futures::future::join_all(sync_hooks_with_idx.iter().map(|(idx, hook)| async move {
                let Ok(_permit) = semaphore.acquire().await else {
                    return (*idx, HookResult::default());
                };
                (*idx, hook.execute(payload_ref).await)
            }))
            .await
        };

        // Aggregate results in config order (deterministic).
        let mut effect = HookAggregateEffect::default();

        // Collect status messages from hooks that have them (before execution).
        for (_idx, hook) in &sync_hooks_with_idx {
            if let Some(ref status_msg) = hook.status_message {
                effect.status_messages.push(status_msg.clone());
            }
        }

        for (_idx, result) in results {
            // Collect metadata from this hook's output.
            if let Some(msg) = result.meta.system_message {
                effect.system_messages.push(msg);
            }
            if let Some(sr) = result.meta.stop_reason {
                effect.stop_reason = Some(sr);
            }
            if let Some(so) = result.meta.suppress_output {
                effect.suppress_output = so;
            }

            // Merge environment variables (later hooks override earlier ones)
            for (key, value) in result.env_vars {
                effect.env_vars.insert(key, value);
            }

            match result.outcome {
                HookOutcome::Block { message } => {
                    // First Block in config order wins; subsequent Blocks
                    // are ignored for the action but their metadata is still
                    // collected above.
                    if effect.action == EffectAction::Proceed {
                        effect.action = EffectAction::Block {
                            reason: message
                                .unwrap_or_else(|| "Blocked by hook".to_string()),
                        };
                    }
                }
                HookOutcome::Modify { content } => {
                    // Last Modify in config order wins.
                    effect.modified_content = Some(content);
                }
                HookOutcome::Proceed => {}
            }
        }

        // Log aggregated result
        tracing::debug!(
            event = %event_name,
            action = ?effect.action,
            system_messages = effect.system_messages.len(),
            env_vars = effect.env_vars.len(),
            "Hook dispatch completed"
        );

        effect
    }
}

/// Build a Command from a CommandSpec.
///
/// - Shell strings are executed via `sh -c` (or `cmd /C` on Windows)
/// - Argv arrays are executed directly
pub(super) fn command_from_spec(spec: &super::config::CommandSpec) -> Option<Command> {
    use super::config::CommandSpec;

    match spec {
        CommandSpec::Shell(cmd) => {
            if cmd.is_empty() {
                return None;
            }
            let command = if cfg!(windows) {
                let mut c = Command::new("cmd");
                c.args(["/C", cmd]);
                c
            } else {
                let mut c = Command::new("sh");
                c.args(["-c", cmd]);
                c
            };
            Some(command)
        }
        CommandSpec::Argv(argv) => {
            let (program, args) = argv.split_first()?;
            if program.is_empty() {
                return None;
            }
            let mut command = Command::new(program);
            command.args(args);
            Some(command)
        }
    }
}

/// Legacy helper for notify_hook (which still uses Vec<String>).
/// Converts Vec<String> to CommandSpec::Argv and delegates to command_from_spec.
pub(super) fn command_from_argv(argv: &[String]) -> Option<Command> {
    use super::config::CommandSpec;
    command_from_spec(&CommandSpec::Argv(argv.to_vec()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use anyhow::Result;
    use chrono::TimeZone;
    use chrono::Utc;
    use codex_protocol::ThreadId;
    use pretty_assertions::assert_eq;
    use serde_json::to_string;
    use tempfile::tempdir;
    use tokio::time::timeout;

    use crate::config::test_config;

    use super::super::types::EffectAction;
    use super::super::types::Hook;
    use super::super::types::HookAggregateEffect;
    use super::super::types::HookEvent;
    use super::super::types::HookEventAfterAgent;
    use super::super::types::HookOutcome;
    use super::super::types::HookPayload;
    use super::super::types::HookResult;
    use super::Hooks;
    use super::command_from_argv;
    use super::get_notify_hook;

    const CWD: &str = "/tmp";
    const INPUT_MESSAGE: &str = "hello";

    fn hook_payload(label: &str) -> HookPayload {
        let hook_event = HookEvent::AfterAgent {
            event: HookEventAfterAgent {
                thread_id: ThreadId::new(),
                turn_id: format!("turn-{label}"),
                input_messages: vec![INPUT_MESSAGE.to_string()],
                last_assistant_message: Some("hi".to_string()),
            },
        };
        HookPayload {
            session_id: ThreadId::new(),
            cwd: PathBuf::from(CWD),
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

    fn counting_hook(calls: &Arc<AtomicUsize>, outcome: HookOutcome) -> Hook {
        let calls = Arc::clone(calls);
        Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(move |_| {
                let calls = Arc::clone(&calls);
                let outcome = outcome.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    HookResult::from(outcome)
                })
            }),
        }
    }

    fn hooks_for_after_agent(hooks: Vec<Hook>) -> Hooks {
        Hooks {
            after_agent: hooks,
            ..Default::default()
        }
    }

    fn hooks_for_pre_tool_use(hooks: Vec<Hook>) -> Hooks {
        Hooks {
            pre_tool_use: hooks,
            ..Default::default()
        }
    }

    fn hooks_for_post_tool_use(hooks: Vec<Hook>) -> Hooks {
        Hooks {
            post_tool_use: hooks,
            ..Default::default()
        }
    }

    fn hook_payload_pre_tool_use(label: &str) -> HookPayload {
        use super::super::types::HookEventPreToolUse;

        let hook_event = HookEvent::PreToolUse {
            event: HookEventPreToolUse {
                tool_name: format!("tool-{label}"),
                tool_input: serde_json::json!({"arg": "value"}),
            },
        };
        HookPayload {
            session_id: ThreadId::new(),
            cwd: PathBuf::from(CWD),
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

    fn hook_payload_post_tool_use(label: &str) -> HookPayload {
        use super::super::types::HookEventPostToolUse;
        use serde_json::json;

        let hook_event = HookEvent::PostToolUse {
            event: HookEventPostToolUse {
                tool_name: format!("tool-{label}"),
                tool_input: json!({"test": "input"}),
                tool_output: "success".to_string(),
            },
        };
        HookPayload {
            session_id: ThreadId::new(),
            cwd: PathBuf::from(CWD),
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

    #[test]
    fn command_from_argv_returns_none_for_empty_args() {
        assert!(command_from_argv(&[]).is_none());
        assert!(command_from_argv(&["".to_string()]).is_none());
    }

    #[test]
    fn command_from_spec_shell_empty_returns_none() {
        use super::super::config::CommandSpec;
        use super::command_from_spec;
        assert!(command_from_spec(&CommandSpec::Shell(String::new())).is_none());
    }

    #[test]
    fn command_from_spec_argv_empty_returns_none() {
        use super::super::config::CommandSpec;
        use super::command_from_spec;
        assert!(command_from_spec(&CommandSpec::Argv(Vec::new())).is_none());
        assert!(command_from_spec(&CommandSpec::Argv(vec!["".to_string()])).is_none());
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn command_from_spec_shell_executes_via_sh() -> Result<()> {
        use super::super::config::CommandSpec;
        use super::command_from_spec;
        use std::process::Stdio;

        let spec = CommandSpec::Shell("echo hello world".to_string());
        let mut command = command_from_spec(&spec).ok_or_else(|| anyhow::anyhow!("command"))?;
        let output = command.stdout(Stdio::piped()).output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim_end_matches(['\r', '\n']);
        assert_eq!(trimmed, "hello world");
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn command_from_spec_shell_executes_via_cmd() -> Result<()> {
        use super::super::config::CommandSpec;
        use super::command_from_spec;
        use std::process::Stdio;

        let spec = CommandSpec::Shell("echo hello world".to_string());
        let mut command = command_from_spec(&spec).ok_or_else(|| anyhow::anyhow!("command"))?;
        let output = command.stdout(Stdio::piped()).output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim_end_matches(['\r', '\n']);
        assert_eq!(trimmed, "hello world");
        Ok(())
    }

    #[tokio::test]
    async fn command_from_argv_builds_command() -> Result<()> {
        let argv = if cfg!(windows) {
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "echo hello world".to_string(),
            ]
        } else {
            vec!["echo".to_string(), "hello".to_string(), "world".to_string()]
        };
        let mut command = command_from_argv(&argv).ok_or_else(|| anyhow::anyhow!("command"))?;
        let output = command.stdout(Stdio::piped()).output().await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim_end_matches(['\r', '\n']);
        assert_eq!(trimmed, "hello world");
        Ok(())
    }

    #[test]
    fn get_notify_hook_requires_program_name() {
        let mut config = test_config();

        config.notify = Some(vec![]);
        assert!(get_notify_hook(&config).is_none());

        config.notify = Some(vec!["".to_string()]);
        assert!(get_notify_hook(&config).is_none());

        config.notify = Some(vec!["notify-send".to_string()]);
        assert!(get_notify_hook(&config).is_some());
    }

    #[tokio::test]
    async fn dispatch_executes_hook() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks = hooks_for_after_agent(vec![counting_hook(&calls, HookOutcome::Proceed)]);

        hooks.dispatch(hook_payload("1")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn default_hook_is_noop_and_proceeds() {
        let payload = hook_payload("d");
        let result = Hook::default().execute(&payload).await;
        assert_eq!(result.outcome, HookOutcome::Proceed);
    }

    #[tokio::test]
    async fn dispatch_executes_multiple_hooks_for_same_event() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks = hooks_for_after_agent(vec![
            counting_hook(&calls, HookOutcome::Proceed),
            counting_hook(&calls, HookOutcome::Proceed),
        ]);

        hooks.dispatch(hook_payload("2")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn dispatch_block_runs_all_hooks_but_aggregates_block() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks = hooks_for_after_agent(vec![
            counting_hook(&calls, HookOutcome::Block { message: None }),
            counting_hook(&calls, HookOutcome::Proceed),
        ]);

        let effect = hooks.dispatch(hook_payload("3")).await;
        // Parallel: all hooks execute regardless of individual outcomes.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // But the aggregate action is still Block.
        assert_eq!(
            effect.action,
            EffectAction::Block {
                reason: "Blocked by hook".to_string()
            }
        );
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn hook_executes_program_with_payload_argument_unix() -> Result<()> {
        let temp_dir = tempdir()?;
        let payload_path = temp_dir.path().join("payload.json");
        let payload_path_arg = payload_path.to_string_lossy().into_owned();
        let hook = Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(move |payload: &HookPayload| {
                let payload_path_arg = payload_path_arg.clone();
                Box::pin(async move {
                    let json = to_string(payload).expect("serialize hook payload");
                    let mut command = command_from_argv(&[
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "printf '%s' \"$2\" > \"$1\"".to_string(),
                        "sh".to_string(),
                        payload_path_arg,
                        json,
                    ])
                    .expect("build command");
                    command.status().await.expect("run hook command");
                    HookResult::from(HookOutcome::Proceed)
                })
            }),
        };

        let payload = hook_payload("4");
        let expected = to_string(&payload)?;

        let hooks = hooks_for_after_agent(vec![hook]);
        hooks.dispatch(payload).await;

        let contents = timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = fs::read_to_string(&payload_path)
                    && !contents.is_empty()
                {
                    return contents;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;

        assert_eq!(contents, expected);
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn hook_executes_program_with_payload_argument_windows() -> Result<()> {
        let temp_dir = tempdir()?;
        let payload_path = temp_dir.path().join("payload.json");
        let payload_path_arg = payload_path.to_string_lossy().into_owned();
        let script_path = temp_dir.path().join("write_payload.ps1");
        fs::write(&script_path, "[IO.File]::WriteAllText($args[0], $args[1])")?;
        let script_path_arg = script_path.to_string_lossy().into_owned();
        let hook = Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(move |payload: &HookPayload| {
                let payload_path_arg = payload_path_arg.clone();
                let script_path_arg = script_path_arg.clone();
                Box::pin(async move {
                    let json = to_string(payload).expect("serialize hook payload");
                    let powershell = crate::powershell::try_find_powershell_executable_blocking()
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "powershell.exe".to_string());
                    let mut command = command_from_argv(&[
                        powershell,
                        "-NoLogo".to_string(),
                        "-NoProfile".to_string(),
                        "-ExecutionPolicy".to_string(),
                        "Bypass".to_string(),
                        "-File".to_string(),
                        script_path_arg,
                        payload_path_arg,
                        json,
                    ])
                    .expect("build command");
                    command.status().await.expect("run hook command");
                    HookResult::from(HookOutcome::Proceed)
                })
            }),
        };

        let payload = hook_payload("4");
        let expected = to_string(&payload)?;

        let hooks = hooks_for_after_agent(vec![hook]);
        hooks.dispatch(payload).await;

        let contents = timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(contents) = fs::read_to_string(&payload_path)
                    && !contents.is_empty()
                {
                    return contents;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;

        assert_eq!(contents, expected);
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_pre_tool_use_hooks_for_pre_tool_use_event() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks = hooks_for_pre_tool_use(vec![counting_hook(&calls, HookOutcome::Proceed)]);

        hooks.dispatch(hook_payload_pre_tool_use("1")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatch_post_tool_use_hooks_for_post_tool_use_event() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks = hooks_for_post_tool_use(vec![counting_hook(&calls, HookOutcome::Proceed)]);

        hooks.dispatch(hook_payload_post_tool_use("1")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatch_does_not_fire_hooks_for_different_event_type() {
        let calls_after = Arc::new(AtomicUsize::new(0));
        let calls_pre = Arc::new(AtomicUsize::new(0));

        let hooks = Hooks {
            after_agent: vec![counting_hook(&calls_after, HookOutcome::Proceed)],
            pre_tool_use: vec![counting_hook(&calls_pre, HookOutcome::Proceed)],
            ..Default::default()
        };

        // Dispatch PreToolUse event should not fire after_agent hooks
        hooks.dispatch(hook_payload_pre_tool_use("1")).await;
        assert_eq!(calls_after.load(Ordering::SeqCst), 0);
        assert_eq!(calls_pre.load(Ordering::SeqCst), 1);

        // Dispatch AfterAgent event should not fire pre_tool_use hooks
        hooks.dispatch(hook_payload("2")).await;
        assert_eq!(calls_after.load(Ordering::SeqCst), 1);
        assert_eq!(calls_pre.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatch_modify_outcome_is_carried_forward() {
        let hooks = hooks_for_after_agent(vec![
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult::from(HookOutcome::Modify {
                            content: "first".to_string(),
                        })
                    })
                }),
            },
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| Box::pin(async { HookResult::from(HookOutcome::Proceed) })),
            },
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult::from(HookOutcome::Modify {
                            content: "second".to_string(),
                        })
                    })
                }),
            },
        ]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        // Last Modify wins
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(
            effect.modified_content,
            Some("second".to_string())
        );
    }

    #[tokio::test]
    async fn dispatch_modify_returned_after_all_hooks_run() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hooks = hooks_for_after_agent(vec![
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult::from(HookOutcome::Modify {
                            content: "modified".to_string(),
                        })
                    })
                }),
            },
            counting_hook(&calls, HookOutcome::Proceed),
            counting_hook(&calls, HookOutcome::Proceed),
        ]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2); // Both subsequent hooks ran
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(
            effect.modified_content,
            Some("modified".to_string())
        );
    }

    #[tokio::test]
    async fn dispatch_proceed_returns_default_aggregate_effect() {
        let hooks = hooks_for_after_agent(vec![
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| Box::pin(async { HookResult::from(HookOutcome::Proceed) })),
            },
        ]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(effect.modified_content, None);
        assert_eq!(effect, HookAggregateEffect::default());
    }

    #[tokio::test]
    async fn dispatch_block_returns_block_aggregate_effect() {
        let hooks = hooks_for_after_agent(vec![Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    HookResult::from(HookOutcome::Block {
                        message: Some("denied".to_string()),
                    })
                })
            }),
        }]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(
            effect.action,
            EffectAction::Block {
                reason: "denied".to_string()
            }
        );
        assert_eq!(effect.modified_content, None);
    }

    #[tokio::test]
    async fn dispatch_block_without_message_uses_default_reason() {
        let hooks = hooks_for_after_agent(vec![Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async { HookResult::from(HookOutcome::Block { message: None }) })
            }),
        }]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(
            effect.action,
            EffectAction::Block {
                reason: "Blocked by hook".to_string()
            }
        );
    }

    /// Proves hooks execute concurrently by using a barrier that requires
    /// all hooks to arrive before any can proceed.  If hooks were sequential,
    /// the first hook would deadlock waiting at the barrier.
    #[tokio::test]
    async fn dispatch_hooks_execute_in_parallel() {
        use std::sync::Barrier;

        let n = 3;
        let barrier = Arc::new(Barrier::new(n));
        let calls = Arc::new(AtomicUsize::new(0));

        let hooks: Vec<Hook> = (0..n)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let calls = Arc::clone(&calls);
                Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(move |_| {
                        let barrier = Arc::clone(&barrier);
                        let calls = Arc::clone(&calls);
                        Box::pin(async move {
                            // Use spawn_blocking because std::Barrier blocks the thread.
                            let barrier_clone = Arc::clone(&barrier);
                            tokio::task::spawn_blocking(move || {
                                barrier_clone.wait();
                            })
                            .await
                            .expect("barrier task");
                            calls.fetch_add(1, Ordering::SeqCst);
                            HookResult::from(HookOutcome::Proceed)
                        })
                    }),
                }
            })
            .collect();

        let hooks = hooks_for_after_agent(hooks);
        let effect = timeout(Duration::from_secs(5), hooks.dispatch(hook_payload("par")))
            .await
            .expect("parallel hooks should not deadlock");

        assert_eq!(calls.load(Ordering::SeqCst), n);
        assert_eq!(effect.action, EffectAction::Proceed);
    }

    /// When multiple hooks return Block, the first Block in config order wins.
    #[tokio::test]
    async fn dispatch_first_block_in_config_order_wins() {
        let hooks = hooks_for_after_agent(vec![
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult::from(HookOutcome::Block {
                            message: Some("first".to_string()),
                        })
                    })
                }),
            },
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult::from(HookOutcome::Block {
                            message: Some("second".to_string()),
                        })
                    })
                }),
            },
        ]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(
            effect.action,
            EffectAction::Block {
                reason: "first".to_string()
            }
        );
    }

    /// Metadata (system_message, stop_reason, suppress_output) is collected
    /// from all hooks in config order.
    #[tokio::test]
    async fn dispatch_collects_metadata_from_all_hooks() {
        use super::super::types::HookOutputMeta;

        let hooks = hooks_for_after_agent(vec![
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult {
                            outcome: HookOutcome::Proceed,
                            meta: HookOutputMeta {
                                system_message: Some("msg1".to_string()),
                                stop_reason: Some("reason1".to_string()),
                                suppress_output: Some(false),
                            },
                            env_vars: HashMap::new(),
                        }
                    })
                }),
            },
            Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                    Box::pin(async {
                        HookResult {
                            outcome: HookOutcome::Proceed,
                            meta: HookOutputMeta {
                                system_message: Some("msg2".to_string()),
                                stop_reason: Some("reason2".to_string()),
                                suppress_output: Some(true),
                            },
                            env_vars: HashMap::new(),
                        }
                    })
                }),
            },
        ]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(effect.system_messages, vec!["msg1", "msg2"]);
        // Last writer wins for stop_reason.
        assert_eq!(effect.stop_reason, Some("reason2".to_string()));
        // Last writer wins for suppress_output.
        assert!(effect.suppress_output);
    }

    /// Async hooks are spawned as fire-and-forget and don't block dispatch.
    #[tokio::test]
    async fn dispatch_async_hooks_dont_block() {
        use std::time::Duration;
        use tokio::time::Instant;

        let slow_async_hook = Hook {
            is_async: true,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    HookResult::from(HookOutcome::Proceed)
                })
            }),
        };

        let hooks = hooks_for_after_agent(vec![slow_async_hook]);

        let start = Instant::now();
        let effect = hooks.dispatch(hook_payload("1")).await;
        let elapsed = start.elapsed();

        // Dispatch should return immediately (< 50ms) even though async hook takes 100ms
        assert!(elapsed < Duration::from_millis(50));
        // Async hook results don't affect aggregate effect
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(effect.modified_content, None);
    }

    /// Async hooks results don't affect aggregate effect.
    #[tokio::test]
    async fn dispatch_async_hooks_results_ignored() {
        let async_block_hook = Hook {
            is_async: true,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    HookResult::from(HookOutcome::Block {
                        message: Some("should be ignored".to_string()),
                    })
                })
            }),
        };

        let async_modify_hook = Hook {
            is_async: true,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    HookResult::from(HookOutcome::Modify {
                        content: "should be ignored".to_string(),
                    })
                })
            }),
        };

        let hooks = hooks_for_after_agent(vec![async_block_hook, async_modify_hook]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        // Async hooks don't affect the aggregate effect
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(effect.modified_content, None);
    }

    /// Mix of sync and async hooks: only sync hooks affect result.
    #[tokio::test]
    async fn dispatch_mixed_sync_async_hooks() {
        let sync_hook = Hook {
            is_async: false,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    HookResult::from(HookOutcome::Modify {
                        content: "sync modified".to_string(),
                    })
                })
            }),
        };

        let async_hook = Hook {
            is_async: true,
            once: false,
            status_message: None,
        matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    HookResult::from(HookOutcome::Block {
                        message: Some("async block ignored".to_string()),
                    })
                })
            }),
        };

        let hooks = hooks_for_after_agent(vec![async_hook, sync_hook]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        // Only sync hook affects result
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(effect.modified_content, Some("sync modified".to_string()));
    }

    /// Hooks with once=true only execute once per session.
    #[tokio::test]
    async fn dispatch_once_hook_executes_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let once_hook = Hook {
            is_async: false,
            once: true,
            status_message: None,
        matcher: None,
            func: Arc::new(move |_| {
                let calls = Arc::clone(&calls_clone);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    HookResult::from(HookOutcome::Proceed)
                })
            }),
        };

        let hooks = hooks_for_after_agent(vec![once_hook]);

        // First dispatch: hook should execute
        hooks.dispatch(hook_payload("1")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Second dispatch: hook should be skipped
        hooks.dispatch(hook_payload("2")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Third dispatch: still skipped
        hooks.dispatch(hook_payload("3")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Hooks without once=true execute every time.
    #[tokio::test]
    async fn dispatch_normal_hook_executes_every_time() {
        let calls = Arc::new(AtomicUsize::new(0));
        let normal_hook = counting_hook(&calls, HookOutcome::Proceed);

        let hooks = hooks_for_after_agent(vec![normal_hook]);

        hooks.dispatch(hook_payload("1")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        hooks.dispatch(hook_payload("2")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        hooks.dispatch(hook_payload("3")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// Status messages from hooks are collected in aggregate effect.
    #[tokio::test]
    async fn dispatch_status_messages_collected() {
        let hook1 = Hook {
            is_async: false,
            once: false,
            status_message: Some("Checking permissions...".to_string()),
            matcher: None,
            func: Arc::new(|_| Box::pin(async { HookResult::from(HookOutcome::Proceed) })),
        };

        let hook2 = Hook {
            is_async: false,
            once: false,
            status_message: Some("Running security audit...".to_string()),
            matcher: None,
            func: Arc::new(|_| Box::pin(async { HookResult::from(HookOutcome::Proceed) })),
        };

        let hook3 = Hook {
            is_async: false,
            once: false,
            status_message: None,
            matcher: None,
            func: Arc::new(|_| Box::pin(async { HookResult::from(HookOutcome::Proceed) })),
        };

        let hooks = hooks_for_after_agent(vec![hook1, hook2, hook3]);

        let effect = hooks.dispatch(hook_payload("1")).await;
        assert_eq!(effect.status_messages, vec![
            "Checking permissions...",
            "Running security audit..."
        ]);
    }

    /// SessionStart hooks receive CLAUDE_ENV_FILE and env_vars are aggregated
    #[tokio::test]
    async fn dispatch_session_start_creates_env_file() {
        use super::super::types::HookEventSessionStart;

        let hook_event = HookEvent::SessionStart {
            event: HookEventSessionStart {
                source: "cli".to_string(),
                model: "claude-opus-4-6".to_string(),
                agent_type: "codex".to_string(),
            },
        };
        let payload = HookPayload {
            session_id: ThreadId::new(),
            cwd: PathBuf::from(CWD),
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

        let hook1 = Hook {
            is_async: false,
            once: false,
            status_message: None,
            matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    let mut result = HookResult::from(HookOutcome::Proceed);
                    result.env_vars.insert("FOO".to_string(), "bar".to_string());
                    result
                })
            }),
        };

        let hook2 = Hook {
            is_async: false,
            once: false,
            status_message: None,
            matcher: None,
            func: Arc::new(|_| {
                Box::pin(async {
                    let mut result = HookResult::from(HookOutcome::Proceed);
                    result.env_vars.insert("BAZ".to_string(), "qux".to_string());
                    result.env_vars.insert("FOO".to_string(), "overridden".to_string());
                    result
                })
            }),
        };

        let hooks = Hooks {
            session_start: vec![hook1, hook2],
            ..Default::default()
        };

        let effect = hooks.dispatch(payload).await;
        assert_eq!(effect.action, EffectAction::Proceed);
        assert_eq!(effect.env_vars.len(), 2);
        assert_eq!(effect.env_vars.get("BAZ"), Some(&"qux".to_string()));
        // Later hook overrides earlier one
        assert_eq!(effect.env_vars.get("FOO"), Some(&"overridden".to_string()));
    }

    /// Multiple once-hooks are tracked independently by index.
    #[tokio::test]
    async fn dispatch_multiple_once_hooks_tracked_independently() {
        let calls1 = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::new(AtomicUsize::new(0));

        let calls1_clone = Arc::clone(&calls1);
        let once_hook1 = Hook {
            is_async: false,
            once: true,
            status_message: None,
            matcher: None,
            func: Arc::new(move |_| {
                let calls1 = Arc::clone(&calls1_clone);
                Box::pin(async move {
                    calls1.fetch_add(1, Ordering::SeqCst);
                    HookResult::from(HookOutcome::Proceed)
                })
            }),
        };

        let calls2_clone = Arc::clone(&calls2);
        let once_hook2 = Hook {
            is_async: false,
            once: true,
            status_message: None,
            matcher: None,
            func: Arc::new(move |_| {
                let calls2 = Arc::clone(&calls2_clone);
                Box::pin(async move {
                    calls2.fetch_add(1, Ordering::SeqCst);
                    HookResult::from(HookOutcome::Proceed)
                })
            }),
        };

        let hooks = hooks_for_after_agent(vec![once_hook1, once_hook2]);

        // First dispatch: both hooks execute
        hooks.dispatch(hook_payload("1")).await;
        assert_eq!(calls1.load(Ordering::SeqCst), 1);
        assert_eq!(calls2.load(Ordering::SeqCst), 1);

        // Second dispatch: both skipped
        hooks.dispatch(hook_payload("2")).await;
        assert_eq!(calls1.load(Ordering::SeqCst), 1);
        assert_eq!(calls2.load(Ordering::SeqCst), 1);
    }
}
