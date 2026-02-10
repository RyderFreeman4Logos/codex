# Codex Hook Examples

This directory contains example hook scripts compatible with both Claude Code and Codex.

## What Are Hooks?

Hooks are external scripts that Codex executes at specific lifecycle events. They receive JSON payloads on stdin and can output JSON on stdout to control behavior (e.g., blocking tool execution).

Codex supports 14 hook events:
- **SessionStart/SessionEnd**: Beginning and end of conversation sessions
- **TurnStart/TurnEnd**: Beginning and end of each AI turn
- **PreToolUse/PostToolUse**: Before and after each tool execution
- **PreToolOutput/PostToolOutput**: When tool output is processed
- **PreModelRequest/PostModelResponse**: Before/after API calls
- **Error**: When errors occur
- **Notification**: When notifications are sent
- **PreCompact/PostCompact**: Before/after context compaction

## Configuring Hooks

Add hooks to your `config.toml`:

```toml
[[hooks.pre_tool_use]]
command = "bash ./examples/hooks/pre-tool-check.sh"
matcher = "^Bash$"  # Only trigger for Bash tool

[[hooks.session_start]]
command = "bash ./examples/hooks/session-logger.sh"

[[hooks.session_end]]
command = "bash ./examples/hooks/session-logger.sh"

[[hooks.notification]]
command = "bash ./examples/hooks/notification-desktop.sh"
async = true  # Don't wait for completion
```

## Example Scripts

### `pre-tool-check.sh`
**Event:** PreToolUse
**Purpose:** Validates tool usage before execution

Blocks dangerous commands:
- `rm -rf /` and similar destructive patterns
- Force push to main branch

Returns JSON:
- `{"decision": "proceed"}` - Allow execution
- `{"decision": "block", "reason": "..."}` - Block with reason

### `session-logger.sh`
**Events:** SessionStart, SessionEnd
**Purpose:** Logs session lifecycle to `.codex/logs/sessions.log`

Records:
- Session start with ID, source, and working directory
- Session end with termination reason
- Timestamps for all events

If `CLAUDE_ENV_FILE` is set, exports `SESSION_LOG_FILE` environment variable.

### `notification-desktop.sh`
**Event:** Notification
**Purpose:** Forwards notifications to desktop notification system

Supports:
- Linux: `notify-send` (libnotify)
- macOS: `osascript` (AppleScript)

Maps severity levels to notification urgency (error/warn → critical).

## Hook Script Requirements

All hook scripts must:

1. **Use bash shebang**: `#!/usr/bin/env bash`
2. **Set strict mode**: `set -euo pipefail`
3. **Read JSON from stdin**: `PAYLOAD=$(cat)`
4. **Parse with jq**: Extract fields from JSON payload
5. **Output valid JSON** (or nothing for async hooks):
   - Blocking hooks: `{"decision": "proceed"}` or `{"decision": "block", "reason": "..."}`
   - Async hooks: Can exit without output
6. **Be executable**: `chmod +x script.sh`

## Common JSON Fields

All events include:
- `hook_event_name`: The event type (e.g., "PreToolUse")
- `session_id`: Unique session identifier
- `cwd`: Current working directory
- `triggered_at`: ISO 8601 timestamp

Event-specific fields:
- **PreToolUse**: `tool_name`, `tool_input`
- **PostToolUse**: `tool_name`, `tool_input`, `tool_output`, `elapsed_ms`
- **SessionStart**: `source` (e.g., "cli", "web")
- **SessionEnd**: `reason` (e.g., "user_exit", "timeout")
- **Notification**: `level` (info/warn/error), `message`, `title`

## Environment Variables

Available in hooks:
- `CODEX_PROJECT_DIR`: Project root directory
- `CLAUDE_ENV_FILE`: Path to write environment variables (SessionStart only)

## Testing Hooks

Test a hook script manually:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"{\"command\":\"rm -rf /\"}"}' | \
  bash examples/hooks/pre-tool-check.sh | jq .
```

Expected output:
```json
{"decision": "block", "reason": "Blocked dangerous rm -rf / command"}
```

## Security Considerations

- Hooks run with the same permissions as Codex
- Validate all input from JSON payloads
- Use `set -euo pipefail` to catch errors
- Be cautious with async hooks that modify state
- Test hooks thoroughly before deploying

## Further Reading

- [Codex Hooks JSON Schema](../../codex-rs/src/hooks/schema.json)
- [Hook Implementation](../../codex-rs/src/hooks/mod.rs)
- [Configuration Documentation](../../docs/config.md)
