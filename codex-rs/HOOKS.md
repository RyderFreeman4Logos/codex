# Codex Hook System

## Overview

Hooks are external commands that run in response to lifecycle events during a Codex session. When a hook event occurs, Codex spawns a subprocess, sends event data as JSON on stdin, and reads the hook's response from stdout to determine how to proceed.

The hook system is designed to be compatible with [Claude Code's hooks specification](https://github.com/anthropics/claude-code), enabling the same hook scripts to work with both Codex and Claude Code.

**Key characteristics:**
- **Event-driven**: Hooks trigger at specific lifecycle points (before tool execution, after agent turn, etc.)
- **Subprocess isolation**: Each hook runs in a separate process with a timeout
- **JSON protocol**: Input payload and output decisions use structured JSON
- **Blockable vs non-blockable**: Some events can block operations (e.g., PreToolUse), others only observe (e.g., PostToolUse)

## Configuration

Hooks are configured in TOML files under the `[hooks]` section. Configuration files are loaded and merged from multiple layers:

1. **Global config**: `~/.codex/config.toml`
2. **Project config**: `.codex/config.toml` (in project root)
3. **Local config**: Any additional TOML files loaded by Codex

Hooks from all layers are **merged** (appended, not overwritten), so global hooks run first, followed by project-specific hooks, then local hooks.

### Configuration Format

Codex supports three configuration formats for maximum flexibility:

#### 1. Legacy Flat Format

```toml
[hooks]
# Simple hook with all options in one entry
[[hooks.pre_tool_use]]
command = ["./my-hook.sh"]
timeout = 30
matcher = "^Bash$"
async = false
once = false
status_message = "Running pre-tool check..."
```

#### 2. Shell String Format

```toml
[hooks]
# Use shell string instead of argv array
[[hooks.pre_tool_use]]
command = "bash ./my-hook.sh"
timeout = 30
matcher = "^Bash$"
```

Shell commands are executed via `sh -c` on Unix or `cmd /C` on Windows.

#### 3. Grouped Format (Recommended)

```toml
[hooks]
# Multiple commands sharing the same matcher
[[hooks.post_tool_use]]
matcher = "^Bash$"

[[hooks.post_tool_use.commands]]
command = ["./log-tool.sh"]
timeout = 10

[[hooks.post_tool_use.commands]]
command = ["./audit-tool.sh"]
timeout = 30
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `command` | String or Array | **Required** | Command to execute (shell string or argv array) |
| `timeout` | Integer | 600 | Timeout in seconds (max execution time) |
| `matcher` | String | `"*"` | Regex pattern to filter events (see Matcher Patterns below) |
| `async` | Boolean | false | Fire-and-forget execution (doesn't block dispatch) |
| `once` | Boolean | false | Execute only once per session |
| `status_message` | String | None | UI spinner text during execution |

### Matcher Patterns

The `matcher` field uses regex patterns to filter which events trigger a hook. Different event types have different matchable fields:

| Event Type | Matcher Field | Example |
|------------|---------------|---------|
| PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest | `tool_name` | `"^Bash$"` matches exactly "Bash" |
| SessionStart | `source` | `"cli"` matches CLI sessions |
| SessionEnd | `reason` | `"user_exit"` |
| Notification | `level` | `"error"` matches error notifications |
| SubagentStart, SubagentStop | `agent_type` | `"researcher.*"` |
| PreCompact | `trigger` | `"auto"` matches auto-compaction |

Special matcher values:
- `None` (omitted) → matches all events
- `""` (empty string) → matches all events
- `"*"` → matches all events
- Any other string → compiled as regex pattern

**Examples:**
```toml
# Match exact tool name
matcher = "^Bash$"

# Match MCP write tools
matcher = "mcp__.*__write.*"

# Match any tool name starting with "shell"
matcher = "shell.*"

# Match all tools (explicit wildcard)
matcher = "*"
```

### Advanced Features

#### Async Hooks (Fire-and-Forget)

```toml
[hooks]
[[hooks.notification]]
command = ["./notify-desktop.sh"]
async = true  # Doesn't block execution
```

Async hooks:
- Run in background without blocking the main flow
- Useful for logging, notifications, telemetry
- No guarantee of completion before session ends

#### Once-Per-Session Hooks

```toml
[hooks]
[[hooks.session_start]]
command = ["./setup-env.sh"]
once = true  # Runs only once, even if session_start fires multiple times
status_message = "Setting up environment..."
```

#### Disabling All Hooks

```toml
[hooks]
disable_all_hooks = true  # Override: disables all hooks regardless of config
```

### Complete Configuration Example

```toml
[hooks]
# Validate tool usage before execution
[[hooks.pre_tool_use]]
command = ["./check-tool.sh"]
matcher = "^Bash$"
timeout = 10
status_message = "Validating command..."

# Log all tool executions (async)
[[hooks.post_tool_use]]
command = ["./log-tool.sh"]
async = true

# Handle tool failures
[[hooks.post_tool_use_failure]]
command = "bash ./on-failure.sh"
timeout = 5

# Session lifecycle logging
[[hooks.session_start]]
command = ["./on-start.sh"]
once = true
status_message = "Initializing session..."

[[hooks.session_end]]
command = ["./on-end.sh"]

# Desktop notifications (fire-and-forget)
[[hooks.notification]]
command = ["./notify-desktop.sh"]
async = true

# Group multiple hooks with same matcher
[[hooks.pre_tool_use]]
matcher = "^Read$"

[[hooks.pre_tool_use.commands]]
command = ["./check-permissions.sh"]
timeout = 5

[[hooks.pre_tool_use.commands]]
command = ["./log-read.sh"]
async = true
```

## Events Reference

| Event | Config Key | Blockable | Matcher Field | Description |
|-------|-----------|-----------|---------------|-------------|
| PreToolUse | `pre_tool_use` | ✅ Yes | `tool_name` | Before tool execution |
| PostToolUse | `post_tool_use` | ❌ No | `tool_name` | After successful tool execution |
| PostToolUseFailure | `post_tool_use_failure` | ❌ No | `tool_name` | After failed tool execution |
| AfterAgent | `after_agent` | ❌ No | - | After agent turn completes |
| SessionStart | `session_start` | ❌ No | `source` | When session begins |
| SessionEnd | `session_end` | ❌ No | `reason` | When session ends |
| UserPromptSubmit | `user_prompt_submit` | ✅ Yes | - | When user submits a prompt |
| Stop | `stop` | ✅ Yes | - | When stop is requested |
| PermissionRequest | `permission_request` | ✅ Yes | `tool_name` | Before permission dialog |
| Notification | `notification` | ❌ No | `level` | When notification is sent |
| SubagentStart | `subagent_start` | ❌ No | `agent_type` | When subagent starts |
| SubagentStop | `subagent_stop` | ❌ No | `agent_type` | When subagent stops |
| PreCompact | `pre_compact` | ❌ No | `trigger` | Before context compaction |
| TaskCompleted | `task_completed` | ❌ No | - | When task completes |

**Blockable events**: These events can return `"decision": "block"` to prevent the operation from proceeding. Exit code 2 also blocks the operation.

**Non-blockable events**: These events are observational only. They cannot block operations, but can inject system messages or collect metadata.

## Hook Input (stdin JSON)

When a hook is executed, Codex sends a JSON payload on stdin containing event context and details:

```json
{
  "session_id": "01JKCJX1234567890ABCDEFGHJK",
  "cwd": "/home/user/project",
  "triggered_at": "2025-01-01T00:00:00Z",
  "hook_event_name": "PreToolUse",
  "permission_mode": "on-request",
  "transcript_path": "/tmp/transcript.jsonl",
  "tool_name": "Bash",
  "tool_input": {
    "command": "ls -la"
  }
}
```

### Common Fields (All Events)

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | String | Unique session identifier (ULID format) |
| `cwd` | String | Current working directory |
| `triggered_at` | String | ISO 8601 timestamp (RFC3339) |
| `hook_event_name` | String | PascalCase event name (e.g., "PreToolUse") |
| `permission_mode` | String | Current approval mode ("on-request", "never", etc.) |
| `transcript_path` | String? | Path to session transcript file (if available) |

### Event-Specific Fields

Event-specific fields are **flattened** into the top level (no nesting):

**PreToolUse:**
```json
{
  "tool_name": "Bash",
  "tool_input": {"command": "ls -la"}
}
```

**PostToolUse:**
```json
{
  "tool_name": "Bash",
  "tool_input": {"command": "ls -la"},
  "tool_response": "file1.txt\nfile2.txt"
}
```

**PostToolUseFailure:**
```json
{
  "tool_name": "Bash",
  "error": "Command failed with exit code 1"
}
```

**SessionStart:**
```json
{
  "source": "cli",
  "model": "claude-opus-4-6",
  "agent_type": "codex"
}
```

**SessionEnd:**
```json
{
  "reason": "user_exit"
}
```

**Notification:**
```json
{
  "message": "Build completed successfully",
  "level": "info"
}
```

**PermissionRequest:**
```json
{
  "tool_name": "Edit",
  "tool_input": {"file_path": "/tmp/test.txt"}
}
```

**SubagentStart:**
```json
{
  "agent_type": "researcher",
  "task": "Analyze security vulnerabilities"
}
```

**SubagentStop:**
```json
{
  "agent_type": "researcher",
  "reason": "task_completed"
}
```

**PreCompact:**
```json
{
  "trigger": "auto"
}
```

**TaskCompleted:**
```json
{
  "summary": "Fixed authentication bug in login flow"
}
```

**UserPromptSubmit:**
```json
{
  "prompt": "Help me debug this code"
}
```

**Stop:**
```json
{
  "reason": "user_request"
}
```

## Hook Output (stdout JSON)

Hooks communicate their decision back to Codex by writing JSON to stdout. The structure depends on whether the event is blockable:

### Decision Types

#### Proceed (Allow Operation)

```json
{"decision": "proceed"}
```

Default behavior if no decision is returned or on non-zero exit code for non-blockable events.

#### Block (Prevent Operation)

```json
{
  "decision": "block",
  "reason": "Blocked dangerous rm -rf / command"
}
```

Only valid for **blockable events** (PreToolUse, UserPromptSubmit, PermissionRequest, Stop). For non-blockable events, this is treated as an error.

#### Modify (Change Input/Output)

```json
{
  "decision": "modify",
  "content": "modified command here"
}
```

The `content` field contains the modified tool input or output as a string.

### Additional Output Fields

Hooks can return additional metadata alongside the decision:

```json
{
  "decision": "proceed",
  "system_message": "Security check passed",
  "suppress_output": false,
  "stop_reason": "custom_stop_reason"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `system_message` | String | Injected into conversation as system message |
| `suppress_output` | Boolean | Suppress tool output from display |
| `stop_reason` | String | Override stop reason for Stop events |

Multiple hooks can return system messages; all will be collected and injected.

## Exit Code Semantics

Hook exit codes have specific meanings:

| Exit Code | Meaning | Effect |
|-----------|---------|--------|
| 0 | Success | stdout JSON is parsed for decision |
| 2 | Block (blockable) / Error (non-blockable) | Block operation (if blockable) or log error |
| Other non-zero | Warning | Warning logged, execution proceeds |

### Exit Code vs JSON Decision

- **Exit 0**: stdout is parsed; decision from JSON (default: proceed)
- **Exit 2** on blockable event: operation is blocked (equivalent to `{"decision": "block"}`)
- **Exit 2** on non-blockable event: error logged, execution proceeds
- **Other non-zero**: warning logged, execution proceeds (decision ignored)

## Environment Variables

Hooks receive environment variables for accessing session context:

| Variable | Description | Example |
|----------|-------------|---------|
| `CLAUDE_PROJECT_DIR` | Project root directory | `/home/user/project` |
| `CODEX_PROJECT_DIR` | Same as above (Codex-specific alias) | `/home/user/project` |
| `CLAUDE_ENV_FILE` | Path to env file for setting variables (SessionStart only) | `/tmp/codex-env-123.txt` |

### Setting Environment Variables (SessionStart only)

SessionStart hooks can set environment variables for the session by writing `KEY=VALUE` pairs to `$CLAUDE_ENV_FILE`:

```bash
#!/usr/bin/env bash
PAYLOAD=$(cat)

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    echo "MY_SESSION_VAR=value" >> "$CLAUDE_ENV_FILE"
    echo "LOG_FILE=/tmp/session.log" >> "$CLAUDE_ENV_FILE"
fi

echo '{"decision": "proceed"}'
exit 0
```

## Examples

Example hook scripts are available in the `examples/hooks/` directory:

### 1. Pre-Tool Security Check (`pre-tool-check.sh`)

Validates tool usage before execution, blocking dangerous commands:

```bash
#!/usr/bin/env bash
PAYLOAD=$(cat)
TOOL_NAME=$(echo "$PAYLOAD" | jq -r '.tool_name')

if [ "$TOOL_NAME" = "Bash" ]; then
    COMMAND=$(echo "$PAYLOAD" | jq -r '.tool_input.command')

    # Block dangerous commands
    if echo "$COMMAND" | grep -qE 'rm\s+-rf\s+/'; then
        echo '{"decision": "block", "reason": "Dangerous command blocked"}'
        exit 0
    fi
fi

echo '{"decision": "proceed"}'
```

### 2. Session Logger (`session-logger.sh`)

Logs session lifecycle events and sets environment variables:

```bash
#!/usr/bin/env bash
PAYLOAD=$(cat)
EVENT=$(echo "$PAYLOAD" | jq -r '.hook_event_name')
SESSION_ID=$(echo "$PAYLOAD" | jq -r '.session_id')

LOG_FILE="${CODEX_PROJECT_DIR}/.codex/logs/sessions.log"
mkdir -p "$(dirname "$LOG_FILE")"

case "$EVENT" in
    SessionStart)
        echo "[$(date)] SESSION START: $SESSION_ID" >> "$LOG_FILE"

        # Set session variables
        if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
            echo "SESSION_LOG=$LOG_FILE" >> "$CLAUDE_ENV_FILE"
        fi
        ;;
    SessionEnd)
        REASON=$(echo "$PAYLOAD" | jq -r '.reason')
        echo "[$(date)] SESSION END: $SESSION_ID ($REASON)" >> "$LOG_FILE"
        ;;
esac

echo '{"decision": "proceed"}'
```

### 3. Desktop Notifications (`notification-desktop.sh`)

Forwards notifications to desktop notification system (async):

```bash
#!/usr/bin/env bash
PAYLOAD=$(cat)
MESSAGE=$(echo "$PAYLOAD" | jq -r '.message')
LEVEL=$(echo "$PAYLOAD" | jq -r '.level')

# Use notify-send on Linux
if command -v notify-send &>/dev/null; then
    URGENCY="normal"
    [ "$LEVEL" = "error" ] && URGENCY="critical"
    notify-send -u "$URGENCY" "Codex" "$MESSAGE"
fi

exit 0
```

Configuration for async notification hook:

```toml
[hooks]
[[hooks.notification]]
command = ["bash", "./examples/hooks/notification-desktop.sh"]
async = true
```

## Debugging Hooks

### Common Issues

**Hook not executing:**
- Check that `disable_all_hooks = false` in config
- Verify the `matcher` pattern matches the event field
- Check hook command path is correct (relative to CWD or absolute)

**Hook timing out:**
- Increase `timeout` value in config
- Check for infinite loops or blocking operations in hook script
- Consider using `async = true` for long-running tasks

**Hook output not parsed:**
- Ensure stdout writes valid JSON
- Verify exit code is 0 for JSON parsing
- Avoid logging to stdout (use stderr instead)

### Testing Hooks

Test hooks independently by simulating JSON input:

```bash
# Test PreToolUse hook
echo '{
  "session_id": "test",
  "cwd": "/tmp",
  "triggered_at": "2025-01-01T00:00:00Z",
  "hook_event_name": "PreToolUse",
  "permission_mode": "on-request",
  "tool_name": "Bash",
  "tool_input": {"command": "ls -la"}
}' | bash ./examples/hooks/pre-tool-check.sh

# Check exit code
echo $?
```

### Logging from Hooks

Hooks should write logs to **stderr** (not stdout) to avoid interfering with JSON output:

```bash
#!/usr/bin/env bash
PAYLOAD=$(cat)

# Log to stderr
echo "[DEBUG] Hook received payload" >&2
echo "$PAYLOAD" | jq '.' >&2

# Output decision to stdout
echo '{"decision": "proceed"}'
exit 0
```

## Claude Code Compatibility

Codex hooks are designed to be compatible with [Claude Code's hooks specification](https://github.com/anthropics/claude-code). The JSON wire protocol uses the same field names and structure, allowing hooks to work with both tools.

**Compatible features:**
- Event names (PascalCase: `PreToolUse`, `PostToolUse`, etc.)
- JSON input/output format
- Exit code semantics
- Environment variables (`CLAUDE_PROJECT_DIR`, `CLAUDE_ENV_FILE`)
- Field renaming compatibility (`tool_response` for tool output, `prompt` for user message)

**Codex-specific features:**
- `CODEX_PROJECT_DIR` environment variable (alias for `CLAUDE_PROJECT_DIR`)
- Grouped matcher format with multiple commands
- Async hooks (`async = true`)
- Once-per-session hooks (`once = true`)
- Status message display (`status_message`)

Write hooks using the Claude Code JSON protocol for maximum portability between tools.
