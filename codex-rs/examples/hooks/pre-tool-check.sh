#!/usr/bin/env bash
# PreToolUse hook: validates tool usage before execution
# Compatible with both Claude Code and Codex
#
# Usage in config.toml:
#   [[hooks.pre_tool_use]]
#   command = "bash ./examples/hooks/pre-tool-check.sh"
#   matcher = "^Bash$"

set -euo pipefail

# Read JSON payload from stdin
PAYLOAD=$(cat)

# Extract fields using jq
TOOL_NAME=$(echo "$PAYLOAD" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$PAYLOAD" | jq -r '.tool_input // empty')

# Example: block dangerous commands
if [ "$TOOL_NAME" = "Bash" ]; then
    COMMAND=$(echo "$TOOL_INPUT" | jq -r '.command // empty')

    # Block rm -rf / and similar dangerous patterns
    if echo "$COMMAND" | grep -qE '^\s*rm\s+-rf\s+/\s*$'; then
        echo '{"decision": "block", "reason": "Blocked dangerous rm -rf / command"}'
        exit 0
    fi

    # Block force push to main
    if echo "$COMMAND" | grep -qE 'git\s+push\s+.*--force.*\s+main'; then
        echo '{"decision": "block", "reason": "Blocked force push to main branch"}'
        exit 0
    fi
fi

# Allow everything else
echo '{"decision": "proceed"}'
exit 0
