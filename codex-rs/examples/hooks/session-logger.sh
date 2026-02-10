#!/usr/bin/env bash
# Session lifecycle logger
# Compatible with both Claude Code and Codex
#
# Usage in config.toml:
#   [[hooks.session_start]]
#   command = "bash ./examples/hooks/session-logger.sh"
#   [[hooks.session_end]]
#   command = "bash ./examples/hooks/session-logger.sh"

set -euo pipefail

PAYLOAD=$(cat)
EVENT_NAME=$(echo "$PAYLOAD" | jq -r '.hook_event_name // "unknown"')
SESSION_ID=$(echo "$PAYLOAD" | jq -r '.session_id // "unknown"')
CWD=$(echo "$PAYLOAD" | jq -r '.cwd // "unknown"')
TIMESTAMP=$(echo "$PAYLOAD" | jq -r '.triggered_at // "unknown"')

LOG_DIR="${CODEX_PROJECT_DIR:-.}/.codex/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/sessions.log"

case "$EVENT_NAME" in
    SessionStart)
        SOURCE=$(echo "$PAYLOAD" | jq -r '.source // "unknown"')
        echo "[$TIMESTAMP] SESSION START: id=$SESSION_ID source=$SOURCE cwd=$CWD" >> "$LOG_FILE"

        # If CLAUDE_ENV_FILE is set, we can write environment variables
        if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
            echo "SESSION_LOG_FILE=$LOG_FILE" >> "$CLAUDE_ENV_FILE"
        fi
        ;;
    SessionEnd)
        REASON=$(echo "$PAYLOAD" | jq -r '.reason // "unknown"')
        echo "[$TIMESTAMP] SESSION END: id=$SESSION_ID reason=$REASON" >> "$LOG_FILE"
        ;;
    *)
        echo "[$TIMESTAMP] $EVENT_NAME: id=$SESSION_ID" >> "$LOG_FILE"
        ;;
esac

echo '{"decision": "proceed"}'
exit 0
