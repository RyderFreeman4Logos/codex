#!/usr/bin/env bash
# Forward notifications to desktop notification system
# Compatible with both Claude Code and Codex
#
# Usage in config.toml:
#   [[hooks.notification]]
#   command = "bash ./examples/hooks/notification-desktop.sh"
#   async = true

set -euo pipefail

PAYLOAD=$(cat)
LEVEL=$(echo "$PAYLOAD" | jq -r '.level // "info"')
MESSAGE=$(echo "$PAYLOAD" | jq -r '.message // "Codex notification"')
TITLE=$(echo "$PAYLOAD" | jq -r '.title // "Codex"')

# Use notify-send on Linux, osascript on macOS
if command -v notify-send &>/dev/null; then
    URGENCY="normal"
    [ "$LEVEL" = "error" ] && URGENCY="critical"
    [ "$LEVEL" = "warn" ] && URGENCY="critical"
    notify-send -u "$URGENCY" "$TITLE" "$MESSAGE"
elif command -v osascript &>/dev/null; then
    osascript -e "display notification \"$MESSAGE\" with title \"$TITLE\""
fi

exit 0
