#!/usr/bin/env bash
# SubagentStop hook: appends one audit line per subagent run to agent/audit.log.
# macOS-compatible (bash 3.2+). Always exits 0.

set -u

INPUT="$(cat)"

LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/agent"
LOG_FILE="$LOG_DIR/audit.log"

HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
fi

get_field() {
  field="$1"
  if [ "$HAVE_JQ" -eq 1 ]; then
    printf '%s' "$INPUT" | jq -r --arg f "$field" '.[$f] // empty' 2>/dev/null
  else
    printf '%s' "$INPUT" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
v = d.get('$field')
print(v if v is not None else '')
" 2>/dev/null
  fi
}

AGENT_TYPE="$(get_field agent_type)"
AGENT_ID="$(get_field agent_id)"
SESSION_ID="$(get_field session_id)"
DURATION_MS="$(get_field duration_ms)"
TOTAL_TOKENS="$(get_field total_tokens)"
STOP_REASON="$(get_field stop_reason)"

[ -n "$AGENT_TYPE" ] || AGENT_TYPE="-"
[ -n "$AGENT_ID" ] || AGENT_ID="-"
[ -n "$SESSION_ID" ] || SESSION_ID="-"
[ -n "$DURATION_MS" ] || DURATION_MS="-"
[ -n "$TOTAL_TOKENS" ] || TOTAL_TOKENS="-"
[ -n "$STOP_REASON" ] || STOP_REASON="-"

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="./agent"
if [ ! -d "$LOG_DIR" ]; then
  mkdir -p "./agent" 2>/dev/null
  LOG_FILE="./agent/audit.log"
fi

printf '%s agent_type=%s agent_id=%s session_id=%s duration_ms=%s total_tokens=%s stop_reason=%s\n' \
  "$TIMESTAMP" "$AGENT_TYPE" "$AGENT_ID" "$SESSION_ID" "$DURATION_MS" "$TOTAL_TOKENS" "$STOP_REASON" \
  >> "$LOG_FILE" 2>/dev/null

exit 0
