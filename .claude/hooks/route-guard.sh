#!/usr/bin/env bash
# PreToolUse hook: enforces ADR-AI-001 model routing for the main (Supervisor) session.
# Subagents (agent_id present) are unrestricted. macOS-compatible (bash 3.2+).

set -u

INPUT="$(cat)"

HAVE_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
fi

get_field() {
  # $1 = field name: agent_id | tool_name | file_path
  field="$1"
  if [ "$HAVE_JQ" -eq 1 ]; then
    case "$field" in
      agent_id)   printf '%s' "$INPUT" | jq -r '.agent_id // empty' 2>/dev/null ;;
      tool_name)  printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null ;;
      file_path)  printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null ;;
    esac
  else
    printf '%s' "$INPUT" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
field = '$field'
if field == 'agent_id':
    print(d.get('agent_id') or '')
elif field == 'tool_name':
    print(d.get('tool_name') or '')
elif field == 'file_path':
    ti = d.get('tool_input') or {}
    print(ti.get('file_path') or '')
" 2>/dev/null
  fi
}

AGENT_ID="$(get_field agent_id)" || exit 0
TOOL_NAME="$(get_field tool_name)" || exit 0
FILE_PATH="$(get_field file_path)" || exit 0

# Parsing errors already tolerated above (empty strings). If we somehow got here
# with unparseable input, just allow silently.

deny() {
  reason="$1"
  if [ "${ROUTE_GUARD_MODE:-}" = "warn" ]; then
    printf '%s\n' "$reason" >&2
    exit 0
  fi
  if [ "$HAVE_JQ" -eq 1 ]; then
    escaped="$(printf '%s' "$reason" | jq -Rs '.')"
  else
    escaped="$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$reason")"
  fi
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%s}}\n' "$escaped"
  exit 0
}

# Subagents: unrestricted.
if [ -n "$AGENT_ID" ]; then
  exit 0
fi

# Main session (Supervisor).
case "$TOOL_NAME" in
  Grep|Glob)
    deny "ROUTING: la sesión principal (Supervisor) no busca en fuentes. Delega a medina-scout (haiku)."
    ;;
  Read)
    case "$FILE_PATH" in
      */CLAUDE.md|*/.claude/*|*/docs/agentic/*|*/agent/*|*scratchpad*)
        exit 0
        ;;
      */tasks/*.output)
        deny "ROUTING: no abrir transcripciones de subagentes"
        ;;
      *)
        if [ -n "$FILE_PATH" ] && [ -f "$FILE_PATH" ]; then
          LINES="$(wc -l < "$FILE_PATH" 2>/dev/null | tr -d ' ')"
          if [ -n "$LINES" ] && [ "$LINES" -gt 150 ] 2>/dev/null; then
            deny "ROUTING: archivo de $LINES líneas. Delega la lectura a medina-scout (haiku) o medina-synth (sonnet) y pide un reporte con citas."
          fi
        fi
        exit 0
        ;;
    esac
    ;;
  Edit|Write|NotebookEdit)
    case "$FILE_PATH" in
      */.claude/*|*/CLAUDE.md|*/docs/agentic/*|*/agent/*|*scratchpad*)
        exit 0
        ;;
      *)
        deny "ROUTING: el Supervisor no edita código ni docs de producto. Delega a lampone-dev (sonnet) o lampone-qa (sonnet)."
        ;;
    esac
    ;;
  *)
    exit 0
    ;;
esac

exit 0
