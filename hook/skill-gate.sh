#!/usr/bin/env bash
# skill-gate.sh - PreToolUse hook for Claude Code
# Intercepts SKILL.md writes and runs security checks
#
# Usage in Claude Code settings.json:
# {
#   "hooks": {
#     "PreToolUse": [
#       {
#         "matcher": "Write|Edit",
#         "hook": "/path/to/skill-gate.sh"
#       }
#     ]
#   }
# }

# Fail-closed helper: any unexpected error path outputs ask + exit 0
fail_closed() {
  echo "{\"permissionDecision\": \"ask\", \"additionalContext\": \"[skill-gate] $1\"}"
  exit 0
}

# Trap any unexpected error to ensure we never exit without JSON output
trap 'fail_closed "Unexpected error occurred. Manual review recommended."' ERR

set -uo pipefail
# NOTE: -e is intentionally omitted; we handle errors explicitly via || fail_closed

# Check jq availability - required for parsing hook JSON
if ! command -v jq &>/dev/null; then
  fail_closed "jq is required but not found. Install with: brew install jq (macOS) or apt install jq (Linux)"
fi

# Read hook input from stdin
INPUT=$(cat)

# Validate input is non-empty
if [[ -z "$INPUT" ]]; then
  fail_closed "Empty input received. Manual review recommended."
fi

# Extract the file path from the hook input (fail-closed on jq parse error)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null) || fail_closed "Failed to parse hook input JSON. Manual review recommended."

# Only process SKILL.md files in skills directories
if [[ -z "$FILE_PATH" ]] || [[ ! "$FILE_PATH" =~ SKILL\.md$ ]]; then
  # Not a SKILL.md write - allow
  echo '{"permissionDecision": "allow"}'
  exit 0
fi

# Get the directory containing the SKILL.md
SKILL_DIR=$(dirname "$FILE_PATH")

# Check if skill-checker is available
CHECKER=""
if command -v skill-checker &>/dev/null; then
  CHECKER="skill-checker"
elif [ -x "$(npm root -g 2>/dev/null)/skill-checker/bin/skill-checker.js" ]; then
  CHECKER="node $(npm root -g)/skill-checker/bin/skill-checker.js"
elif command -v npx &>/dev/null; then
  CHECKER="npx skill-checker"
fi

if [[ -z "$CHECKER" ]]; then
  # skill-checker not found - fail-closed: ask user to review manually
  fail_closed "skill-checker not found. Install with: npm install -g skill-checker. Manual review recommended."
fi

# For new file writes, we need to create a temp dir with the content
# since the file hasn't been written yet
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Extract file content from hook input and write to temp (fail-closed on jq error)
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null) || fail_closed "Failed to extract content from hook input. Manual review recommended."
if [[ -n "$CONTENT" ]]; then
  echo "$CONTENT" > "$TEMP_DIR/SKILL.md"
  SCAN_DIR="$TEMP_DIR"
else
  # Editing existing file - scan the directory
  SCAN_DIR="$SKILL_DIR"
fi

# Run the scan in hook mode - fail-closed: scanner errors → ask user
RESULT=$($CHECKER scan "$SCAN_DIR" --format hook 2>/dev/null) || RESULT=""

if [[ -z "$RESULT" ]]; then
  fail_closed "Scan failed or produced no results. Manual review recommended."
fi

# Output the hook response
echo "$RESULT"
