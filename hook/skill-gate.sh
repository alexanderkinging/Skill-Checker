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

set -euo pipefail

# Check jq availability - required for parsing hook JSON
if ! command -v jq &>/dev/null; then
  echo '{"permissionDecision": "ask", "additionalContext": "[skill-gate] jq is required but not found. Install with: brew install jq (macOS) or apt install jq (Linux)"}'
  exit 0
fi

# Read hook input from stdin
INPUT=$(cat)

# Extract the file path from the hook input
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty')

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
  echo '{"permissionDecision": "ask", "additionalContext": "[skill-gate] skill-checker not found. Install with: npm install -g skill-checker. Manual review recommended."}'
  exit 0
fi

# For new file writes, we need to create a temp dir with the content
# since the file hasn't been written yet
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Extract file content from hook input and write to temp
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty')
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
  echo '{"permissionDecision": "ask", "additionalContext": "[skill-gate] Scan failed or produced no results. Manual review recommended."}'
  exit 0
fi

# Output the hook response
echo "$RESULT"
