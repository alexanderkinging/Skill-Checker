---
name: skill-check
description: Scan a Claude Code skill for security issues before installation
version: 0.1.0
allowed-tools:
  - Bash(npx skill-checker *)
  - Bash(node */bin/skill-checker.js *)
  - Read
  - Glob
---

# Skill Security Checker

When invoked as `/skill-check <path>`, scan the specified skill directory for security issues.

## Usage

The user provides a path to a skill directory (or the current directory if none specified).

## Steps

1. Run the skill-checker scanner on the target path:

```bash
npx skill-checker scan <path> --format terminal
```

2. If the scan finds CRITICAL issues (exit code 1), **warn the user strongly** and recommend NOT installing.

3. If the scan finds HIGH/MEDIUM issues, present the report and let the user decide.

4. If the path is a URL, tell the user to download it first, then scan the local directory.

## Output Format

The terminal output includes:
- Grade (A-F) and score (0-100)
- Summary of findings by severity
- Detailed findings grouped by category
- Recommendation

## Example

```
/skill-check ~/.claude/skills/my-skill
/skill-check ./downloaded-skill/
```
