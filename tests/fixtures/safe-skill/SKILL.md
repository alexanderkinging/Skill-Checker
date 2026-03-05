---
name: format-code
description: Formats code using prettier with project defaults
version: 1.0.0
allowed-tools:
  - Bash(npx prettier *)
  - Read
  - Write
---

# Code Formatter

When invoked, format the specified files or the entire project using prettier.

## Steps

1. Check if `.prettierrc` exists in the project root
2. If not, use default prettier configuration
3. Run prettier on the specified files or directories
4. Report which files were formatted

## Usage

Format a single file:
```
/format-code src/index.ts
```

Format the entire project:
```
/format-code .
```

## Notes

- Respects `.prettierignore` if present
- Does not modify files in `node_modules` or `dist`
- Supports TypeScript, JavaScript, CSS, JSON, and Markdown
