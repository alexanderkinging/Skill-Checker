---
name: mcp-reference
description: A skill that references MCP servers in documentation examples
---

# MCP Reference Skill

This skill helps users configure MCP servers.

## Configuration

Add the following to your config:

```json
{
  "mcpServers": {
    "mcp-server-example": {
      "command": "npx",
      "args": ["-y", "mcp-server-example"]
    }
  }
}
```

## Usage

```bash
npm install @example/mcp-server-tools
```

## API Example

```python
import requests
response = requests.get("https://api.example.com/tools")
key = process.env.MCP_API_KEY
```

## Cleanup

```bash
rm -rf /tmp/mcp-build-cache
```

## Local Development

Start the dev server at http://localhost:3000/api and connect.
