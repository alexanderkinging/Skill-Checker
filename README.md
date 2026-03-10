# Skill Checker

Security checker for Claude Code skills — detect injection, malicious code, and supply chain risks before installation.

## Features

- **55 security rules** across 6 categories: structural validity, content quality, injection detection, code safety, supply chain, and resource abuse
- **Scoring system**: Grade A–F with 0–100 score
- **Dual entry**: CLI tool + PreToolUse hook for automatic interception
- **Configurable policies**: strict / balanced / permissive approval strategies
- **Context-aware detection**: severity reduction in code blocks and documentation sections, with zero reduction for injection rules
- **IOC threat intelligence**: built-in seed data for known malicious hashes, C2 IPs, and typosquat names
- **Multiple output formats**: terminal (color), JSON, hook response

## Security Standard & Benchmark

Skill Checker's 55 rules are aligned with established security frameworks including OWASP Top 10 for LLM Applications (2025), MITRE CWE, and MITRE ATT&CK. The tool ships with a reproducible benchmark dataset of six fixture skills covering all rule categories. This alignment is an internal mapping exercise — Skill Checker does not claim third-party certification or external audit status.

See [docs/SECURITY_BENCHMARK.md](docs/SECURITY_BENCHMARK.md) for the full rule mapping matrix, benchmark methodology, scoring model, and known limitations.

## Quick Start

```bash
# Install globally
npm install -g skill-checker

# Scan a skill directory
skill-checker scan ./path/to/skill/

# Or run without installing
npx skill-checker scan ./path/to/skill/
```

## Usage

```bash
skill-checker scan <path> [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `terminal` (default), `json`, `hook` |
| `-p, --policy <policy>` | Approval policy: `strict`, `balanced` (default), `permissive` |
| `-c, --config <path>` | Path to config file |

```bash
# Colored terminal report
skill-checker scan ./my-skill

# JSON output for CI/programmatic use
skill-checker scan ./my-skill --format json

# Hook response format (for PreToolUse integration)
skill-checker scan ./my-skill --format hook

# Strict policy — deny on HIGH and above
skill-checker scan ./my-skill --policy strict
```

Exit code `0` = no critical issues, `1` = critical issues detected.

### Recommended Scan Path

Skill Checker is designed to scan individual skill directories containing a `SKILL.md` file at the root. Running `scan .` from a project root or non-skill directory will produce noisy results (e.g. STRUCT-001 for missing SKILL.md).

```bash
# Correct: point to a skill directory
skill-checker scan ./path/to/my-skill/

# Avoid: scanning project root or arbitrary directories
skill-checker scan .
```

## Hook Integration

Skill Checker can run automatically as a Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks), intercepting skill file writes before they happen.

### Setup

```bash
npx tsx hook/install.ts
```

This adds a hook entry to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hook": "/path/to/skill-gate.sh"
      }
    ]
  }
}
```

### How It Works

1. Claude Code intercepts Write/Edit operations targeting SKILL.md files
2. `skill-gate.sh` receives the file content via stdin (JSON)
3. Runs `skill-checker scan --format hook` on the content
4. Returns a permission decision: `allow`, `ask`, or `deny`

The hook is fail-closed — if the scanner is unavailable, JSON parsing fails, or any unexpected error occurs, it returns `ask` (never silently allows).

### Requirements

- `jq` must be installed for JSON parsing
- `skill-checker` must be globally installed or available via `npx`

## Scoring

Base score starts at **100**. Each finding deducts points by severity:

| Severity | Deduction |
|----------|-----------|
| CRITICAL | -25 |
| HIGH | -10 |
| MEDIUM | -3 |
| LOW | -1 |

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90–100 | Safe to install |
| B | 75–89 | Minor issues |
| C | 60–74 | Review advised |
| D | 40–59 | Significant risk |
| F | 0–39 | Not recommended |

## Configuration

Create `.skillcheckerrc.yaml` in your project root or home directory:

```yaml
# Approval policy
policy: balanced    # strict / balanced / permissive

# Override severity for specific rules
overrides:
  CODE-006: LOW     # env var access is expected in my skills
  SUPPLY-002: LOW   # I trust npx -y in my workflow

# Ignore rules entirely
ignore:
  - CONT-006        # reference-heavy skills are fine
```

Config is resolved in order: CLI `--config` flag → project directory (walks up) → home directory → defaults.

### Policy Matrix

| Severity | strict | balanced | permissive |
|----------|--------|----------|------------|
| CRITICAL | deny | deny | ask |
| HIGH | deny | ask | report |
| MEDIUM | ask | report | report |
| LOW | report | report | report |

## Rule Categories

| Category | Rules | Examples |
|----------|-------|---------|
| Structural (STRUCT) | 8 | Missing SKILL.md, invalid frontmatter, binary files |
| Content (CONT) | 7 | Placeholder text, lorem ipsum, promotional content |
| Injection (INJ) | 9 | Zero-width chars, prompt override, tag injection, encoded payloads |
| Code Safety (CODE) | 15 | eval/exec, shell execution, reverse shell, data exfiltration, API key leakage, rm -rf, obfuscation |
| Supply Chain (SUPPLY) | 10 | Unknown MCP servers, suspicious domains, malicious hashes, typosquat |
| Resource Abuse (RES) | 6 | Unrestricted tool access, disable safety checks, ignore project rules |

See [docs/SECURITY_BENCHMARK.md](docs/SECURITY_BENCHMARK.md) for the complete rule mapping with OWASP/CWE/ATT&CK references.

## Programmatic API

```typescript
import { scanSkillDirectory } from 'skill-checker';

const report = scanSkillDirectory('./my-skill', {
  policy: 'strict',
  overrides: { 'CODE-006': 'LOW' },
  ignore: ['CONT-001'],
});

console.log(report.grade, report.score, report.results.length);
```

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)** — see the [LICENSE](LICENSE) file for details.

**Commercial License (商业授权)**

If you want to integrate this tool into a closed-source commercial product or SaaS, or cannot comply with AGPLv3 due to company policy, contact Alexander.kinging@gmail.com for a commercial license.
