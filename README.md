# Skill Checker

Security checker for Claude Code skills — detect injection, malicious code, and supply chain risks before installation.

## Features

- **48 security rules** across 6 categories: structural validity, content quality, injection detection, code safety, supply chain, and resource abuse
- **Scoring system**: Grade A–F with 0–100 score
- **Dual entry**: CLI tool + PreToolUse hook for automatic interception
- **Configurable policies**: strict / balanced / permissive approval strategies
- **Multiple output formats**: terminal (color), JSON, hook response

## Quick Start

```bash
# Scan a skill directory
npx skill-checker scan ./path/to/skill/

# Scan with JSON output
npx skill-checker scan ./path/to/skill/ --format json

# Scan with strict policy
npx skill-checker scan ./path/to/skill/ --policy strict
```

## Installation

```bash
npm install -g skill-checker
```

## Configuration

Create a `.skillcheckerrc.yaml` in your project root or home directory:

```yaml
policy: balanced

overrides:
  CODE-006: LOW

ignore:
  - CONT-006
```

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)** - see the [LICENSE](LICENSE) file for details.

**商业授权 (Commercial License)**

如果您希望将本工具集成到闭源的商业产品、SaaS 服务中，或者由于公司合规原因无法遵守 AGPLv3 协议，请通过 Alexander.kinging@gmail.com 联系作者购买商业授权。
