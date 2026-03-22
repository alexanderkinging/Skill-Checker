// Skill Checker - Security checker for Claude Code skills
// Copyright (C) 2026 Alexander Jin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

export interface RemediationEntry {
  guidance: string;
  effort: 'low' | 'medium' | 'high';
}

const REMEDIATION_MAP: Record<string, RemediationEntry> = {
  // ===== STRUCT =====
  'STRUCT-001': {
    guidance: 'Create a SKILL.md file in the skill directory with valid YAML frontmatter and a body section.',
    effort: 'low',
  },
  'STRUCT-002': {
    guidance: 'Fix the YAML frontmatter syntax. Ensure it is enclosed between --- delimiters and contains valid YAML.',
    effort: 'low',
  },
  'STRUCT-003': {
    guidance: 'Add a `name` field to the frontmatter, e.g. `name: my-skill`.',
    effort: 'low',
  },
  'STRUCT-004': {
    guidance: 'Add a `description` field to the frontmatter explaining what the skill does.',
    effort: 'low',
  },
  'STRUCT-005': {
    guidance: 'Expand the body section with meaningful instructions. A skill body should describe the workflow and expected behavior.',
    effort: 'medium',
  },
  'STRUCT-006': {
    guidance: 'Remove binary, executable, or script files from the skill directory. Skills should contain only text-based configuration and documentation.',
    effort: 'low',
  },
  'STRUCT-007': {
    guidance: 'Use lowercase kebab-case for the skill name (e.g. `my-skill-name`). Avoid special characters or spaces.',
    effort: 'low',
  },
  'STRUCT-008': {
    guidance: 'Ensure the skill directory structure is standard. This warning indicates some files could not be scanned.',
    effort: 'low',
  },

  // ===== CONT =====
  'CONT-001': {
    guidance: 'Replace TODO/FIXME/placeholder text with actual content. If the skill instructs creating placeholders, use `<!-- skill-checker-ignore CONT-001 -->` before the line.',
    effort: 'low',
  },
  'CONT-002': {
    guidance: 'Remove lorem ipsum filler text and replace with real skill instructions.',
    effort: 'low',
  },
  'CONT-003': {
    guidance: 'Reduce duplicated lines. Consolidate repeated instructions into a single clear statement.',
    effort: 'medium',
  },
  'CONT-004': {
    guidance: 'Align the frontmatter description with the body content. The description should accurately summarize what the skill does.',
    effort: 'medium',
  },
  'CONT-005': {
    guidance: 'Remove promotional or advertising content. If describing pricing/marketing concepts for educational purposes, use `<!-- skill-checker-ignore CONT-005 -->` before the line.',
    effort: 'low',
  },
  'CONT-006': {
    guidance: 'Add more instructional prose around code examples. A skill should explain when and how to use the code, not just provide raw snippets.',
    effort: 'medium',
  },
  'CONT-007': {
    guidance: 'Ensure the skill body references the capabilities implied by the skill name, or rename the skill to match its actual functionality.',
    effort: 'medium',
  },

  // ===== INJ =====
  'INJ-001': {
    guidance: 'Remove zero-width Unicode characters from the file. These can hide malicious content. Use a hex editor or run: `sed -i "" "s/[\\x200B\\x200C\\x200D\\xFEFF]//g" SKILL.md`.',
    effort: 'low',
  },
  'INJ-002': {
    guidance: 'Replace homoglyph characters (e.g. Cyrillic/Greek lookalikes) with their ASCII equivalents to prevent spoofing.',
    effort: 'low',
  },
  'INJ-003': {
    guidance: 'Remove RTL/bidirectional override characters. These manipulate text display and can disguise malicious content.',
    effort: 'low',
  },
  'INJ-004': {
    guidance: 'Remove instructions that attempt to override the system prompt. A skill must not contain "ignore previous instructions" or similar patterns.',
    effort: 'low',
  },
  'INJ-005': {
    guidance: 'Remove patterns that simulate or manipulate tool output (e.g. `permissionDecision`, `tool_result`). Skills must not forge tool responses.',
    effort: 'low',
  },
  'INJ-006': {
    guidance: 'Remove instruction-like content from HTML comments. If comments are needed for documentation, ensure they do not contain executable directives.',
    effort: 'low',
  },
  'INJ-007': {
    guidance: 'Remove special model/system tags (e.g. `<|im_start|>`, `<system>`). These attempt to inject into the model context boundary.',
    effort: 'low',
  },
  'INJ-008': {
    guidance: 'Remove base64-encoded strings that decode to instructions. Legitimate data should be stored in plain text or referenced via file paths.',
    effort: 'low',
  },
  'INJ-009': {
    guidance: 'Avoid delimiter patterns that mimic system/instruction boundaries (e.g. `[SYSTEM]`, `[INST]`). Use standard Markdown headers instead.',
    effort: 'low',
  },
  'INJ-010': {
    guidance: 'Remove social engineering patterns (identity hijacking, deception, config tampering, verification bypass). Skills must not attempt to alter model identity or hide actions from users.',
    effort: 'low',
  },

  // ===== CODE =====
  'CODE-001': {
    guidance: 'Remove eval(), Function(), or dynamic code execution. Use explicit function calls or tool APIs instead.',
    effort: 'medium',
  },
  'CODE-002': {
    guidance: 'Remove shell/subprocess calls. Use tool APIs instead. If shell access is essential (e.g. calling soffice), use `<!-- skill-checker-ignore CODE-002 -->` and explain the necessity.',
    effort: 'medium',
  },
  'CODE-003': {
    guidance: 'Remove destructive file operations (rm -rf, rmdir, unlink on broad paths). If file cleanup is needed, target specific files with explicit paths.',
    effort: 'medium',
  },
  'CODE-004': {
    guidance: 'Review hardcoded URLs. Ensure all external URLs use HTTPS and point to trusted domains. If URLs are necessary API endpoints, use `<!-- skill-checker-ignore CODE-004 -->`.',
    effort: 'medium',
  },
  'CODE-005': {
    guidance: 'Restrict file writes to the skill working directory. Avoid writing to system paths, home directories, or parent directories.',
    effort: 'medium',
  },
  'CODE-006': {
    guidance: 'Avoid direct environment variable access for sensitive data. If env vars are needed for configuration, document which variables and why.',
    effort: 'medium',
  },
  'CODE-007': {
    guidance: 'Review long encoded strings. If they contain legitimate data (e.g. embedded assets), add a comment explaining their purpose.',
    effort: 'low',
  },
  'CODE-008': {
    guidance: 'Review high-entropy strings. These may be embedded secrets or obfuscated code. Replace with references to external configuration.',
    effort: 'medium',
  },
  'CODE-009': {
    guidance: 'Remove multi-layer encoding (e.g. base64 within hex). Legitimate content should use a single encoding layer at most.',
    effort: 'low',
  },
  'CODE-010': {
    guidance: 'Remove dynamic code generation patterns. Use static code with explicit function calls instead of constructing code at runtime.',
    effort: 'medium',
  },
  'CODE-011': {
    guidance: 'Use descriptive variable names instead of obfuscated single-character or hex-named variables.',
    effort: 'low',
  },
  'CODE-012': {
    guidance: 'Remove permission escalation commands (sudo, chmod 777, setuid). Skills should operate within normal user permissions.',
    effort: 'low',
  },
  'CODE-013': {
    guidance: 'Remove hardcoded API keys, tokens, or credentials. Use environment variables or a secrets manager, and add patterns to .gitignore.',
    effort: 'medium',
  },
  'CODE-014': {
    guidance: 'Remove reverse shell patterns. These are indicators of malicious intent and have no legitimate use in skills.',
    effort: 'low',
  },
  'CODE-015': {
    guidance: 'Remove remote pipeline execution or data exfiltration patterns (e.g. curl | sh, piping sensitive data to external endpoints).',
    effort: 'low',
  },
  'CODE-016': {
    guidance: 'Remove persistence mechanism patterns (cron jobs, launchd plists, shell profile modifications, autostart entries). Skills should not install persistent system services.',
    effort: 'medium',
  },

  // ===== SUPPLY =====
  'SUPPLY-001': {
    guidance: 'Review the MCP server reference. Ensure it points to a trusted, well-known server. Document why external MCP access is needed.',
    effort: 'medium',
  },
  'SUPPLY-002': {
    guidance: 'Avoid `npx -y` auto-install. Pin the package version and verify the package before use. Use `npx package@version` instead.',
    effort: 'low',
  },
  'SUPPLY-003': {
    guidance: 'Review package installation commands. Pin exact versions and verify package authenticity. Avoid installing packages from untrusted sources.',
    effort: 'medium',
  },
  'SUPPLY-004': {
    guidance: 'Use HTTPS instead of HTTP for all URLs to prevent man-in-the-middle attacks.',
    effort: 'low',
  },
  'SUPPLY-005': {
    guidance: 'Replace raw IP addresses with domain names. IP-based URLs bypass DNS security controls and are harder to audit.',
    effort: 'low',
  },
  'SUPPLY-006': {
    guidance: 'Review git clone commands. Ensure repositories are from trusted sources. Pin to a specific commit hash or tag for reproducibility.',
    effort: 'medium',
  },
  'SUPPLY-007': {
    guidance: 'Remove references to known suspicious domains. These domains have been flagged for malicious activity.',
    effort: 'low',
  },
  'SUPPLY-008': {
    guidance: 'Remove files matching known malicious hashes. These files have been identified as malware or exploits.',
    effort: 'low',
  },
  'SUPPLY-009': {
    guidance: 'Remove references to known command-and-control IP addresses. These IPs are associated with malware infrastructure.',
    effort: 'low',
  },
  'SUPPLY-010': {
    guidance: 'Verify the package name is correct and not a typosquat of a popular package. Check the official registry for the canonical name.',
    effort: 'low',
  },

  // ===== RES =====
  'RES-001': {
    guidance: 'Remove recursive or repetitive task patterns (e.g. "repeat 1000 times"). Use bounded iteration with a clear termination condition.',
    effort: 'low',
  },
  'RES-002': {
    guidance: 'Request only the specific tools needed instead of unrestricted access. List individual tools in allowed-tools.',
    effort: 'medium',
  },
  'RES-003': {
    guidance: 'Reduce the number of allowed tools. Review if all listed tools are actually needed. Consider splitting into multiple focused skills.',
    effort: 'medium',
  },
  'RES-004': {
    guidance: 'Remove instructions that disable safety checks, hooks, or verification. Skills must operate within the security framework.',
    effort: 'low',
  },
  'RES-005': {
    guidance: 'Remove token-wasting patterns (e.g. "repeat in every response"). Keep instructions concise and avoid mandating boilerplate in every output.',
    effort: 'low',
  },
  'RES-006': {
    guidance: 'Remove instructions to ignore CLAUDE.md or project rules. Skills must respect the project configuration set by the user.',
    effort: 'low',
  },
};

/**
 * Get remediation guidance for a rule ID.
 */
export function getRemediation(ruleId: string): RemediationEntry | undefined {
  return REMEDIATION_MAP[ruleId];
}

/**
 * Get all known rule IDs that have remediation entries.
 */
export function getRemediationRuleIds(): string[] {
  return Object.keys(REMEDIATION_MAP);
}
