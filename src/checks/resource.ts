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

import type { CheckModule, CheckResult, ParsedSkill } from '../types.js';

/** Recursive/amplification patterns */
const AMPLIFICATION_PATTERNS = [
  /\brepeat\s+(this|the\s+above)\s+\d+\s+times\b/i,
  /\bdo\s+this\s+forever\b/i,
  /\binfinite\s+loop\b/i,
  /\bwhile\s*\(\s*true\s*\)/,
  /\bfor\s*\(\s*;;\s*\)/,
  /\brecursively\s+(apply|run|execute|call)/i,
  /\bkeep\s+(running|doing|executing)\s+until/i,
];

/**
 * Requesting unrestricted tool access.
 *
 * Invariant: `full access` only triggers when the object is explicitly
 * tools (e.g. `full tool access`). Standalone `full access` without
 * `tool` MUST NOT trigger — it could refer to directory/volume/file
 * permissions. `all tools` is tool-specific by definition.
 */
const UNRESTRICTED_TOOL_PATTERNS = [
  /\bBash\s*\(\s*\*\s*\)/,
  /allowed[_-]?tools\s*:\s*\[?\s*["']?\*["']?\s*\]?/i,
  /\bunrestricted\s+(?:access|tool)/i,
  /\ball\s+tools?\s+access\b/i,
  /\bfull\s+tool\s+access\b/i,
  /\b(?:need|require|grant|give|allow|request|enable)\s+all\s+tools\b/i,
  /\ball\s+tools\s+(?:enabled|granted|allowed|required|needed)\b/i,
];

/** Patterns that disable safety */
const DISABLE_SAFETY_PATTERNS = [
  /\bdisable\s+(safety|security|checks?|hooks?|guard)/i,
  /\bbypass\s+(safety|security|checks?|hooks?|guard)/i,
  /\bskip\s+(safety|security|checks?|hooks?|guard|verification)/i,
  /\bturn\s+off\s+(safety|security|checks?|hooks?)/i,
  /--no-verify\b/,
  /--skip-hooks?\b/,
];

/**
 * Patterns that ignore project rules.
 *
 * Invariant: only exempt when example/template/snippet/sample immediately
 * modifies the ignored object (e.g. "ignore the CLAUDE.md example text").
 * A line like "In this tutorial, ignore the CLAUDE.md" MUST still trigger
 * because the imperative targets the real CLAUDE.md, not an example of it.
 * No whole-line keyword skip is allowed.
 */
const IGNORE_RULES_PATTERNS = [
  /\bignore\s+(the\s+)?CLAUDE\.md\b(?!\s+(?:example|template|snippet|sample))/i,
  /\bignore\s+(the\s+)?project\s+rules?\b(?!\s+(?:example|template|snippet|sample))/i,
  /\bignore\s+(the\s+)?\.claude\b(?!\s+(?:example|template|snippet|sample))/i,
  /\boverride\s+(the\s+)?project\s+(settings?|config|rules?)\b/i,
  /\bdo\s+not\s+(follow|obey|respect)\s+(the\s+)?(project|CLAUDE)/i,
  /\bdisregard\s+(the\s+)?(project|CLAUDE)\s+(rules?|config|settings?)/i,
];

/** Token waste patterns */
const TOKEN_WASTE_PATTERNS = [
  /\brepeat\s+(every|each)\s+(response|answer|reply)/i,
  /\balways\s+(start|begin|end)\s+(every|each)\s+(response|answer|reply)\s+with/i,
  /\binclude\s+this\s+(text|message|string)\s+in\s+(every|each|all)/i,
  /\bprint\s+(the\s+)?full\s+(source|code|file)\s+(every|each)\s+time/i,
];

export const resourceChecks: CheckModule = {
  name: 'Resource Abuse',
  category: 'RES',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];

    for (let i = 0; i < skill.bodyLines.length; i++) {
      const line = skill.bodyLines[i];
      const lineNum = skill.bodyStartLine + i;

      // RES-001: Instruction amplification
      for (const pattern of AMPLIFICATION_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'RES-001',
            category: 'RES',
            severity: 'HIGH',
            title: 'Instruction amplification',
            message: `Line ${lineNum}: Contains recursive/repetitive task pattern.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // RES-002: Unrestricted tool access
      for (const pattern of UNRESTRICTED_TOOL_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'RES-002',
            category: 'RES',
            severity: 'CRITICAL',
            title: 'Unrestricted tool access requested',
            message: `Line ${lineNum}: Requests broad/unrestricted tool access.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // RES-004: Disable safety checks
      for (const pattern of DISABLE_SAFETY_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'RES-004',
            category: 'RES',
            severity: 'CRITICAL',
            title: 'Attempts to disable safety checks',
            message: `Line ${lineNum}: Instructs disabling of safety mechanisms.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // RES-005: Token waste
      for (const pattern of TOKEN_WASTE_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'RES-005',
            category: 'RES',
            severity: 'MEDIUM',
            title: 'Token waste pattern',
            message: `Line ${lineNum}: Contains instructions that waste tokens.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // RES-006: Ignore CLAUDE.md / project rules
      for (const pattern of IGNORE_RULES_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'RES-006',
            category: 'RES',
            severity: 'CRITICAL',
            title: 'Attempts to ignore project rules',
            message: `Line ${lineNum}: Instructs ignoring CLAUDE.md or project configuration.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }
    }

    // RES-003: Excessive allowed-tools
    const allowedTools = skill.frontmatter['allowed-tools'];
    if (Array.isArray(allowedTools) && allowedTools.length > 15) {
      results.push({
        id: 'RES-003',
        category: 'RES',
        severity: 'MEDIUM',
        title: 'Excessive allowed-tools list',
        message: `Frontmatter declares ${allowedTools.length} allowed tools. This is unusually broad.`,
      });
    }

    // RES-002 (frontmatter): Check allowed-tools for dangerous patterns
    if (Array.isArray(allowedTools)) {
      for (const tool of allowedTools) {
        if (typeof tool !== 'string') continue;
        for (const pattern of UNRESTRICTED_TOOL_PATTERNS) {
          if (pattern.test(tool)) {
            results.push({
              id: 'RES-002',
              category: 'RES',
              severity: 'CRITICAL',
              title: 'Unrestricted tool access requested',
              message: `Frontmatter allowed-tools contains dangerous pattern: "${tool}"`,
              snippet: tool.slice(0, 120),
            });
            break;
          }
        }
      }
    }

    return results;
  },
};
