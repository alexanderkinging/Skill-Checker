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

import type { CheckResult, SuppressionDirective } from './types.js';

/** Valid rule ID format: CATEGORY-NNN */
const RULE_ID_RE = /^[A-Z]+-\d{3}$/;

/** Standalone HTML comment: <!-- skill-checker-ignore CODE-002 [CONT-001 ...] --> */
const NEXT_LINE_RE = /^<!--\s*skill-checker-ignore\s+([\w-]+(?:\s+[\w-]+)*)\s*-->$/;

/** File-level HTML comment: <!-- skill-checker-ignore-file CODE-002 [CONT-001 ...] --> */
const FILE_LEVEL_RE = /^<!--\s*skill-checker-ignore-file\s+([\w-]+(?:\s+[\w-]+)*)\s*-->$/;

/** Same-line trailing comment: some code // skill-checker-ignore CODE-002 */
const INLINE_COMMENT_RE = /\/\/\s*skill-checker-ignore\s+([\w-]+(?:\s+[\w-]+)*)\s*$/;

/**
 * Parse inline suppression directives from raw SKILL.md lines.
 * Lines are 1-based to match CheckResult.line convention.
 *
 * @param source - the source file these lines come from (e.g. 'SKILL.md').
 *   Directives only suppress findings from the same source.
 */
export function parseSuppressionDirectives(rawLines: string[], source = 'SKILL.md'): SuppressionDirective[] {
  const directives: SuppressionDirective[] = [];

  for (let i = 0; i < rawLines.length; i++) {
    const trimmed = rawLines[i].trim();
    const lineNum = i + 1; // 1-based

    const nextMatch = NEXT_LINE_RE.exec(trimmed);
    if (nextMatch) {
      const ruleIds = nextMatch[1].split(/\s+/);
      directives.push({ ruleIds, scope: 'next-line', line: lineNum, source });
      continue;
    }

    const fileMatch = FILE_LEVEL_RE.exec(trimmed);
    if (fileMatch) {
      const ruleIds = fileMatch[1].split(/\s+/);
      directives.push({ ruleIds, scope: 'file', line: lineNum, source });
      continue;
    }

    // Same-line trailing // comment: suppresses finding on this line (not next)
    const inlineMatch = INLINE_COMMENT_RE.exec(rawLines[i]);
    if (inlineMatch) {
      const ruleIds = inlineMatch[1].split(/\s+/);
      directives.push({ ruleIds, scope: 'same-line', line: lineNum, source });
    }
  }

  return directives;
}

/** INJ category prefix — these rules cannot be suppressed */
function isInjRule(ruleId: string): boolean {
  return ruleId.startsWith('INJ-');
}

export interface SuppressionResult {
  active: CheckResult[];
  suppressed: CheckResult[];
  warnings: string[];
}

/**
 * Apply suppression directives to check results.
 *
 * Rules:
 * - INJ-* rules cannot be suppressed (security policy)
 * - Invalid rule IDs produce warnings
 * - Unused directives produce warnings
 * - Fail-closed: unrecognized comments are simply ignored
 */
/**
 * Apply suppression directives to check results.
 *
 * @param bodyStartLine - offset where body starts in the raw file (1-based).
 *   Some check modules (code-safety) use body-relative line numbers (1-based within body),
 *   while others (injection, resource, content) use raw file line numbers.
 *   When bodyStartLine is provided, next-line matching checks both coordinate systems.
 */
export function applySuppressions(
  results: CheckResult[],
  directives: SuppressionDirective[],
  bodyStartLine?: number
): SuppressionResult {
  const warnings: string[] = [];
  const usedDirectiveRules = new Set<string>(); // track "directiveLine:ruleId"

  // Validate rule IDs upfront and warn about INJ attempts
  for (const d of directives) {
    for (const ruleId of d.ruleIds) {
      if (!RULE_ID_RE.test(ruleId)) {
        warnings.push(`Invalid suppression: ${ruleId} at line ${d.line}`);
      } else if (isInjRule(ruleId)) {
        warnings.push(`Cannot suppress INJ rule: ${ruleId} at line ${d.line} (security policy)`);
      }
    }
  }

  const active: CheckResult[] = [];
  const suppressed: CheckResult[] = [];

  for (const result of results) {
    let isSuppressed = false;

    // INJ rules are never suppressed
    if (!isInjRule(result.id)) {
      for (const d of directives) {
        if (!d.ruleIds.includes(result.id)) continue;
        if (!RULE_ID_RE.test(result.id)) continue;

        // Source boundary: directive only suppresses findings from the same source
        if (result.source !== undefined && result.source !== d.source) continue;
        // Findings without source (whole-file checks) only match SKILL.md directives
        if (result.source === undefined && d.source !== 'SKILL.md') continue;

        if (d.scope === 'next-line') {
          // Match: finding line === directive line + 1 (raw coordinates)
          // Also check body-relative: finding line === directive line + 1 - bodyStartLine + 1
          const rawTarget = d.line + 1;
          const bodyTarget = bodyStartLine !== undefined
            ? rawTarget - bodyStartLine + 1
            : undefined;
          if (
            result.line !== undefined &&
            (result.line === rawTarget || (bodyTarget !== undefined && result.line === bodyTarget))
          ) {
            isSuppressed = true;
            usedDirectiveRules.add(`${d.line}:${result.id}`);
            break;
          }
        } else if (d.scope === 'same-line') {
          // Match: finding on the same line as the comment
          const rawTarget = d.line;
          const bodyTarget = bodyStartLine !== undefined
            ? rawTarget - bodyStartLine + 1
            : undefined;
          if (
            result.line !== undefined &&
            (result.line === rawTarget || (bodyTarget !== undefined && result.line === bodyTarget))
          ) {
            isSuppressed = true;
            usedDirectiveRules.add(`${d.line}:${result.id}`);
            break;
          }
        } else if (d.scope === 'file') {
          // Match: any finding with this rule ID in the same source
          // Source boundary already enforced above
          isSuppressed = true;
          usedDirectiveRules.add(`${d.line}:${result.id}`);
          break;
        }
      }
    }

    if (isSuppressed) {
      suppressed.push({ ...result, suppressed: true });
    } else {
      active.push(result);
    }
  }

  // Warn about unused directive rule IDs
  for (const d of directives) {
    for (const ruleId of d.ruleIds) {
      if (!RULE_ID_RE.test(ruleId)) continue;
      if (isInjRule(ruleId)) continue;
      const key = `${d.line}:${ruleId}`;
      if (!usedDirectiveRules.has(key)) {
        warnings.push(`Unused suppression: ${ruleId} at line ${d.line}`);
      }
    }
  }

  return { active, suppressed, warnings };
}
