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

import { parseSkill, parseSkillContent } from './parser.js';
import { runAllChecks } from './checks/index.js';
import type {
  CheckResult,
  ScanReport,
  SkillCheckerConfig,
  Severity,
  ParsedSkill,
} from './types.js';
import { SEVERITY_SCORES, computeGrade, DEFAULT_CONFIG } from './types.js';

/**
 * Scan a skill directory and produce a security report.
 */
export function scanSkillDirectory(
  dirPath: string,
  config: SkillCheckerConfig = DEFAULT_CONFIG
): ScanReport {
  const skill = parseSkill(dirPath);
  return buildReport(skill, config);
}

/**
 * Scan a single SKILL.md content string.
 */
export function scanSkillContent(
  content: string,
  config: SkillCheckerConfig = DEFAULT_CONFIG
): ScanReport {
  const skill = parseSkillContent(content);
  return buildReport(skill, config);
}

function buildReport(
  skill: ParsedSkill,
  config: SkillCheckerConfig
): ScanReport {
  // Run all checks
  let results = runAllChecks(skill);

  // Apply severity overrides
  results = results.map((r) => {
    if (config.overrides[r.id]) {
      return { ...r, severity: config.overrides[r.id] };
    }
    return r;
  });

  // Filter ignored rules
  results = results.filter((r) => !config.ignore.includes(r.id));

  // Deduplicate: same rule + same source file → single finding with occurrences count
  results = deduplicateResults(results);

  // Calculate score
  const score = calculateScore(results);
  const grade = computeGrade(score);

  // Build summary
  const summary = {
    total: results.length,
    critical: results.filter((r) => r.severity === 'CRITICAL').length,
    high: results.filter((r) => r.severity === 'HIGH').length,
    medium: results.filter((r) => r.severity === 'MEDIUM').length,
    low: results.filter((r) => r.severity === 'LOW').length,
  };

  return {
    skillPath: skill.dirPath,
    skillName: skill.frontmatter.name ?? 'unknown',
    timestamp: new Date().toISOString(),
    results,
    score,
    grade,
    summary,
  };
}

/**
 * Deduplicate results: same rule ID + same title + same source → single finding.
 * Keeps the highest severity (most conservative). Sets occurrences count.
 *
 * Title is included in the key so that rules with multiple sub-types
 * (e.g. CODE-016 persistence groups, CODE-013 credential providers)
 * are not incorrectly merged within the same file.
 *
 * Key uses the structural `source` field when available.
 * Falls back to `category + line` when source is absent, to avoid
 * merging unrelated findings under a shared "unknown" bucket.
 */
function deduplicateResults(results: CheckResult[]): CheckResult[] {
  const groups = new Map<string, CheckResult[]>();
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
  };

  for (const r of results) {
    // Prefer structural source; fall back to category+line for uniqueness
    const sourceKey = r.source ?? `_no_source_:${r.category}:${r.line ?? ''}`;
    const key = `${r.id}::${r.title}::${sourceKey}`;
    const group = groups.get(key);
    if (group) {
      group.push(r);
    } else {
      groups.set(key, [r]);
    }
  }

  const deduped: CheckResult[] = [];
  for (const group of groups.values()) {
    // Pick the entry with highest severity
    group.sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);
    const best = { ...group[0] };
    if (group.length > 1) {
      best.occurrences = group.length;
      // Only say "in this file" when we have a real source
      const suffix = best.source
        ? ` (${group.length} occurrences in this file)`
        : ` (${group.length} occurrences)`;
      best.message += suffix;
    }
    deduped.push(best);
  }

  return deduped;
}

function calculateScore(results: CheckResult[]): number {
  let score = 100;
  for (const r of results) {
    score -= SEVERITY_SCORES[r.severity];
  }
  return Math.max(0, score);
}

/**
 * Determine the worst severity found in results.
 */
export function worstSeverity(results: CheckResult[]): Severity | null {
  const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  for (const sev of order) {
    if (results.some((r) => r.severity === sev)) return sev;
  }
  return null;
}
