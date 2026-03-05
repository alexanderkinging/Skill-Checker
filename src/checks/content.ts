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

const PLACEHOLDER_PATTERNS = [
  /\bTODO\b/i,
  /\bFIXME\b/i,
  /\bHACK\b/i,
  /\bXXX\b/,
  /\bplaceholder\b/i,
  /\binsert\s+here\b/i,
  /\bfill\s+in\b/i,
  /\bTBD\b/,
  /\bcoming\s+soon\b/i,
];

const LOREM_PATTERNS = [
  /lorem\s+ipsum/i,
  /dolor\s+sit\s+amet/i,
  /consectetur\s+adipiscing/i,
];

const AD_PATTERNS = [
  /\bbuy\s+now\b/i,
  /\bfree\s+trial\b/i,
  /\bdiscount\b/i,
  /\bpromo\s*code\b/i,
  /\bsubscribe\s+(to|now)\b/i,
  /\bsponsored\s+by\b/i,
  /\baffiliate\s+link\b/i,
  /\bclick\s+here\s+to\s+(buy|subscribe|download)/i,
  /\buse\s+code\b.*\b\d+%?\s*off\b/i,
  /\bcheck\s+out\s+my\b/i,
];

export const contentChecks: CheckModule = {
  name: 'Content Quality',
  category: 'CONT',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];

    if (!skill.body || skill.body.trim().length === 0) return results;

    // CONT-001: Placeholder content
    for (let i = 0; i < skill.bodyLines.length; i++) {
      const line = skill.bodyLines[i];
      for (const pattern of PLACEHOLDER_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'CONT-001',
            category: 'CONT',
            severity: 'HIGH',
            title: 'Placeholder content detected',
            message: `Line ${skill.bodyStartLine + i}: Contains placeholder text.`,
            line: skill.bodyStartLine + i,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }
    }

    // CONT-002: Lorem ipsum
    for (const pattern of LOREM_PATTERNS) {
      if (pattern.test(skill.body)) {
        results.push({
          id: 'CONT-002',
          category: 'CONT',
          severity: 'CRITICAL',
          title: 'Lorem ipsum filler text',
          message: 'Body contains lorem ipsum placeholder text.',
        });
        break;
      }
    }

    // CONT-003: Low information density (excessive repetition)
    checkRepetition(results, skill);

    // CONT-004: Description vs body mismatch
    // Simple heuristic: check if description keywords appear in body
    checkDescriptionMismatch(results, skill);

    // CONT-005: Ad/promotional content
    for (let i = 0; i < skill.bodyLines.length; i++) {
      const line = skill.bodyLines[i];
      for (const pattern of AD_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'CONT-005',
            category: 'CONT',
            severity: 'HIGH',
            title: 'Promotional/advertising content',
            message: `Line ${skill.bodyStartLine + i}: Contains ad-like content.`,
            line: skill.bodyStartLine + i,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }
    }

    // CONT-006: Body is mostly code with no instructions
    checkCodeHeavy(results, skill);

    // CONT-007: Name doesn't match body capabilities
    checkNameMismatch(results, skill);

    return results;
  },
};

function checkRepetition(results: CheckResult[], skill: ParsedSkill): void {
  const lines = skill.bodyLines.filter((l) => l.trim().length > 0);
  if (lines.length < 5) return;

  const lineCounts = new Map<string, number>();
  for (const line of lines) {
    const normalized = line.trim().toLowerCase();
    lineCounts.set(normalized, (lineCounts.get(normalized) ?? 0) + 1);
  }

  let duplicated = 0;
  for (const count of lineCounts.values()) {
    if (count > 1) duplicated += count - 1;
  }

  const ratio = duplicated / lines.length;
  if (ratio > 0.5) {
    results.push({
      id: 'CONT-003',
      category: 'CONT',
      severity: 'MEDIUM',
      title: 'Low information density',
      message: `${Math.round(ratio * 100)}% of lines are duplicates. Possible filler content.`,
    });
  }
}

function checkDescriptionMismatch(
  results: CheckResult[],
  skill: ParsedSkill
): void {
  const desc = skill.frontmatter.description;
  if (!desc || desc.length < 10) return;

  // Extract significant words from description
  const descWords = desc
    .toLowerCase()
    .split(/\W+/)
    .filter((w) => w.length > 4);
  if (descWords.length === 0) return;

  const bodyLower = skill.body.toLowerCase();
  const matched = descWords.filter((w) => bodyLower.includes(w));

  // If less than 20% of description words appear in body
  if (matched.length / descWords.length < 0.2) {
    results.push({
      id: 'CONT-004',
      category: 'CONT',
      severity: 'MEDIUM',
      title: 'Description/body mismatch',
      message:
        'The frontmatter description appears unrelated to the body content.',
    });
  }
}

function checkCodeHeavy(results: CheckResult[], skill: ParsedSkill): void {
  const lines = skill.bodyLines;
  if (lines.length < 10) return;

  let inCodeBlock = false;
  let codeLines = 0;

  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      inCodeBlock = !inCodeBlock;
      continue;
    }
    if (inCodeBlock) codeLines++;
  }

  const nonEmptyLines = lines.filter((l) => l.trim().length > 0).length;
  if (nonEmptyLines > 0 && codeLines / nonEmptyLines > 0.8) {
    results.push({
      id: 'CONT-006',
      category: 'CONT',
      severity: 'MEDIUM',
      title: 'Body is mostly code examples',
      message:
        'Over 80% of body content is in code blocks with minimal instructions.',
    });
  }
}

function checkNameMismatch(results: CheckResult[], skill: ParsedSkill): void {
  const name = skill.frontmatter.name;
  if (!name) return;

  // Extract capability hints from name
  const nameWords = name
    .split(/[-_]/)
    .filter((w) => w.length > 2)
    .map((w) => w.toLowerCase());
  const bodyLower = skill.body.toLowerCase();

  // If name suggests a specific capability, check body mentions it
  const capabilityHints = nameWords.filter((w) =>
    !['the', 'and', 'for', 'skill', 'tool', 'helper', 'util'].includes(w)
  );

  if (capabilityHints.length === 0) return;

  const matched = capabilityHints.filter((w) => bodyLower.includes(w));
  if (matched.length === 0 && capabilityHints.length >= 2) {
    results.push({
      id: 'CONT-007',
      category: 'CONT',
      severity: 'HIGH',
      title: 'Name/body capability mismatch',
      message: `Skill name "${name}" implies capabilities not found in body content.`,
    });
  }
}
