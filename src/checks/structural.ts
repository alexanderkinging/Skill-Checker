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

const HYPHEN_CASE_RE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const MAX_NAME_LENGTH = 64;
const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.ps1', '.com', '.msi',
]);
const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm', '.class', '.pyc',
]);

export const structuralChecks: CheckModule = {
  name: 'Structural Validity',
  category: 'STRUCT',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];

    // STRUCT-001: Missing SKILL.md
    if (!skill.raw) {
      results.push({
        id: 'STRUCT-001',
        category: 'STRUCT',
        severity: 'CRITICAL',
        title: 'Missing SKILL.md',
        message: 'No SKILL.md file found in the skill directory.',
      });
      return results; // no point checking further
    }

    // STRUCT-002: Invalid/missing frontmatter
    if (!skill.frontmatterValid) {
      results.push({
        id: 'STRUCT-002',
        category: 'STRUCT',
        severity: 'HIGH',
        title: 'Invalid YAML frontmatter',
        message:
          'SKILL.md is missing valid YAML frontmatter (---...--- block).',
      });
    }

    // STRUCT-003: Missing name field
    if (!skill.frontmatter.name) {
      results.push({
        id: 'STRUCT-003',
        category: 'STRUCT',
        severity: 'HIGH',
        title: 'Missing name field',
        message: 'Frontmatter is missing the required "name" field.',
      });
    }

    // STRUCT-004: Missing description field
    if (!skill.frontmatter.description) {
      results.push({
        id: 'STRUCT-004',
        category: 'STRUCT',
        severity: 'MEDIUM',
        title: 'Missing description field',
        message: 'Frontmatter is missing the "description" field.',
      });
    }

    // STRUCT-005: Body too short
    if (skill.body.trim().length < 50) {
      results.push({
        id: 'STRUCT-005',
        category: 'STRUCT',
        severity: 'CRITICAL',
        title: 'SKILL.md body is too short',
        message: `Body is only ${skill.body.trim().length} characters. A valid skill should have meaningful instructions (>=50 chars).`,
      });
    }

    // STRUCT-006: Unexpected files (binary/executable)
    for (const file of skill.files) {
      const ext = file.extension.toLowerCase();
      if (BINARY_EXTENSIONS.has(ext) || EXECUTABLE_EXTENSIONS.has(ext)) {
        results.push({
          id: 'STRUCT-006',
          category: 'STRUCT',
          severity: 'HIGH',
          title: 'Unexpected binary/executable file',
          message: `Found unexpected file: ${file.path} (${ext})`,
        });
      }
    }

    // STRUCT-007: Name format
    const name = skill.frontmatter.name;
    if (name) {
      if (!HYPHEN_CASE_RE.test(name)) {
        results.push({
          id: 'STRUCT-007',
          category: 'STRUCT',
          severity: 'MEDIUM',
          title: 'Name not in hyphen-case format',
          message: `Skill name "${name}" should be in hyphen-case (e.g. "my-skill").`,
        });
      }
      if (name.length > MAX_NAME_LENGTH) {
        results.push({
          id: 'STRUCT-007',
          category: 'STRUCT',
          severity: 'MEDIUM',
          title: 'Name too long',
          message: `Skill name is ${name.length} chars, max ${MAX_NAME_LENGTH}.`,
        });
      }
    }

    // STRUCT-008: Skipped or partially scanned paths
    for (const warning of skill.warnings) {
      results.push({
        id: 'STRUCT-008',
        category: 'STRUCT',
        severity: 'MEDIUM',
        title: 'Scan coverage warning',
        message: warning,
      });
    }

    return results;
  },
};
