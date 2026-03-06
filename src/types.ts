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

// ===== Severity & Scoring =====

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const SEVERITY_SCORES: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 3,
  LOW: 1,
};

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export function computeGrade(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

// ===== Check Result =====

export type CheckCategory =
  | 'STRUCT'
  | 'CONT'
  | 'INJ'
  | 'CODE'
  | 'SUPPLY'
  | 'RES';

export interface CheckResult {
  id: string;            // e.g. "INJ-001"
  category: CheckCategory;
  severity: Severity;
  title: string;
  message: string;
  line?: number;         // line number in SKILL.md
  snippet?: string;      // relevant code snippet
  reducedFrom?: Severity; // original severity before context-aware reduction
  occurrences?: number;   // count after per-file deduplication
}

// ===== Severity Reduction =====

const REDUCE_MAP: Record<Severity, Severity> = {
  CRITICAL: 'HIGH',
  HIGH: 'MEDIUM',
  MEDIUM: 'LOW',
  LOW: 'LOW',
};

/**
 * Reduce severity by one level with audit trail.
 * Safety floor: a CRITICAL-origin finding never drops below MEDIUM.
 */
export function reduceSeverity(
  original: Severity,
  reason: string
): { severity: Severity; reducedFrom: Severity; annotation: string } {
  let reduced = REDUCE_MAP[original];
  // Safety floor: CRITICAL source never goes below MEDIUM
  if (original === 'CRITICAL' && reduced === 'LOW') {
    reduced = 'MEDIUM';
  }
  return {
    severity: reduced,
    reducedFrom: original,
    annotation: `[reduced: ${reason}]`,
  };
}

// ===== Parsed Skill =====

export interface SkillFrontmatter {
  name?: string;
  description?: string;
  version?: string;
  'allowed-tools'?: string[];
  [key: string]: unknown;
}

export interface ParsedSkill {
  /** Path to the skill directory */
  dirPath: string;
  /** Raw SKILL.md content */
  raw: string;
  /** Parsed frontmatter (YAML) */
  frontmatter: SkillFrontmatter;
  /** Whether frontmatter was valid YAML */
  frontmatterValid: boolean;
  /** Body text after frontmatter */
  body: string;
  /** Lines of the body for line-number tracking */
  bodyLines: string[];
  /** Offset: line number where body starts in the raw file */
  bodyStartLine: number;
  /** Other files in the skill directory */
  files: SkillFile[];
  /** Warnings about skipped directories/files during parsing */
  warnings: string[];
}

export interface SkillFile {
  path: string;          // relative to skill dir
  name: string;
  extension: string;
  sizeBytes: number;
  isBinary: boolean;
  content?: string;      // text content if not binary
}

// ===== Scan Report =====

export interface ScanReport {
  skillPath: string;
  skillName: string;
  timestamp: string;
  results: CheckResult[];
  score: number;
  grade: Grade;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// ===== Check Module Interface =====

export interface CheckModule {
  name: string;
  category: CheckCategory;
  run(skill: ParsedSkill): CheckResult[];
}

// ===== Configuration =====

export type PolicyLevel = 'strict' | 'balanced' | 'permissive';
export type HookAction = 'deny' | 'ask' | 'report';

export interface SkillCheckerConfig {
  policy: PolicyLevel;
  overrides: Record<string, Severity>;
  ignore: string[];
}

export const DEFAULT_CONFIG: SkillCheckerConfig = {
  policy: 'balanced',
  overrides: {},
  ignore: [],
};

/** Maps policy + severity to hook action */
export function getHookAction(
  policy: PolicyLevel,
  severity: Severity
): HookAction {
  const matrix: Record<PolicyLevel, Record<Severity, HookAction>> = {
    strict: {
      CRITICAL: 'deny',
      HIGH: 'deny',
      MEDIUM: 'ask',
      LOW: 'report',
    },
    balanced: {
      CRITICAL: 'deny',
      HIGH: 'ask',
      MEDIUM: 'report',
      LOW: 'report',
    },
    permissive: {
      CRITICAL: 'ask',
      HIGH: 'report',
      MEDIUM: 'report',
      LOW: 'report',
    },
  };
  return matrix[policy][severity];
}
