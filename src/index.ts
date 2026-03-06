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

// Public API
export { scanSkillDirectory, scanSkillContent, worstSeverity } from './scanner.js';
export { parseSkill, parseSkillContent } from './parser.js';
export { runAllChecks } from './checks/index.js';
export { formatTerminalReport } from './reporter/terminal.js';
export { formatJsonReport, generateHookResponse } from './reporter/json.js';
export { loadConfig } from './config.js';
export { loadIOC, resetIOCCache } from './ioc/index.js';

export type {
  Severity,
  Grade,
  CheckCategory,
  CheckResult,
  CheckModule,
  SkillFrontmatter,
  ParsedSkill,
  SkillFile,
  ScanReport,
  PolicyLevel,
  HookAction,
  SkillCheckerConfig,
} from './types.js';

export {
  SEVERITY_SCORES,
  computeGrade,
  getHookAction,
  DEFAULT_CONFIG,
} from './types.js';
