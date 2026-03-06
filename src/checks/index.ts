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
import { structuralChecks } from './structural.js';
import { contentChecks } from './content.js';
import { injectionChecks } from './injection.js';
import { codeSafetyChecks } from './code-safety.js';
import { supplyChainChecks } from './supply-chain.js';
import { resourceChecks } from './resource.js';
import { iocChecks } from './ioc.js';

const ALL_MODULES: CheckModule[] = [
  structuralChecks,
  contentChecks,
  injectionChecks,
  codeSafetyChecks,
  supplyChainChecks,
  resourceChecks,
  iocChecks,
];

/**
 * Run all registered check modules against a parsed skill.
 */
export function runAllChecks(skill: ParsedSkill): CheckResult[] {
  const results: CheckResult[] = [];
  for (const mod of ALL_MODULES) {
    results.push(...mod.run(skill));
  }
  return results;
}

export { ALL_MODULES };
