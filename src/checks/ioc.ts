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
import { loadIOC } from '../ioc/index.js';
import {
  matchMaliciousHashes,
  matchC2IPs,
  matchTyposquat,
} from '../ioc/matcher.js';

export const iocChecks: CheckModule = {
  name: 'IOC Threat Intelligence',
  category: 'SUPPLY',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];
    const ioc = loadIOC();

    // SUPPLY-008: Known malicious file hashes
    const hashMatches = matchMaliciousHashes(skill, ioc);
    for (const match of hashMatches) {
      results.push({
        id: 'SUPPLY-008',
        category: 'SUPPLY',
        severity: 'CRITICAL',
        title: 'Known malicious file hash',
        message: `File "${match.file}" matches known malicious hash: ${match.description}`,
        snippet: match.hash,
        source: match.file,
      });
    }

    // SUPPLY-009: Known C2 IP addresses
    const ipMatches = matchC2IPs(skill, ioc);
    for (const match of ipMatches) {
      results.push({
        id: 'SUPPLY-009',
        category: 'SUPPLY',
        severity: 'CRITICAL',
        title: 'Known C2 IP address',
        message: `${match.source}:${match.line}: Contains known C2 server IP: ${match.ip}`,
        line: match.line,
        snippet: match.snippet,
        source: match.source,
      });
    }

    // SUPPLY-010: Typosquat name detection
    const skillName = skill.frontmatter.name;
    if (skillName) {
      const typoMatch = matchTyposquat(skillName, ioc);
      if (typoMatch) {
        if (typoMatch.type === 'known') {
          results.push({
            id: 'SUPPLY-010',
            category: 'SUPPLY',
            severity: 'CRITICAL',
            title: 'Known typosquat name',
            message: `Skill name "${skillName}" matches known typosquat pattern "${typoMatch.target}".`,
            snippet: skillName,
          });
        } else {
          results.push({
            id: 'SUPPLY-010',
            category: 'SUPPLY',
            severity: 'HIGH',
            title: 'Possible typosquat name',
            message: `Skill name "${skillName}" is similar to protected name "${typoMatch.target}" (edit distance: ${typoMatch.distance}).`,
            snippet: skillName,
          });
        }
      }
    }

    return results;
  },
};
