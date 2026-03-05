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
import {
  isNamespaceOrSchemaURI,
  isInNetworkRequestContext,
  isInDocumentationContext,
} from '../utils/context.js';

/** Known suspicious/malicious domains (sample list) */
const SUSPICIOUS_DOMAINS = [
  'evil.com',
  'malware.com',
  'exploit.in',
  'darkweb.onion',
  'pastebin.com',  // often used for payload hosting
  'ngrok.io',      // tunneling service
  'requestbin.com',
  'webhook.site',
  'pipedream.net',
  'burpcollaborator.net',
  'interact.sh',
  'oastify.com',
];

const MCP_SERVER_PATTERN = /\bmcp[-_]?server\b/i;
const NPX_Y_PATTERN = /\bnpx\s+-y\s+/;
const NPM_INSTALL_PATTERN = /\bnpm\s+install\b/;
const PIP_INSTALL_PATTERN = /\bpip3?\s+install\b/;
const GIT_CLONE_PATTERN = /\bgit\s+clone\b/;

/** URL extraction pattern */
const URL_PATTERN = /https?:\/\/[^\s"'`<>)\]]+/g;
/** IP address pattern (not localhost) */
const IP_URL_PATTERN = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/;

export const supplyChainChecks: CheckModule = {
  name: 'Supply Chain',
  category: 'SUPPLY',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];
    const allText = getAllText(skill);

    for (let i = 0; i < allText.length; i++) {
      const { line, lineNum, source } = allText[i];

      // SUPPLY-001: Unknown MCP server references
      if (MCP_SERVER_PATTERN.test(line)) {
        results.push({
          id: 'SUPPLY-001',
          category: 'SUPPLY',
          severity: 'HIGH',
          title: 'MCP server reference',
          message: `${source}:${lineNum}: References an MCP server. Verify it is from a trusted source.`,
          line: lineNum,
          snippet: line.trim().slice(0, 120),
        });
      }

      // SUPPLY-002: npx -y auto-install
      if (NPX_Y_PATTERN.test(line)) {
        results.push({
          id: 'SUPPLY-002',
          category: 'SUPPLY',
          severity: 'MEDIUM',
          title: 'npx -y auto-install',
          message: `${source}:${lineNum}: Uses npx -y which auto-installs packages without confirmation.`,
          line: lineNum,
          snippet: line.trim().slice(0, 120),
        });
      }

      // SUPPLY-003: npm/pip install unknown packages
      // Skip when in documentation context (installation guides / prerequisites)
      if (NPM_INSTALL_PATTERN.test(line) || PIP_INSTALL_PATTERN.test(line)) {
        const allLines = getAllLines(skill);
        const globalIdx = findGlobalLineIndex(allLines, source, lineNum);
        const isDoc = globalIdx >= 0 && isInDocumentationContext(
          allLines.map((l) => l.line),
          globalIdx
        );
        if (!isDoc) {
          results.push({
            id: 'SUPPLY-003',
            category: 'SUPPLY',
            severity: 'HIGH',
            title: 'Package installation command',
            message: `${source}:${lineNum}: Installs packages. Verify package names are legitimate.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
        }
      }

      // SUPPLY-006: git clone non-standard source
      if (GIT_CLONE_PATTERN.test(line)) {
        results.push({
          id: 'SUPPLY-006',
          category: 'SUPPLY',
          severity: 'MEDIUM',
          title: 'git clone command',
          message: `${source}:${lineNum}: Clones a git repository. Verify the source.`,
          line: lineNum,
          snippet: line.trim().slice(0, 120),
        });
      }

      // URL-based checks
      const urls = line.match(URL_PATTERN) || [];
      for (const url of urls) {
        // SUPPLY-004: Non-HTTPS URL
        // Skip namespace/schema URIs (identifiers, not network endpoints)
        // and URLs not in actual network request context
        if (url.startsWith('http://')) {
          if (!isNamespaceOrSchemaURI(url, line)) {
            // Still flag if in network request context, or as lower severity info
            const isNetworkCtx = isInNetworkRequestContext(line);
            results.push({
              id: 'SUPPLY-004',
              category: 'SUPPLY',
              severity: isNetworkCtx ? 'HIGH' : 'MEDIUM',
              title: 'Non-HTTPS URL',
              message: `${source}:${lineNum}: Uses insecure HTTP: ${url}`,
              line: lineNum,
              snippet: url,
            });
          }
        }

        // SUPPLY-005: IP address instead of domain
        if (IP_URL_PATTERN.test(url)) {
          // Exclude localhost
          if (!/https?:\/\/127\.0\.0\.1/.test(url) && !/https?:\/\/0\.0\.0\.0/.test(url)) {
            results.push({
              id: 'SUPPLY-005',
              category: 'SUPPLY',
              severity: 'CRITICAL',
              title: 'IP address used instead of domain',
              message: `${source}:${lineNum}: Uses raw IP address: ${url}. This may bypass DNS-based security.`,
              line: lineNum,
              snippet: url,
            });
          }
        }

        // SUPPLY-007: Known suspicious domains
        for (const domain of SUSPICIOUS_DOMAINS) {
          if (url.includes(domain)) {
            results.push({
              id: 'SUPPLY-007',
              category: 'SUPPLY',
              severity: 'CRITICAL',
              title: 'Suspicious domain detected',
              message: `${source}:${lineNum}: References suspicious domain "${domain}".`,
              line: lineNum,
              snippet: url,
            });
            break;
          }
        }
      }
    }

    return results;
  },
};

type TextLine = { line: string; lineNum: number; source: string };

function getAllText(skill: ParsedSkill): TextLine[] {
  const result: TextLine[] = [];

  for (let i = 0; i < skill.bodyLines.length; i++) {
    result.push({
      line: skill.bodyLines[i],
      lineNum: skill.bodyStartLine + i,
      source: 'SKILL.md',
    });
  }

  for (const file of skill.files) {
    if (file.content && file.path !== 'SKILL.md') {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        result.push({ line: lines[i], lineNum: i + 1, source: file.path });
      }
    }
  }

  return result;
}

/** Get all lines from SKILL.md body (for context lookback) */
function getAllLines(skill: ParsedSkill): TextLine[] {
  return getAllText(skill);
}

/** Find the global index of a source:lineNum in the flat list */
function findGlobalLineIndex(
  allLines: TextLine[],
  source: string,
  lineNum: number
): number {
  return allLines.findIndex(
    (l) => l.source === source && l.lineNum === lineNum
  );
}
