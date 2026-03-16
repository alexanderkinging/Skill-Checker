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

import type { CheckModule, CheckResult, ParsedSkill, Severity } from '../types.js';
import { reduceSeverity } from '../types.js';
import {
  isNamespaceOrSchemaURI,
  isInNetworkRequestContext,
  isInDocumentationContext,
  isNearDocumentationHeader,
  isInCodeBlock,
  isLicenseFile,
  isLocalhostURL,
} from '../utils/context.js';
import { loadIOC, getAllDomains, getDomainCategory } from '../ioc/index.js';

/** Hardcoded fallback domains (used when IOC has no malicious_domains) */
const FALLBACK_SUSPICIOUS_DOMAINS = [
  'darkweb.onion',
];

/**
 * Check if the line contains a suspicious domain combined with sensitive operations.
 * These combinations indicate likely malicious intent rather than documentation.
 */
function isSensitiveDomainCombo(line: string): boolean {
  if (/curl\b[^\n]*(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\s+@/i.test(line)) {
    return true;
  }
  if (/curl\b[^\n]*(?:-F|--form)\s+[^\s=]+=@/i.test(line)) {
    return true;
  }
  if (/wget\b[^\n]*--post-file/i.test(line)) {
    return true;
  }
  if (/\|\s*(?:sh|bash|zsh|python|node)\b/i.test(line)) {
    return true;
  }
  if (/(?:\.env|\.ssh|id_rsa|\.aws|credentials|\.netrc|\.git-credentials)/i.test(line)) {
    return true;
  }
  return false;
}

const MCP_SERVER_PATTERN = /\bmcp[-_]?server\b/i;
const NPX_Y_PATTERN = /\bnpx\s+-y\s+/;
const NPM_INSTALL_PATTERN = /\bnpm\s+install\b/;
const PIP_INSTALL_PATTERN = /\bpip3?\s+install\b/;
const GIT_CLONE_PATTERN = /\bgit\s+clone\b/;

/** URL extraction pattern */
const URL_PATTERN = /https?:\/\/[^\s"'`<>)\]]+/g;
/** IP address pattern (not localhost) */
const IP_URL_PATTERN = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/;

/**
 * Extract hostname from a URL string without using the URL constructor
 * (which may throw on malformed URLs found in skill content).
 */
function extractHostname(url: string): string {
  const afterProto = url.replace(/^https?:\/\//, '');
  const hostPort = afterProto.split('/')[0].split('?')[0].split('#')[0];
  const host = hostPort.split(':')[0];
  return host.toLowerCase();
}

/**
 * Check if a hostname matches a domain exactly or is a subdomain of it.
 * e.g. domain="evil.com" matches "evil.com" and "a.evil.com"
 * but NOT "notevil.com" or "evil.com.cn"
 */
function hostnameMatchesDomain(hostname: string, domain: string): boolean {
  const d = domain.toLowerCase();
  return hostname === d || hostname.endsWith('.' + d);
}

export const supplyChainChecks: CheckModule = {
  name: 'Supply Chain',
  category: 'SUPPLY',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];
    const allText = getAllText(skill);
    const ioc = loadIOC();
    const suspiciousDomains = getAllDomains(ioc);
    if (suspiciousDomains.length === 0) {
      suspiciousDomains.push(...FALLBACK_SUSPICIOUS_DOMAINS);
    }

    for (let i = 0; i < allText.length; i++) {
      const { line, lineNum, source } = allText[i];

      // SUPPLY-001: Unknown MCP server references
      if (MCP_SERVER_PATTERN.test(line)) {
        let severity: Severity = 'HIGH';
        let reducedFrom: Severity | undefined;
        let msgSuffix = '';
        const srcLines = getLinesForSource(skill, source);
        const localIdx = getLocalIndex(source, lineNum, skill.bodyStartLine);
        if (localIdx >= 0 && isInCodeBlock(srcLines, localIdx)) {
          const r = reduceSeverity(severity, 'in code block');
          severity = r.severity;
          reducedFrom = r.reducedFrom;
          msgSuffix = ` ${r.annotation}`;
        }
        results.push({
          id: 'SUPPLY-001',
          category: 'SUPPLY',
          severity,
          title: 'MCP server reference',
          message: `${source}:${lineNum}: References an MCP server. Verify it is from a trusted source.${msgSuffix}`,
          line: lineNum,
          snippet: line.trim().slice(0, 120),
          source,
          reducedFrom,
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
          source,
        });
      }

      // SUPPLY-003: npm/pip install unknown packages
      // Skip when in documentation context (installation guides / prerequisites)
      // Documentation context only applies to SKILL.md, not companion scripts
      if (NPM_INSTALL_PATTERN.test(line) || PIP_INSTALL_PATTERN.test(line)) {
        const allLines = getAllLines(skill);
        const globalIdx = findGlobalLineIndex(allLines, source, lineNum);
        const isDoc = source === 'SKILL.md' && globalIdx >= 0 && isInDocumentationContext(
          allLines.map((l) => l.line),
          globalIdx
        );
        const srcLines = getLinesForSource(skill, source);
        const localIdx = getLocalIndex(source, lineNum, skill.bodyStartLine);
        const inCodeBlock = localIdx >= 0 && isInCodeBlock(srcLines, localIdx);
        if (isDoc && !inCodeBlock) {
          // Documentation context without code block: skip entirely
        } else {
          let severity: Severity = 'HIGH';
          let reducedFrom: Severity | undefined;
          let msgSuffix = '';
          if (inCodeBlock) {
            // Check if also under a documentation header (double context)
            // Only applies to SKILL.md (script comments must not match)
            const isNearDoc = source === 'SKILL.md' && globalIdx >= 0 && isNearDocumentationHeader(
              allLines.map((l) => l.line),
              globalIdx
            );
            if (isNearDoc) {
              // Double context: code block + documentation header → LOW
              severity = 'LOW';
              reducedFrom = 'HIGH';
              msgSuffix = ' [reduced: in code block within documentation]';
            } else {
              const r = reduceSeverity(severity, 'in code block');
              severity = r.severity;
              reducedFrom = r.reducedFrom;
              msgSuffix = ` ${r.annotation}`;
            }
          }
          results.push({
            id: 'SUPPLY-003',
            category: 'SUPPLY',
            severity,
            title: 'Package installation command',
            message: `${source}:${lineNum}: Installs packages. Verify package names are legitimate.${msgSuffix}`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
            source,
            reducedFrom,
          });
        }
      }

      // SUPPLY-006: git clone non-standard source
      // Skip when in documentation context (installation guides / prerequisites)
      // Documentation context only applies to SKILL.md, not companion scripts
      if (GIT_CLONE_PATTERN.test(line)) {
        const allLines = getAllLines(skill);
        const globalIdx = findGlobalLineIndex(allLines, source, lineNum);
        const isDoc = source === 'SKILL.md' && globalIdx >= 0 && isInDocumentationContext(
          allLines.map((l) => l.line),
          globalIdx
        );
        if (!isDoc) {
          let severity: Severity = 'MEDIUM';
          let reducedFrom: Severity | undefined;
          let msgSuffix = '';
          const srcLines = getLinesForSource(skill, source);
          const localIdx = getLocalIndex(source, lineNum, skill.bodyStartLine);
          if (localIdx >= 0 && isInCodeBlock(srcLines, localIdx)) {
            const r = reduceSeverity(severity, 'in code block');
            severity = r.severity;
            reducedFrom = r.reducedFrom;
            msgSuffix = ` ${r.annotation}`;
          }
          results.push({
            id: 'SUPPLY-006',
            category: 'SUPPLY',
            severity,
            title: 'git clone command',
            message: `${source}:${lineNum}: Clones a git repository. Verify the source.${msgSuffix}`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
            source,
            reducedFrom,
          });
        }
      }

      // URL-based checks
      const urls = line.match(URL_PATTERN) || [];
      for (const url of urls) {
        // SUPPLY-004: Non-HTTPS URL
        // Skip namespace/schema URIs, license files, and localhost
        if (url.startsWith('http://')) {
          if (isLicenseFile(source)) continue; // legal text, not instruction
          if (isLocalhostURL(url)) continue;   // no external attack surface
          if (!isNamespaceOrSchemaURI(url, line)) {
            const isNetworkCtx = isInNetworkRequestContext(line);
            let severity: Severity = isNetworkCtx ? 'HIGH' : 'MEDIUM';
            let reducedFrom: Severity | undefined;
            let msgSuffix = '';
            const srcLines = getLinesForSource(skill, source);
            const localIdx = getLocalIndex(source, lineNum, skill.bodyStartLine);
            if (localIdx >= 0 && isInCodeBlock(srcLines, localIdx)) {
              const r = reduceSeverity(severity, 'in code block');
              severity = r.severity;
              reducedFrom = r.reducedFrom;
              msgSuffix = ` ${r.annotation}`;
            }
            results.push({
              id: 'SUPPLY-004',
              category: 'SUPPLY',
              severity,
              title: 'Non-HTTPS URL',
              message: `${source}:${lineNum}: Uses insecure HTTP: ${url}${msgSuffix}`,
              line: lineNum,
              snippet: url,
              source,
              reducedFrom,
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
              source,
            });
          }
        }

        // SUPPLY-007: Known suspicious domains (from IOC database)
        const hostname = extractHostname(url);
        for (const domain of suspiciousDomains) {
          if (hostnameMatchesDomain(hostname, domain)) {
            const category = getDomainCategory(ioc, domain);
            const categoryLabel = category ? ` (${category})` : '';

            let severity: Severity = 'HIGH';
            let reducedFrom: Severity | undefined;
            let msgSuffix = '';

            // Escalate: combined with sensitive operations on same line
            if (isSensitiveDomainCombo(line)) {
              severity = 'CRITICAL';
              msgSuffix = ' [escalated: combined with sensitive operation]';
            } else {
              // Check code block context
              const srcLines = getLinesForSource(skill, source);
              const localIdx = getLocalIndex(source, lineNum, skill.bodyStartLine);
              const inCodeBlock = localIdx >= 0 && isInCodeBlock(srcLines, localIdx);

              if (inCodeBlock) {
                severity = 'MEDIUM';
                reducedFrom = 'HIGH';
                msgSuffix = ' [reduced: in code block]';
              } else {
                // Check documentation context
                const allLines = getAllLines(skill);
                const globalIdx = findGlobalLineIndex(allLines, source, lineNum);
                const isDoc = source === 'SKILL.md' && globalIdx >= 0 && isInDocumentationContext(
                  allLines.map((l) => l.line),
                  globalIdx
                );
                if (isDoc) {
                  severity = 'LOW';
                  reducedFrom = 'HIGH';
                  msgSuffix = ' [reduced: in documentation context]';
                }
              }
            }

            results.push({
              id: 'SUPPLY-007',
              category: 'SUPPLY',
              severity,
              title: `Suspicious domain${categoryLabel} detected`,
              message: `${source}:${lineNum}: References suspicious domain "${domain}".${msgSuffix}`,
              line: lineNum,
              snippet: url,
              source,
              reducedFrom,
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

/** Get all lines for a specific source file as a string array (for code block tracking). */
function getLinesForSource(skill: ParsedSkill, source: string): string[] {
  if (source === 'SKILL.md') return skill.bodyLines;
  const file = skill.files.find((f) => f.path === source);
  return file?.content?.split('\n') ?? [];
}

/** Convert source-relative lineNum to zero-based index in the source lines array. */
function getLocalIndex(source: string, lineNum: number, bodyStartLine: number): number {
  if (source === 'SKILL.md') return lineNum - bodyStartLine;
  return lineNum - 1;
}

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
