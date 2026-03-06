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
import { shannonEntropy, isBase64Like, isHexEncoded } from '../utils/entropy.js';
import { isInDocumentationContext, isInCodeBlock } from '../utils/context.js';

/** Dangerous eval/exec patterns */
const EVAL_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bsetTimeout\s*\(\s*["'`]/,
  /\bsetInterval\s*\(\s*["'`]/,
];

/** Shell execution patterns */
const SHELL_EXEC_PATTERNS = [
  /\bchild_process\b/,
  /\bexecSync\b/,
  /\bspawnSync\b/,
  /\bos\.system\s*\(/,
  /\bsubprocess\.(run|call|Popen)\s*\(/,
  /(?<!\bplatform\.)\bsystem\s*\(/, // exclude platform.system()
  /`[^`]*\$\([^)]+\)[^`]*`/, // backtick with command substitution
];

/**
 * Patterns that look like shell execution but are actually
 * read-only system info queries (not dangerous).
 */
const SHELL_EXEC_FALSE_POSITIVES = [
  /\bplatform\.system\s*\(\s*\)/,  // Python: just reads OS name
];

/** Destructive file operations */
const DESTRUCTIVE_PATTERNS = [
  /\brm\s+-rf\b/,
  /\brm\s+-r\b/,
  /\brmdir\b/,
  /\bunlink\s*\(/,
  /\bfs\.rm(Sync)?\s*\(/,
  /\bshutil\.rmtree\s*\(/,
  /\bdel\s+\/[sf]/i,
  /\bformat\s+[a-z]:/i,
];

/** Network request patterns with hardcoded URLs */
const NETWORK_PATTERNS = [
  /\bfetch\s*\(\s*["'`]https?:\/\//,
  /\baxios\.(get|post|put|delete)\s*\(\s*["'`]https?:\/\//,
  /\bcurl\s+/,
  /\bwget\s+/,
  /\brequests?\.(get|post)\s*\(/,
  /\bhttp\.get\s*\(/,
  /\bURLSession\b/,
];

/** File write outside expected directory */
const FILE_WRITE_PATTERNS = [
  /\bfs\.writeFile(Sync)?\s*\(\s*["'`]\//,
  /\bopen\s*\(\s*["'`]\/[^"'`]+["'`]\s*,\s*["'`]w/,
  />\s*\/etc\//,
  />\s*\/usr\//,
  />\s*~\//,
  />\s*\$HOME\//,
];

/** Environment variable access */
const ENV_ACCESS_PATTERNS = [
  /process\.env\b/,
  /\bos\.environ\b/,
  /\bgetenv\s*\(/,
  /\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)\w*\}?/i,
];

/** Dynamic code generation */
const DYNAMIC_CODE_PATTERNS = [
  /\bcompile\s*\(/,
  /\bcodegen\b/i,
  /\bimport\s*\(\s*[^"'`\s]/,
  /\brequire\s*\(\s*[^"'`\s]/,
  /\b__import__\s*\(/,
];

/** Permission escalation */
const PERMISSION_PATTERNS = [
  /\bchmod\s+[+0-9]/,
  /\bchown\b/,
  /\bsudo\b/,
  /\bdoas\b/,
  /\bsetuid\b/,
  /\bsetgid\b/,
];

export const codeSafetyChecks: CheckModule = {
  name: 'Code Safety',
  category: 'CODE',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];

    // Collect all text content to scan
    const textSources = getTextSources(skill);

    for (const { text, source } of textSources) {
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;
        const loc = `${source}:${lineNum}`;
        const cbCtx = { lines, index: i };

        // CODE-001: eval/exec — always CRITICAL, no code block reduction
        checkPatterns(results, line, EVAL_PATTERNS, {
          id: 'CODE-001',
          severity: 'CRITICAL',
          title: 'eval/exec/Function constructor',
          loc,
          lineNum,
        });

        // CODE-002: shell execution — always CRITICAL, no code block reduction
        if (!SHELL_EXEC_FALSE_POSITIVES.some((p) => p.test(line))) {
          checkPatterns(results, line, SHELL_EXEC_PATTERNS, {
            id: 'CODE-002',
            severity: 'CRITICAL',
            title: 'Shell/subprocess execution',
            loc,
            lineNum,
          });
        }

        // CODE-003: destructive file operations — code block reduction
        checkPatterns(results, line, DESTRUCTIVE_PATTERNS, {
          id: 'CODE-003',
          severity: 'CRITICAL',
          title: 'Destructive file operation',
          loc,
          lineNum,
          codeBlockCtx: cbCtx,
        });

        // CODE-004: hardcoded external URLs — code block reduction
        checkPatterns(results, line, NETWORK_PATTERNS, {
          id: 'CODE-004',
          severity: 'HIGH',
          title: 'Hardcoded external URL/network request',
          loc,
          lineNum,
          codeBlockCtx: cbCtx,
        });

        // CODE-005: file write outside expected dir — no code block reduction
        checkPatterns(results, line, FILE_WRITE_PATTERNS, {
          id: 'CODE-005',
          severity: 'HIGH',
          title: 'File write outside expected directory',
          loc,
          lineNum,
        });

        // CODE-006: env var access — code block reduction
        checkPatterns(results, line, ENV_ACCESS_PATTERNS, {
          id: 'CODE-006',
          severity: 'MEDIUM',
          title: 'Environment variable access',
          loc,
          lineNum,
          codeBlockCtx: cbCtx,
        });

        // CODE-010: dynamic code generation — no code block reduction
        checkPatterns(results, line, DYNAMIC_CODE_PATTERNS, {
          id: 'CODE-010',
          severity: 'HIGH',
          title: 'Dynamic code generation pattern',
          loc,
          lineNum,
        });

        // CODE-012: permission escalation
        // Skip when in documentation context (installation guides)
        {
          const isDoc = isInDocumentationContext(lines, i);
          if (!isDoc) {
            checkPatterns(results, line, PERMISSION_PATTERNS, {
              id: 'CODE-012',
              severity: 'HIGH',
              title: 'Permission escalation',
              loc,
              lineNum,
            });
          }
        }
      }

      // Multi-line checks
      scanEncodedStrings(results, text, source);
      scanObfuscation(results, text, source);
    }

    return results;
  },
};

interface PatternCheckOpts {
  id: string;
  severity: Severity;
  title: string;
  loc: string;
  lineNum: number;
  codeBlockCtx?: { lines: string[]; index: number };
}

function checkPatterns(
  results: CheckResult[],
  line: string,
  patterns: RegExp[],
  opts: PatternCheckOpts
): void {
  for (const pattern of patterns) {
    if (pattern.test(line)) {
      let severity = opts.severity;
      let reducedFrom: Severity | undefined;
      let msgSuffix = '';
      if (opts.codeBlockCtx && isInCodeBlock(opts.codeBlockCtx.lines, opts.codeBlockCtx.index)) {
        const r = reduceSeverity(severity, 'in code block');
        severity = r.severity;
        reducedFrom = r.reducedFrom;
        msgSuffix = ` ${r.annotation}`;
      }
      results.push({
        id: opts.id,
        category: 'CODE',
        severity,
        title: opts.title,
        message: `At ${opts.loc}: ${line.trim().slice(0, 120)}${msgSuffix}`,
        line: opts.lineNum,
        snippet: line.trim().slice(0, 120),
        reducedFrom,
      });
      return; // one match per line per rule
    }
  }
}

function getTextSources(
  skill: ParsedSkill
): Array<{ text: string; source: string }> {
  const sources: Array<{ text: string; source: string }> = [
    { text: skill.body, source: 'SKILL.md' },
  ];
  for (const file of skill.files) {
    if (file.content && file.path !== 'SKILL.md') {
      sources.push({ text: file.content, source: file.path });
    }
  }
  return sources;
}

function scanEncodedStrings(
  results: CheckResult[],
  text: string,
  source: string
): void {
  // CODE-007: Base64/Hex long strings
  const longStringRegex = /[A-Za-z0-9+/=]{50,}|(?:0x)?[0-9a-fA-F]{50,}/g;
  let match;
  while ((match = longStringRegex.exec(text)) !== null) {
    const str = match[0];
    if (isBase64Like(str) || isHexEncoded(str)) {
      const lineNum = text.slice(0, match.index).split('\n').length;
      results.push({
        id: 'CODE-007',
        category: 'CODE',
        severity: 'HIGH',
        title: 'Long encoded string',
        message: `${source}:${lineNum}: Found ${str.length}-char encoded string.`,
        line: lineNum,
        snippet: str.slice(0, 80) + '...',
      });
    }
  }

  // CODE-008: High Shannon entropy strings
  const wordRegex = /\b[A-Za-z0-9_]{20,}\b/g;
  while ((match = wordRegex.exec(text)) !== null) {
    const entropy = shannonEntropy(match[0]);
    if (entropy > 4.5) {
      const lineNum = text.slice(0, match.index).split('\n').length;
      results.push({
        id: 'CODE-008',
        category: 'CODE',
        severity: 'MEDIUM',
        title: 'High entropy string',
        message: `${source}:${lineNum}: String "${match[0].slice(0, 30)}..." has entropy ${entropy.toFixed(2)} bits/char.`,
        line: lineNum,
      });
    }
  }

  // CODE-009: Multi-layer encoding
  const multiEncodingPatterns = [
    /atob\s*\(\s*atob/i,
    /base64.*decode.*base64.*decode/i,
    /Buffer\.from\(.*Buffer\.from/,
    /decode.*decode.*decode/i,
  ];
  for (const pattern of multiEncodingPatterns) {
    if (pattern.test(text)) {
      results.push({
        id: 'CODE-009',
        category: 'CODE',
        severity: 'CRITICAL',
        title: 'Multi-layer encoding detected',
        message: `${source}: Contains nested encoding/decoding operations.`,
      });
      break;
    }
  }
}

function scanObfuscation(
  results: CheckResult[],
  text: string,
  source: string
): void {
  // CODE-011: Obfuscated variable names
  // Look for patterns like: const _0x1a2b = ...
  const obfuscatedVarRegex = /\b_0x[0-9a-f]{2,}\b/g;
  const obfMatches = text.match(obfuscatedVarRegex);
  if (obfMatches && obfMatches.length >= 3) {
    results.push({
      id: 'CODE-011',
      category: 'CODE',
      severity: 'MEDIUM',
      title: 'Obfuscated variable names',
      message: `${source}: Found ${obfMatches.length} hex-style variable names (e.g. ${obfMatches[0]}). May indicate obfuscated code.`,
    });
  }
}
