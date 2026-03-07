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

/** CODE-013 provider credential patterns (precise matches) */
const PROVIDER_CREDENTIAL_PATTERNS: Array<{ pattern: RegExp; title: string }> = [
  {
    pattern: /\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b/,
    title: 'Anthropic API key exposure',
  },
  {
    pattern: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/,
    title: 'OpenAI project key exposure',
  },
  {
    pattern: /\bxox[bps]-[A-Za-z0-9-]{20,}\b/,
    title: 'Slack token exposure',
  },
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    title: 'AWS access key exposure',
  },
  {
    pattern: /\bgh[op]_[A-Za-z0-9]{20,}\b/,
    title: 'GitHub token exposure',
  },
  {
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
    title: 'GitHub fine-grained token exposure',
  },
];

/** CODE-013 restricted sk-* fallback */
const OPENAI_SK_FALLBACK_PATTERN = /\bsk-[A-Za-z0-9_-]{20,}\b/;

const CREDENTIAL_NAME_TOKENS = new Set([
  'api',
  'key',
  'token',
  'secret',
  'password',
  'credential',
]);

const CREDENTIAL_COMPOUND_NAMES = new Set([
  'apikey',
  'apitoken',
  'accesskey',
  'accesstoken',
  'secretkey',
  'secrettoken',
]);

const CREDENTIAL_EQUALS_PATTERN =
  /\b([A-Za-z0-9_-]+)\b\s*=\s*["'`]?([A-Za-z0-9._~+/=\-]{20,})/i;

const CREDENTIAL_KEY_VALUE_PATTERN =
  /^\s*["'`]?([A-Za-z0-9_-]+)["'`]?\s*:\s*["'`]?([A-Za-z0-9._~+/=\-]{20,})/i;

const AUTHORIZATION_BEARER_PATTERN =
  /\bAuthorization\b\s*:\s*Bearer\s+([A-Za-z0-9._~+/=\-]{20,})/i;

const X_API_KEY_PATTERN =
  /\bx-api-key\b\s*:\s*([A-Za-z0-9._~+/=\-]{20,})/i;

const CREDENTIAL_MIN_LENGTH = 20;
const CREDENTIAL_MIN_ENTROPY = 4.5;

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
          source,
        });

        // CODE-002: shell execution — always CRITICAL, no code block reduction
        if (!SHELL_EXEC_FALSE_POSITIVES.some((p) => p.test(line))) {
          checkPatterns(results, line, SHELL_EXEC_PATTERNS, {
            id: 'CODE-002',
            severity: 'CRITICAL',
            title: 'Shell/subprocess execution',
            loc,
            lineNum,
            source,
          });
        }

        // CODE-003: destructive file operations — code block reduction
        checkPatterns(results, line, DESTRUCTIVE_PATTERNS, {
          id: 'CODE-003',
          severity: 'CRITICAL',
          title: 'Destructive file operation',
          loc,
          lineNum,
          source,
          codeBlockCtx: cbCtx,
        });

        // CODE-004: hardcoded external URLs — code block reduction
        checkPatterns(results, line, NETWORK_PATTERNS, {
          id: 'CODE-004',
          severity: 'HIGH',
          title: 'Hardcoded external URL/network request',
          loc,
          lineNum,
          source,
          codeBlockCtx: cbCtx,
        });

        // CODE-005: file write outside expected dir — no code block reduction
        checkPatterns(results, line, FILE_WRITE_PATTERNS, {
          id: 'CODE-005',
          severity: 'HIGH',
          title: 'File write outside expected directory',
          loc,
          lineNum,
          source,
        });

        // CODE-006: env var access — code block reduction
        checkPatterns(results, line, ENV_ACCESS_PATTERNS, {
          id: 'CODE-006',
          severity: 'MEDIUM',
          title: 'Environment variable access',
          loc,
          lineNum,
          source,
          codeBlockCtx: cbCtx,
        });

        // CODE-013: API key/credential leakage — no code block reduction
        const credentialLeak = detectCredentialLeak(line);
        if (credentialLeak) {
          results.push({
            id: 'CODE-013',
            category: 'CODE',
            severity: credentialLeak.severity,
            title: credentialLeak.title,
            message: `At ${loc}: ${line.trim().slice(0, 120)}`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
            source,
          });
        }

        // CODE-010: dynamic code generation — no code block reduction
        checkPatterns(results, line, DYNAMIC_CODE_PATTERNS, {
          id: 'CODE-010',
          severity: 'HIGH',
          title: 'Dynamic code generation pattern',
          loc,
          lineNum,
          source,
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
              source,
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
  source: string;
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
        source: opts.source,
        reducedFrom,
      });
      return; // one match per line per rule
    }
  }
}

interface CredentialLeakMatch {
  severity: Severity;
  title: string;
}

function detectCredentialLeak(line: string): CredentialLeakMatch | null {
  for (const provider of PROVIDER_CREDENTIAL_PATTERNS) {
    if (provider.pattern.test(line)) {
      return {
        severity: 'CRITICAL',
        title: provider.title,
      };
    }
  }

  if (
    OPENAI_SK_FALLBACK_PATTERN.test(line) &&
    isCredentialAssignmentContext(line)
  ) {
    return {
      severity: 'CRITICAL',
      title: 'OpenAI-style API key exposure',
    };
  }

  const assignmentMatch = line.match(CREDENTIAL_EQUALS_PATTERN);
  if (
    assignmentMatch?.[1] &&
    assignmentMatch[2] &&
    hasCredentialNameToken(assignmentMatch[1]) &&
    isHighEntropyCredential(assignmentMatch[2])
  ) {
    return {
      severity: 'HIGH',
      title: 'High-entropy credential assignment',
    };
  }

  const keyValueMatch = line.match(CREDENTIAL_KEY_VALUE_PATTERN);
  if (
    keyValueMatch?.[1] &&
    keyValueMatch[2] &&
    hasCredentialNameToken(keyValueMatch[1]) &&
    isHighEntropyCredential(keyValueMatch[2])
  ) {
    return {
      severity: 'HIGH',
      title: 'High-entropy credential assignment',
    };
  }

  const bearerMatch = line.match(AUTHORIZATION_BEARER_PATTERN);
  if (bearerMatch?.[1] && isHighEntropyCredential(bearerMatch[1])) {
    return {
      severity: 'HIGH',
      title: 'Authorization bearer credential exposure',
    };
  }

  const xApiKeyMatch = line.match(X_API_KEY_PATTERN);
  if (xApiKeyMatch?.[1] && isHighEntropyCredential(xApiKeyMatch[1])) {
    return {
      severity: 'HIGH',
      title: 'X-API-Key credential exposure',
    };
  }

  return null;
}

function isCredentialAssignmentContext(line: string): boolean {
  if (/\bAuthorization\b\s*:\s*Bearer\s+sk-/i.test(line)) {
    return true;
  }

  if (/\bx-api-key\b\s*:\s*sk-/i.test(line)) {
    return true;
  }

  const equalsMatch = line.match(CREDENTIAL_EQUALS_PATTERN);
  if (equalsMatch?.[1] && equalsMatch[2]) {
    return hasCredentialNameToken(equalsMatch[1]) && equalsMatch[2].startsWith('sk-');
  }

  const keyValueMatch = line.match(CREDENTIAL_KEY_VALUE_PATTERN);
  if (keyValueMatch?.[1] && keyValueMatch[2]) {
    return hasCredentialNameToken(keyValueMatch[1]) && keyValueMatch[2].startsWith('sk-');
  }

  return false;
}

function hasCredentialNameToken(name: string): boolean {
  const normalized = name
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/([A-Za-z])([0-9])/g, '$1_$2')
    .replace(/([0-9])([A-Za-z])/g, '$1_$2')
    .toLowerCase();

  const tokens = normalized
    .split(/[_-]+/)
    .map((token) => token.trim())
    .filter(Boolean);

  if (tokens.some((token) => CREDENTIAL_NAME_TOKENS.has(token))) {
    return true;
  }

  return tokens.length === 1 && CREDENTIAL_COMPOUND_NAMES.has(tokens[0]);
}

function isHighEntropyCredential(value: string): boolean {
  if (value.length < CREDENTIAL_MIN_LENGTH) {
    return false;
  }
  return shannonEntropy(value) > CREDENTIAL_MIN_ENTROPY;
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
        source,
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
        source,
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
        source,
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
      source,
    });
  }
}
