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
import { findZeroWidthChars, findRTLOverrides, findHomoglyphs } from '../utils/unicode.js';
import { isBase64Like, tryDecodeBase64 } from '../utils/entropy.js';

/** Patterns that attempt to override system prompts */
const SYSTEM_OVERRIDE_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?prior\s+instructions/i,
  /disregard\s+(all\s+)?previous/i,
  /forget\s+(all\s+)?previous/i,
  /you\s+are\s+now\s+a\s+different/i,
  /new\s+system\s+prompt/i,
  /override\s+system\s+prompt/i,
  /your\s+new\s+instructions?\s+(are|is)/i,
  /from\s+now\s+on,?\s+you\s+(will|must|should)/i,
  /act\s+as\s+(if|though)\s+your\s+instructions/i,
];

/** Patterns that manipulate tool output */
const TOOL_MANIPULATION_PATTERNS = [
  /\bresult\s*[:=]\s*["']?success/i,
  /tool_result/i,
  /<tool_result>/i,
  /\breturn\s+["']?(true|success|approved)/i,
  /permissionDecision\s*[:=]/i,
];

/** Tag injection patterns */
const TAG_INJECTION_PATTERNS = [
  /<system>/i,
  /<\/system>/i,
  /<\|im_start\|>/i,
  /<\|im_end\|>/i,
  /<\|endoftext\|>/i,
  /<human>/i,
  /<assistant>/i,
  /<\|system\|>/i,
  /<\|user\|>/i,
  /<\|assistant\|>/i,
];

/** Delimiter confusion patterns */
const DELIMITER_PATTERNS = [
  /={5,}/,
  /-{5,}\s*(system|instruction|prompt)/i,
  /#{3,}\s*(system|instruction|prompt)/i,
  /\[SYSTEM\]/i,
  /\[INST\]/i,
  /\[\/INST\]/i,
];

/** Dangerous role targets for identity hijacking — privilege, jailbreak, or malicious roles */
const DANGEROUS_ROLE_PATTERN =
  '(?:(?:an?\\s+)?(?:hacker|attacker|cracker|root|admin(?:istrator)?|superuser|unrestricted|jailbroken|evil|malicious|unfiltered|uncensored)\\b|DAN\\b|(?:a\\s+)?different\\b)';

/** INJ-010: Identity hijacking patterns (CRITICAL) */
const IDENTITY_HIJACKING_PATTERNS = [
  new RegExp(`\\byou\\s+are\\s+now\\s+${DANGEROUS_ROLE_PATTERN}`, 'i'),
  new RegExp(`\\bact\\s+as\\s+${DANGEROUS_ROLE_PATTERN}`, 'i'),
  new RegExp(`\\bpretend\\s+(?:you\\s+are|to\\s+be)\\s+${DANGEROUS_ROLE_PATTERN}`, 'i'),
  new RegExp(`\\broleplay\\s+(?:as|like)\\s+${DANGEROUS_ROLE_PATTERN}`, 'i'),
  new RegExp(`\\bassume\\s+the\\s+role\\s+of\\s+${DANGEROUS_ROLE_PATTERN}`, 'i'),
  /\byou\s+are\s+no\s+longer\s+claude\b/i,
  /\bfrom\s+now\s+on,?\s+you\s+are\b/i,
];

/** INJ-010: Deception/secrecy patterns (CRITICAL) */
const DECEPTION_SECRECY_PATTERNS = [
  /\bdo\s+not\s+tell\s+(the\s+)?(user|human|person|operator)\b/i,
  /\bdo\s+not\s+(mention|reveal|disclose|expose)\s+(this|that|the|any|these)\b/i,
  /\bnever\s+(tell|mention|reveal|disclose)\s+(the\s+)?(user|human|person|operator)\b/i,
  /\bkeep\s+this\s+(secret|hidden|private|confidential)\b(?!\s+key)/i,
  /\bhide\s+this\s+(from|action|operation|instruction)\b/i,
  /\bwithout\s+(the\s+)?(user|human)('?s)?\s+(knowledge|knowing|awareness|consent)\b/i,
  /\bsilently\s+(execute|run|perform|install|download|delete|modify|send)\b/i,
];

/** INJ-010: Configuration tampering patterns (HIGH) */
const CONFIG_TAMPERING_PATTERNS = [
  /\b(modify|change|update|edit|alter|rewrite)\s+(your|my)\s+(memory|config|configuration|settings?|instructions?|behavior|personality)\b/i,
  /\bwrite\s+to\s+(CLAUDE\.md|\.claude|settings\.json|memory\.md)\b/i,
  /\b(append|prepend|add|insert)\s+.{0,30}\bto\s+(CLAUDE\.md|\.claude|memory\.md)\b/i,
  /\boverwrite\s+(your|the)\s+(system|core)\s+(prompt|instructions?|config)\b/i,
  /\bpersist\s+(this|these|the)\s+(instruction|change|modification|setting)s?\b/i,
];

/** INJ-010: Verification bypass patterns (HIGH) */
const VERIFICATION_BYPASS_PATTERNS = [
  /\btrust\s+(this|the|these|that|my)\s+(result|output|response|answer|value|data|input)s?\b/i,
  /\bno\s+need\s+to\s+(check|verify|validate|review|confirm|inspect)\b/i,
  /\bdo\s+not\s+(verify|validate|check|review|confirm|inspect)\s+(the|this|that|any|these)\b/i,
  /\b(assume|consider)\s+(it|this|that)\s+(is|to\s+be)\s+(correct|safe|valid|trusted|clean|secure|legitimate)\b/i,
  /\baccept\s+(this|the|these|that)\s+without\s+(checking|verifying|validating|questioning)\b/i,
  /\bblindly\s+(trust|accept|execute|run|follow|apply)\b/i,
];

export const injectionChecks: CheckModule = {
  name: 'Injection Detection',
  category: 'INJ',

  run(skill: ParsedSkill): CheckResult[] {
    const results: CheckResult[] = [];
    const fullText = skill.raw;

    // INJ-001: Zero-width Unicode characters
    const zeroWidth = findZeroWidthChars(fullText);
    if (zeroWidth.length > 0) {
      results.push({
        id: 'INJ-001',
        category: 'INJ',
        severity: 'CRITICAL',
        title: 'Zero-width Unicode characters detected',
        message: `Found ${zeroWidth.length} zero-width character(s): ${zeroWidth.slice(0, 5).map((z) => z.codePoint).join(', ')}. These can hide malicious content.`,
      });
    }

    // INJ-002: Homoglyph characters
    const homoglyphs = findHomoglyphs(fullText);
    if (homoglyphs.length > 0) {
      results.push({
        id: 'INJ-002',
        category: 'INJ',
        severity: 'HIGH',
        title: 'Homoglyph characters detected',
        message: `Found ${homoglyphs.length} character(s) that mimic Latin letters (e.g. Cyrillic/Greek). Could be used for spoofing.`,
        snippet: homoglyphs
          .slice(0, 5)
          .map((h) => `"${h.char}" looks like "${h.looksLike}"`)
          .join(', '),
      });
    }

    // INJ-003: RTL override characters
    const rtl = findRTLOverrides(fullText);
    if (rtl.length > 0) {
      results.push({
        id: 'INJ-003',
        category: 'INJ',
        severity: 'CRITICAL',
        title: 'RTL override characters detected',
        message: `Found ${rtl.length} RTL/bidirectional override character(s): ${rtl.slice(0, 5).map((r) => r.codePoint).join(', ')}. These can manipulate text display direction.`,
      });
    }

    // Check body lines for remaining patterns
    for (let i = 0; i < skill.bodyLines.length; i++) {
      const line = skill.bodyLines[i];
      const lineNum = skill.bodyStartLine + i;

      // INJ-004: System prompt override
      for (const pattern of SYSTEM_OVERRIDE_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'INJ-004',
            category: 'INJ',
            severity: 'CRITICAL',
            title: 'System prompt override attempt',
            message: `Line ${lineNum}: Attempts to override system instructions.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-005: Tool output manipulation
      for (const pattern of TOOL_MANIPULATION_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'INJ-005',
            category: 'INJ',
            severity: 'HIGH',
            title: 'Tool output manipulation',
            message: `Line ${lineNum}: Attempts to manipulate tool results.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-007: Tag injection
      for (const pattern of TAG_INJECTION_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'INJ-007',
            category: 'INJ',
            severity: 'CRITICAL',
            title: 'Tag injection detected',
            message: `Line ${lineNum}: Contains special model/system tags.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-009: Delimiter confusion
      for (const pattern of DELIMITER_PATTERNS) {
        if (pattern.test(line)) {
          results.push({
            id: 'INJ-009',
            category: 'INJ',
            severity: 'MEDIUM',
            title: 'Delimiter confusion pattern',
            message: `Line ${lineNum}: Uses patterns that could confuse model context boundaries.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-010: Two-line sliding window to catch cross-line splits
      const nextLine = i + 1 < skill.bodyLines.length ? skill.bodyLines[i + 1] : '';
      const crossLine = nextLine ? `${line} ${nextLine}` : line;

      // INJ-010: Social engineering — identity hijacking (CRITICAL)
      for (const pattern of IDENTITY_HIJACKING_PATTERNS) {
        if (pattern.test(crossLine)) {
          results.push({
            id: 'INJ-010',
            category: 'INJ',
            severity: 'CRITICAL',
            title: 'Social engineering: identity hijacking',
            message: `Line ${lineNum}: Attempts to hijack the model's identity.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-010: Social engineering — deception/secrecy (CRITICAL)
      for (const pattern of DECEPTION_SECRECY_PATTERNS) {
        if (pattern.test(crossLine)) {
          results.push({
            id: 'INJ-010',
            category: 'INJ',
            severity: 'CRITICAL',
            title: 'Social engineering: deception/secrecy',
            message: `Line ${lineNum}: Instructs the model to hide actions from the user.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-010: Social engineering — configuration tampering (HIGH)
      for (const pattern of CONFIG_TAMPERING_PATTERNS) {
        if (pattern.test(crossLine)) {
          results.push({
            id: 'INJ-010',
            category: 'INJ',
            severity: 'HIGH',
            title: 'Social engineering: configuration tampering',
            message: `Line ${lineNum}: Attempts to tamper with model configuration or memory.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }

      // INJ-010: Social engineering — verification bypass (HIGH)
      for (const pattern of VERIFICATION_BYPASS_PATTERNS) {
        if (pattern.test(crossLine)) {
          results.push({
            id: 'INJ-010',
            category: 'INJ',
            severity: 'HIGH',
            title: 'Social engineering: verification bypass',
            message: `Line ${lineNum}: Attempts to bypass verification or validation.`,
            line: lineNum,
            snippet: line.trim().slice(0, 120),
          });
          break;
        }
      }
    }

    // INJ-006: Hidden instructions in HTML/Markdown comments
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let commentMatch;
    while ((commentMatch = commentRegex.exec(fullText)) !== null) {
      const commentBody = commentMatch[1];
      if (hasInstructionLikeContent(commentBody)) {
        const lineNum = fullText.slice(0, commentMatch.index).split('\n').length;
        results.push({
          id: 'INJ-006',
          category: 'INJ',
          severity: 'HIGH',
          title: 'Hidden instructions in HTML comment',
          message: `Line ${lineNum}: HTML comment contains instruction-like content.`,
          line: lineNum,
          snippet: commentBody.trim().slice(0, 120),
        });
      }
    }

    // INJ-008: Encoded instructions (base64 in body)
    const base64Regex = /[A-Za-z0-9+/=]{60,}/g;
    let b64Match;
    while ((b64Match = base64Regex.exec(skill.body)) !== null) {
      const candidate = b64Match[0];
      if (isBase64Like(candidate)) {
        const decoded = tryDecodeBase64(candidate);
        if (decoded && hasInstructionLikeContent(decoded)) {
          const lineNum =
            skill.bodyStartLine +
            skill.body.slice(0, b64Match.index).split('\n').length -
            1;
          results.push({
            id: 'INJ-008',
            category: 'INJ',
            severity: 'CRITICAL',
            title: 'Encoded instructions detected',
            message: `Line ${lineNum}: Base64 string decodes to instruction-like content.`,
            line: lineNum,
            snippet: decoded.slice(0, 120),
          });
        }
      }
    }

    // Deduplicate by id+line
    return dedup(results);
  },
};

function hasInstructionLikeContent(text: string): boolean {
  const instructionPatterns = [
    /you\s+(must|should|will|are)/i,
    /ignore\s+previous/i,
    /execute\s+the\s+following/i,
    /run\s+this\s+command/i,
    /\bsudo\b/i,
    /\brm\s+-rf\b/i,
    /\bcurl\b.*\bsh\b/i,
    /\beval\b/i,
    /\bexec\b/i,
    /\bdo\s+not\s+tell\s+(the\s+)?(user|human)/i,
    /\bpretend\s+(you\s+are|to\s+be)/i,
    /\bsilently\s+(execute|run|install)/i,
  ];
  return instructionPatterns.some((p) => p.test(text));
}

function dedup(results: CheckResult[]): CheckResult[] {
  const seen = new Set<string>();
  return results.filter((r) => {
    const key = `${r.id}:${r.line ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
