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

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { levenshtein } from '../utils/levenshtein.js';
import type { IOCDatabase } from './indicators.js';
import type { ParsedSkill } from '../types.js';

/** SHA-256 of empty content — must never be treated as malicious */
const EMPTY_FILE_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** Max file size for hash computation (10 MB) */
const MAX_HASH_FILE_SIZE = 10 * 1024 * 1024;

/** IPv4 pattern — matches standalone IPs in text */
const IPV4_PATTERN = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

/** Private/reserved IP ranges to exclude */
function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => p < 0 || p > 255)) return true;
  // 127.x.x.x (loopback)
  if (parts[0] === 127) return true;
  // 10.x.x.x
  if (parts[0] === 10) return true;
  // 172.16-31.x.x
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.x.x
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 0.0.0.0
  if (parts.every((p) => p === 0)) return true;
  // 169.254.x.x (link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

/**
 * SUPPLY-008: Check file hashes against known malicious hashes.
 */
export function matchMaliciousHashes(
  skill: ParsedSkill,
  ioc: IOCDatabase
): { file: string; hash: string; description: string }[] {
  const matches: { file: string; hash: string; description: string }[] = [];
  const hashKeys = Object.keys(ioc.malicious_hashes);
  if (hashKeys.length === 0) return matches;

  for (const file of skill.files) {
    const filePath = join(skill.dirPath, file.path);
    try {
      const stat = statSync(filePath);
      if (stat.size === 0 || stat.size > MAX_HASH_FILE_SIZE) continue;
      const content = readFileSync(filePath);
      const hash = createHash('sha256').update(content).digest('hex');
      if (hash === EMPTY_FILE_HASH) continue;
      if (ioc.malicious_hashes[hash]) {
        matches.push({
          file: file.path,
          hash,
          description: ioc.malicious_hashes[hash],
        });
      }
    } catch {
      // Skip unreadable files
    }
  }

  return matches;
}

/**
 * SUPPLY-009: Extract IPs from skill content and match against C2 list.
 */
export function matchC2IPs(
  skill: ParsedSkill,
  ioc: IOCDatabase
): { ip: string; line: number; source: string; snippet: string }[] {
  const matches: { ip: string; line: number; source: string; snippet: string }[] = [];
  if (ioc.c2_ips.length === 0) return matches;

  const c2Set = new Set(ioc.c2_ips);
  const allText = getAllText(skill);

  for (const { line, lineNum, source } of allText) {
    let m: RegExpExecArray | null;
    const re = new RegExp(IPV4_PATTERN.source, 'g');
    while ((m = re.exec(line)) !== null) {
      const ip = m[1];
      if (!isPrivateIP(ip) && c2Set.has(ip)) {
        matches.push({
          ip,
          line: lineNum,
          source,
          snippet: line.trim().slice(0, 120),
        });
      }
    }
  }

  return matches;
}

/**
 * SUPPLY-010: Check skill name for typosquatting.
 * Two-layer strategy:
 *   1. Exact match against known_patterns → CRITICAL
 *   2. Levenshtein distance ≤ 2 against protected_names → HIGH
 */
export function matchTyposquat(
  skillName: string,
  ioc: IOCDatabase
): { type: 'known' | 'similar'; target: string; distance?: number } | null {
  if (!skillName) return null;
  const name = skillName.toLowerCase().trim();

  // Layer 1: exact match against known typosquat patterns
  for (const pattern of ioc.typosquat.known_patterns) {
    if (name === pattern.toLowerCase()) {
      return { type: 'known', target: pattern };
    }
  }

  // Layer 2: edit distance against protected names
  for (const protected_name of ioc.typosquat.protected_names) {
    const pn = protected_name.toLowerCase();
    if (name === pn) continue; // exact match = legitimate, skip
    const dist = levenshtein(name, pn);
    if (dist > 0 && dist <= 2) {
      return { type: 'similar', target: protected_name, distance: dist };
    }
  }

  return null;
}

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
