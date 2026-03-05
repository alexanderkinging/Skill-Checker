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

/**
 * Calculate Shannon entropy of a string (bits per character).
 * Higher entropy suggests encoded/obfuscated content.
 * Typical English text: ~3.5-4.0, random/encoded: >4.5
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Check if a string looks like base64 encoded content.
 */
export function isBase64Like(str: string): boolean {
  // Must be at least 50 chars and match base64 pattern
  if (str.length < 50) return false;
  return /^[A-Za-z0-9+/=]{50,}$/.test(str.trim());
}

/**
 * Check if a string looks like hex encoded content.
 */
export function isHexEncoded(str: string): boolean {
  if (str.length < 50) return false;
  return /^(0x)?[0-9a-fA-F]{50,}$/.test(str.trim());
}

/**
 * Try to decode base64 and check if result contains suspicious content.
 */
export function tryDecodeBase64(str: string): string | null {
  try {
    const decoded = Buffer.from(str.trim(), 'base64').toString('utf-8');
    // Check if decoded result is mostly printable
    const printable = decoded.replace(/[^\x20-\x7E\n\r\t]/g, '');
    if (printable.length / decoded.length > 0.8) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}
