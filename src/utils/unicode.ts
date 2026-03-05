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
 * Zero-width Unicode characters that can hide content.
 */
export const ZERO_WIDTH_CHARS = [
  '\u200B', // ZERO WIDTH SPACE
  '\u200C', // ZERO WIDTH NON-JOINER
  '\u200D', // ZERO WIDTH JOINER
  '\u200E', // LEFT-TO-RIGHT MARK
  '\u200F', // RIGHT-TO-LEFT MARK
  '\uFEFF', // ZERO WIDTH NO-BREAK SPACE (BOM)
  '\u2060', // WORD JOINER
  '\u2061', // FUNCTION APPLICATION
  '\u2062', // INVISIBLE TIMES
  '\u2063', // INVISIBLE SEPARATOR
  '\u2064', // INVISIBLE PLUS
];

/**
 * RTL override characters that can manipulate display.
 */
export const RTL_OVERRIDE_CHARS = [
  '\u202A', // LEFT-TO-RIGHT EMBEDDING
  '\u202B', // RIGHT-TO-LEFT EMBEDDING
  '\u202C', // POP DIRECTIONAL FORMATTING
  '\u202D', // LEFT-TO-RIGHT OVERRIDE
  '\u202E', // RIGHT-TO-LEFT OVERRIDE
  '\u2066', // LEFT-TO-RIGHT ISOLATE
  '\u2067', // RIGHT-TO-LEFT ISOLATE
  '\u2068', // FIRST STRONG ISOLATE
  '\u2069', // POP DIRECTIONAL ISOLATE
];

/**
 * Homoglyph map: Cyrillic/Greek characters that look like Latin.
 */
const HOMOGLYPHS: Record<string, string> = {
  '\u0410': 'A', // Cyrillic А
  '\u0412': 'B', // Cyrillic В
  '\u0421': 'C', // Cyrillic С
  '\u0415': 'E', // Cyrillic Е
  '\u041D': 'H', // Cyrillic Н
  '\u041A': 'K', // Cyrillic К
  '\u041C': 'M', // Cyrillic М
  '\u041E': 'O', // Cyrillic О
  '\u0420': 'P', // Cyrillic Р
  '\u0422': 'T', // Cyrillic Т
  '\u0425': 'X', // Cyrillic Х
  '\u0430': 'a', // Cyrillic а
  '\u0435': 'e', // Cyrillic е
  '\u043E': 'o', // Cyrillic о
  '\u0440': 'p', // Cyrillic р
  '\u0441': 'c', // Cyrillic с
  '\u0443': 'y', // Cyrillic у
  '\u0445': 'x', // Cyrillic х
  '\u0391': 'A', // Greek Α
  '\u0392': 'B', // Greek Β
  '\u0395': 'E', // Greek Ε
  '\u0397': 'H', // Greek Η
  '\u0399': 'I', // Greek Ι
  '\u039A': 'K', // Greek Κ
  '\u039C': 'M', // Greek Μ
  '\u039D': 'N', // Greek Ν
  '\u039F': 'O', // Greek Ο
  '\u03A1': 'P', // Greek Ρ
  '\u03A4': 'T', // Greek Τ
  '\u03A7': 'X', // Greek Χ
  '\u03BF': 'o', // Greek ο
};

/**
 * Find zero-width characters in text, returning positions.
 */
export function findZeroWidthChars(
  text: string
): Array<{ char: string; codePoint: string; position: number }> {
  const found: Array<{ char: string; codePoint: string; position: number }> = [];
  for (let i = 0; i < text.length; i++) {
    if (ZERO_WIDTH_CHARS.includes(text[i])) {
      found.push({
        char: text[i],
        codePoint: 'U+' + text[i].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
        position: i,
      });
    }
  }
  return found;
}

/**
 * Find RTL override characters in text.
 */
export function findRTLOverrides(
  text: string
): Array<{ char: string; codePoint: string; position: number }> {
  const found: Array<{ char: string; codePoint: string; position: number }> = [];
  for (let i = 0; i < text.length; i++) {
    if (RTL_OVERRIDE_CHARS.includes(text[i])) {
      found.push({
        char: text[i],
        codePoint: 'U+' + text[i].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'),
        position: i,
      });
    }
  }
  return found;
}

/**
 * Find homoglyph characters (non-Latin chars posing as Latin).
 */
export function findHomoglyphs(
  text: string
): Array<{ char: string; looksLike: string; position: number }> {
  const found: Array<{ char: string; looksLike: string; position: number }> = [];
  for (let i = 0; i < text.length; i++) {
    const latin = HOMOGLYPHS[text[i]];
    if (latin) {
      found.push({ char: text[i], looksLike: latin, position: i });
    }
  }
  return found;
}
