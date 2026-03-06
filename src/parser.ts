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

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, extname, basename, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { ParsedSkill, SkillFrontmatter, SkillFile } from './types.js';

/** Binary file extensions that we skip reading */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.svg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.zip', '.gz', '.tar', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.mp3', '.mp4', '.wav', '.avi', '.mov',
  '.wasm', '.pyc', '.class',
]);

/**
 * Parse a skill directory, reading SKILL.md and enumerating files.
 */
export function parseSkill(dirPath: string): ParsedSkill {
  const absDir = resolve(dirPath);

  // Find SKILL.md
  const skillMdPath = join(absDir, 'SKILL.md');
  const hasSkillMd = existsSync(skillMdPath);

  const raw = hasSkillMd ? readFileSync(skillMdPath, 'utf-8') : '';

  // Parse frontmatter
  const { frontmatter, frontmatterValid, body, bodyStartLine } =
    parseFrontmatter(raw);

  // Enumerate directory files
  const files = enumerateFiles(absDir);

  return {
    dirPath: absDir,
    raw,
    frontmatter,
    frontmatterValid,
    body,
    bodyLines: body.split('\n'),
    bodyStartLine,
    files,
  };
}

/**
 * Parse a single SKILL.md content string (without directory enumeration).
 * Useful for testing or when you only have the file content.
 */
export function parseSkillContent(
  content: string,
  dirPath = '.'
): ParsedSkill {
  const { frontmatter, frontmatterValid, body, bodyStartLine } =
    parseFrontmatter(content);

  return {
    dirPath,
    raw: content,
    frontmatter,
    frontmatterValid,
    body,
    bodyLines: body.split('\n'),
    bodyStartLine,
    files: [],
  };
}

interface FrontmatterResult {
  frontmatter: SkillFrontmatter;
  frontmatterValid: boolean;
  body: string;
  bodyStartLine: number;
}

function parseFrontmatter(raw: string): FrontmatterResult {
  const fmRegex = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/;
  const match = raw.match(fmRegex);

  if (!match) {
    return {
      frontmatter: {},
      frontmatterValid: false,
      body: raw,
      bodyStartLine: 1,
    };
  }

  const yamlStr = match[1];
  const fmLineCount = match[0].split('\n').length;

  try {
    const parsed = parseYaml(yamlStr);
    return {
      frontmatter: (typeof parsed === 'object' && parsed !== null
        ? parsed
        : {}) as SkillFrontmatter,
      frontmatterValid: true,
      body: raw.slice(match[0].length),
      bodyStartLine: fmLineCount,
    };
  } catch {
    return {
      frontmatter: {},
      frontmatterValid: false,
      body: raw.slice(match[0].length),
      bodyStartLine: fmLineCount,
    };
  }
}

function enumerateFiles(dirPath: string, maxDepth = 5): SkillFile[] {
  const files: SkillFile[] = [];

  if (!existsSync(dirPath)) return files;

  function walk(currentDir: string, depth: number): void {
    if (depth > maxDepth) return;

    let entries;
    try {
      entries = readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        // Skip hidden dirs and node_modules
        if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
        walk(fullPath, depth + 1);
        continue;
      }

      const ext = extname(entry.name).toLowerCase();
      let stats;
      try {
        stats = statSync(fullPath);
      } catch {
        continue;
      }
      const isBinary = BINARY_EXTENSIONS.has(ext);
      const relativePath = fullPath.slice(dirPath.length + 1);

      let content: string | undefined;
      if (!isBinary && stats.size < 1_000_000) {
        try {
          content = readFileSync(fullPath, 'utf-8');
        } catch {
          // skip unreadable files
        }
      }

      files.push({
        path: relativePath,
        name: basename(entry.name, ext),
        extension: ext,
        sizeBytes: stats.size,
        isBinary,
        content,
      });
    }
  }

  walk(dirPath, 0);
  return files;
}
