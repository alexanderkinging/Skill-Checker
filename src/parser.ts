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

import { readFileSync, readdirSync, lstatSync, existsSync, openSync, readSync, closeSync } from 'node:fs';
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
  const warnings: string[] = [];
  const files = enumerateFiles(absDir, warnings);

  return {
    dirPath: absDir,
    raw,
    frontmatter,
    frontmatterValid,
    body,
    bodyLines: body.split('\n'),
    bodyStartLine,
    files,
    warnings,
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
    warnings: [],
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

/** Directories always skipped entirely (not security-relevant VCS internals) */
const SKIP_DIRS = new Set(['.git']);

/** Directories skipped with a warning (potentially hiding payloads) */
const WARN_SKIP_DIRS = new Set(['node_modules']);

/** Max scan depth — deep enough for real skills, bounded for safety */
const MAX_DEPTH = 15;

/** Max file size for full text read (5 MB) */
const FULL_READ_LIMIT = 5_000_000;

/** Partial read size for large text files — scan first 512 KB for key patterns */
const PARTIAL_READ_LIMIT = 512 * 1024;

function enumerateFiles(dirPath: string, warnings: string[]): SkillFile[] {
  const files: SkillFile[] = [];

  if (!existsSync(dirPath)) return files;

  function walk(currentDir: string, depth: number): void {
    if (depth > MAX_DEPTH) {
      const rel = currentDir.slice(dirPath.length + 1) || currentDir;
      warnings.push(`Depth limit (${MAX_DEPTH}) exceeded at: ${rel}. Contents not scanned.`);
      return;
    }

    let entries;
    try {
      entries = readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      const relativePath = fullPath.slice(dirPath.length + 1);

      // Use lstat to detect symlinks without following them
      let lstats;
      try {
        lstats = lstatSync(fullPath);
      } catch {
        continue;
      }

      // Skip symlinks entirely — prevent traversal outside skill directory
      if (lstats.isSymbolicLink()) {
        warnings.push(`Skipped symlink: ${relativePath}`);
        continue;
      }

      if (lstats.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (WARN_SKIP_DIRS.has(entry.name)) {
          warnings.push(`Skipped directory: ${relativePath}. May contain unscanned files.`);
          continue;
        }
        // Hidden directories (except .git) ARE scanned — payloads can hide there
        walk(fullPath, depth + 1);
        continue;
      }

      // Skip special files (FIFO, socket, device, etc.) — only process regular files
      if (!lstats.isFile()) {
        warnings.push(`Skipped special file: ${relativePath}`);
        continue;
      }

      const ext = extname(entry.name).toLowerCase();
      const isBinary = BINARY_EXTENSIONS.has(ext);

      let content: string | undefined;
      if (!isBinary) {
        if (lstats.size <= FULL_READ_LIMIT) {
          try {
            content = readFileSync(fullPath, 'utf-8');
          } catch {
            // skip unreadable files
          }
        } else {
          // Large text file: window scan (head + tail) for pattern detection
          let fd: number | undefined;
          try {
            fd = openSync(fullPath, 'r');

            const headBuf = Buffer.alloc(PARTIAL_READ_LIMIT);
            const headBytesRead = readSync(fd, headBuf, 0, PARTIAL_READ_LIMIT, 0);
            const headContent = headBuf.slice(0, headBytesRead).toString('utf-8');

            const tailOffset = Math.max(0, lstats.size - PARTIAL_READ_LIMIT);
            const tailBuf = Buffer.alloc(PARTIAL_READ_LIMIT);
            const tailBytesRead = readSync(fd, tailBuf, 0, PARTIAL_READ_LIMIT, tailOffset);
            const tailContent = tailBuf.slice(0, tailBytesRead).toString('utf-8');

            content = tailOffset > 0
              ? `${headContent}\n/* ... window gap ... */\n${tailContent}`
              : headContent;

            warnings.push(
              `Large file window-scanned (head+tail ${PARTIAL_READ_LIMIT} bytes each): ${relativePath} (${lstats.size} bytes total)`
            );
          } catch {
            warnings.push(`Large file could not be read: ${relativePath} (${lstats.size} bytes)`);
          } finally {
            if (fd !== undefined) {
              try { closeSync(fd); } catch { /* fd already closed or invalid */ }
            }
          }
        }
      }

      files.push({
        path: relativePath,
        name: basename(entry.name, ext),
        extension: ext,
        sizeBytes: lstats.size,
        isBinary,
        content,
      });
    }
  }

  walk(dirPath, 0);
  return files;
}
