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

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { SkillCheckerConfig, PolicyLevel, Severity } from './types.js';
import { DEFAULT_CONFIG } from './types.js';

const CONFIG_FILENAMES = [
  '.skillcheckerrc.yaml',
  '.skillcheckerrc.yml',
  '.skillcheckerrc',
];

/**
 * Load configuration.
 * If configPath is provided and points to a file, load it directly.
 * Otherwise, search up the directory tree from startDir.
 */
export function loadConfig(startDir?: string, configPath?: string): SkillCheckerConfig {
  // Direct file path provided via --config
  if (configPath) {
    const absPath = resolve(configPath);
    if (existsSync(absPath)) {
      return parseConfigFile(absPath);
    }
    // Config file specified but not found - return default
    return { ...DEFAULT_CONFIG };
  }

  const dir = startDir ? resolve(startDir) : process.cwd();

  // Search for config file in current dir and parents
  let current = dir;
  while (true) {
    for (const filename of CONFIG_FILENAMES) {
      const configPath = join(current, filename);
      if (existsSync(configPath)) {
        return parseConfigFile(configPath);
      }
    }

    const parent = join(current, '..');
    if (parent === current) break; // reached root
    current = parent;
  }

  // Also check home directory
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (home) {
    for (const filename of CONFIG_FILENAMES) {
      const configPath = join(home, filename);
      if (existsSync(configPath)) {
        return parseConfigFile(configPath);
      }
    }
  }

  return { ...DEFAULT_CONFIG };
}

function parseConfigFile(path: string): SkillCheckerConfig {
  try {
    const raw = readFileSync(path, 'utf-8');
    const parsed = parseYaml(raw);

    if (!parsed || typeof parsed !== 'object') {
      return { ...DEFAULT_CONFIG };
    }

    const config: SkillCheckerConfig = {
      policy: isValidPolicy(parsed.policy) ? parsed.policy : 'balanced',
      overrides: {},
      ignore: [],
    };

    // Parse overrides
    if (parsed.overrides && typeof parsed.overrides === 'object') {
      for (const [key, value] of Object.entries(parsed.overrides)) {
        const sev = normalizeSeverity(value as string);
        if (sev) {
          config.overrides[key] = sev;
        }
      }
    }

    // Parse ignore list
    if (Array.isArray(parsed.ignore)) {
      config.ignore = parsed.ignore.filter(
        (item: unknown) => typeof item === 'string'
      );
    }

    return config;
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function isValidPolicy(value: unknown): value is PolicyLevel {
  return (
    typeof value === 'string' &&
    ['strict', 'balanced', 'permissive'].includes(value)
  );
}

function normalizeSeverity(value: string): Severity | null {
  const upper = value?.toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(upper)) {
    return upper as Severity;
  }
  return null;
}
