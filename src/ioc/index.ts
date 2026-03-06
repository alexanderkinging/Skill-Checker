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
import { join } from 'node:path';
import { homedir } from 'node:os';
import { DEFAULT_IOC, type IOCDatabase } from './indicators.js';

let cachedIOC: IOCDatabase | null = null;

/**
 * Load IOC database: embedded seed data + optional external override file.
 * External file is merged (appended) into the seed data, not replacing it.
 *
 * Search paths for override file:
 *   1. ~/.config/skill-checker/ioc-override.json
 */
export function loadIOC(): IOCDatabase {
  if (cachedIOC) return cachedIOC;

  const ioc = structuredClone(DEFAULT_IOC);

  const overridePath = join(
    homedir(),
    '.config',
    'skill-checker',
    'ioc-override.json'
  );

  if (existsSync(overridePath)) {
    try {
      const raw = readFileSync(overridePath, 'utf-8');
      const ext = JSON.parse(raw) as Partial<IOCDatabase>;
      mergeIOC(ioc, ext);
    } catch {
      // Invalid override file — silently use seed data only
    }
  }

  cachedIOC = ioc;
  return ioc;
}

/**
 * Reset the cached IOC database (useful for testing).
 */
export function resetIOCCache(): void {
  cachedIOC = null;
}

/**
 * Merge external IOC data into the base database.
 * Arrays are concatenated (deduplicated), objects are merged.
 */
function mergeIOC(base: IOCDatabase, ext: Partial<IOCDatabase>): void {
  if (ext.c2_ips) {
    base.c2_ips = dedupe([...base.c2_ips, ...ext.c2_ips]);
  }
  if (ext.malicious_hashes) {
    Object.assign(base.malicious_hashes, ext.malicious_hashes);
  }
  if (ext.malicious_domains) {
    base.malicious_domains = dedupe([
      ...base.malicious_domains,
      ...ext.malicious_domains,
    ]);
  }
  if (ext.typosquat) {
    if (ext.typosquat.known_patterns) {
      base.typosquat.known_patterns = dedupe([
        ...base.typosquat.known_patterns,
        ...ext.typosquat.known_patterns,
      ]);
    }
    if (ext.typosquat.protected_names) {
      base.typosquat.protected_names = dedupe([
        ...base.typosquat.protected_names,
        ...ext.typosquat.protected_names,
      ]);
    }
  }
  if (ext.malicious_publishers) {
    base.malicious_publishers = dedupe([
      ...base.malicious_publishers,
      ...ext.malicious_publishers,
    ]);
  }
  if (ext.version) base.version = ext.version;
  if (ext.updated) base.updated = ext.updated;
}

function dedupe(arr: string[]): string[] {
  return [...new Set(arr)];
}
