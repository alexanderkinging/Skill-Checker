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
 * Hook installer - adds skill-gate.sh to Claude Code settings.
 *
 * Usage: npx tsx hook/install.ts
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const HOME = process.env.HOME ?? process.env.USERPROFILE ?? '';
const CLAUDE_SETTINGS_DIR = join(HOME, '.claude');
const CLAUDE_SETTINGS_PATH = join(CLAUDE_SETTINGS_DIR, 'settings.json');

interface ClaudeSettings {
  hooks?: {
    PreToolUse?: Array<{
      matcher: string;
      hook: string;
    }>;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export function installHook(hookScriptPath: string): void {
  // Read existing settings
  let settings: ClaudeSettings = {};
  if (existsSync(CLAUDE_SETTINGS_PATH)) {
    const raw = readFileSync(CLAUDE_SETTINGS_PATH, 'utf-8');
    settings = JSON.parse(raw);
  }

  // Ensure hooks structure exists
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  // Check if already installed
  const existing = settings.hooks.PreToolUse.find(
    (h) => h.hook.includes('skill-gate')
  );

  if (existing) {
    console.log('skill-gate hook is already installed.');
    console.log(`Current path: ${existing.hook}`);
    return;
  }

  // Add the hook
  settings.hooks.PreToolUse.push({
    matcher: 'Write|Edit',
    hook: hookScriptPath,
  });

  // Ensure directory exists
  if (!existsSync(CLAUDE_SETTINGS_DIR)) {
    mkdirSync(CLAUDE_SETTINGS_DIR, { recursive: true });
  }

  // Write settings
  writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2));
  console.log('skill-gate hook installed successfully!');
  console.log(`Hook script: ${hookScriptPath}`);
  console.log(`Settings file: ${CLAUDE_SETTINGS_PATH}`);
}

// Run if called directly
const isMainModule = process.argv[1]?.endsWith('install.ts') ||
  process.argv[1]?.endsWith('install.js');
if (isMainModule) {
  const scriptPath = join(import.meta.dirname ?? '.', 'skill-gate.sh');
  installHook(scriptPath);
}
