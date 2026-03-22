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

import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Command } from 'commander';
import { scanSkillDirectory } from './scanner.js';
import { formatTerminalReport } from './reporter/terminal.js';
import { formatJsonReport, generateHookResponse } from './reporter/json.js';
import { loadConfig } from './config.js';
import type { PolicyLevel } from './types.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

const program = new Command();

program
  .name('skill-checker')
  .description(
    'Security checker for Claude Code skills - detect injection, malicious code, and supply chain risks'
  )
  .version(pkg.version);

const VALID_POLICIES = ['strict', 'balanced', 'permissive'] as const;

program
  .command('scan')
  .description('Scan a skill directory for security issues')
  .argument('<path>', 'Path to the skill directory')
  .option('-f, --format <format>', 'Output format: terminal, json, hook', 'terminal')
  .option('-p, --policy <policy>', 'Policy: strict, balanced, permissive')
  .option('-c, --config <path>', 'Path to config file')
  .option('--no-ignore', 'Disable inline suppression comments')
  .action(
    (
      path: string,
      opts: { format: string; policy?: string; config?: string; ignore: boolean }
    ) => {
      // Validate policy before anything else
      if (opts.policy && !VALID_POLICIES.includes(opts.policy as PolicyLevel)) {
        console.error(`Error: invalid policy "${opts.policy}". Valid values: ${VALID_POLICIES.join(', ')}`);
        process.exit(1);
      }
      // Load config
      const config = loadConfig(path, opts.config);

      // Warn if target directory has no SKILL.md
      if (!existsSync(join(path, 'SKILL.md'))) {
        console.error(
          'Warning: No SKILL.md found in the specified directory. ' +
          'This tool is designed to scan skill directories. ' +
          'Results may contain noise. See: skill-checker scan --help'
        );
      }

      // Override policy from CLI
      if (opts.policy) {
        config.policy = opts.policy as PolicyLevel;
      }

      // --no-ignore disables inline suppression
      if (!opts.ignore) {
        config.noIgnoreInline = true;
      }

      // Run scan
      const report = scanSkillDirectory(path, config);

      // Output
      switch (opts.format) {
        case 'json':
          console.log(formatJsonReport(report));
          break;
        case 'hook': {
          const hookResp = generateHookResponse(report, config);
          console.log(JSON.stringify(hookResp));
          break;
        }
        case 'terminal':
        default:
          console.log(formatTerminalReport(report));
          break;
      }

      // Exit code: non-zero if critical issues found
      if (report.summary.critical > 0) {
        process.exit(1);
      }
    }
  );

program.parse();
