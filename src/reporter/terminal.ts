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

import chalk from 'chalk';
import type { ScanReport, Severity, Grade } from '../types.js';

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow,
  LOW: chalk.gray,
};

const GRADE_COLORS: Record<Grade, (s: string) => string> = {
  A: chalk.green.bold,
  B: chalk.cyan.bold,
  C: chalk.yellow.bold,
  D: chalk.red.bold,
  F: chalk.bgRed.white.bold,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  CRITICAL: 'X',
  HIGH: '!',
  MEDIUM: '~',
  LOW: '-',
};

export function formatTerminalReport(report: ScanReport): string {
  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(
    chalk.bold('Skill Security Report') +
      chalk.gray(` - ${report.skillName}`)
  );
  lines.push(chalk.gray(`Path: ${report.skillPath}`));
  lines.push(chalk.gray(`Time: ${report.timestamp}`));
  lines.push('');

  // Score & Grade
  const gradeStr = GRADE_COLORS[report.grade](`  ${report.grade}  `);
  const scoreStr =
    report.score >= 75
      ? chalk.green(`${report.score}/100`)
      : report.score >= 40
        ? chalk.yellow(`${report.score}/100`)
        : chalk.red(`${report.score}/100`);

  lines.push(`Grade: ${gradeStr}  Score: ${scoreStr}`);
  lines.push('');

  // Summary bar
  const parts: string[] = [];
  if (report.summary.critical > 0)
    parts.push(chalk.bgRed.white(` ${report.summary.critical} CRITICAL `));
  if (report.summary.high > 0)
    parts.push(chalk.red(` ${report.summary.high} HIGH `));
  if (report.summary.medium > 0)
    parts.push(chalk.yellow(` ${report.summary.medium} MEDIUM `));
  if (report.summary.low > 0)
    parts.push(chalk.gray(` ${report.summary.low} LOW `));

  if (parts.length > 0) {
    lines.push(`Findings: ${parts.join(' ')}`);
  } else {
    lines.push(chalk.green('No issues found.'));
  }
  lines.push('');

  // Findings detail
  if (report.results.length > 0) {
    lines.push(chalk.bold.underline('Findings:'));
    lines.push('');

    // Group by category
    const grouped = new Map<string, typeof report.results>();
    for (const r of report.results) {
      const group = grouped.get(r.category) ?? [];
      group.push(r);
      grouped.set(r.category, group);
    }

    for (const [category, findings] of grouped) {
      lines.push(chalk.bold(`[${category}]`));

      // Sort by severity
      const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      findings.sort(
        (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)
      );

      for (const f of findings) {
        const icon = SEVERITY_ICONS[f.severity];
        const sevLabel = SEVERITY_COLORS[f.severity](
          ` ${f.severity} `
        );
        const idStr = chalk.gray(f.id);
        lines.push(`  [${icon}] ${sevLabel} ${idStr} ${f.title}`);
        lines.push(`      ${chalk.gray(f.message)}`);
        if (f.snippet) {
          lines.push(`      ${chalk.dim(f.snippet)}`);
        }
      }
      lines.push('');
    }
  }

  // Recommendation
  lines.push(chalk.bold('Recommendation:'));
  switch (report.grade) {
    case 'A':
      lines.push(chalk.green('  Safe to install.'));
      break;
    case 'B':
      lines.push(chalk.cyan('  Minor issues found. Generally safe.'));
      break;
    case 'C':
      lines.push(
        chalk.yellow('  Review recommended before installation.')
      );
      break;
    case 'D':
      lines.push(
        chalk.red('  Significant risks detected. Install with caution.')
      );
      break;
    case 'F':
      lines.push(
        chalk.bgRed.white('  DO NOT INSTALL. Critical security issues found.')
      );
      break;
  }
  lines.push('');

  return lines.join('\n');
}
