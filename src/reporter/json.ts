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

import type { ScanReport, SkillCheckerConfig, HookAction } from '../types.js';
import { getHookAction, DEFAULT_CONFIG } from '../types.js';
import { worstSeverity } from '../scanner.js';

/**
 * Format a scan report as JSON string.
 */
export function formatJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Generate a hook response JSON for PreToolUse hooks.
 */
export interface HookResponse {
  permissionDecision: 'deny' | 'ask' | 'allow';
  reason?: string;
  additionalContext?: string;
}

export function generateHookResponse(
  report: ScanReport,
  config: SkillCheckerConfig = DEFAULT_CONFIG
): HookResponse {
  const worst = worstSeverity(report.results);

  // Safety floor: suppressed CRITICAL/HIGH findings still require at least "ask"
  const suppressedWorst = report.suppressedResults
    ? worstSeverity(report.suppressedResults)
    : null;
  const hasSuppressedCriticalOrHigh =
    suppressedWorst === 'CRITICAL' || suppressedWorst === 'HIGH';

  if (!worst && !hasSuppressedCriticalOrHigh) {
    return { permissionDecision: 'allow' };
  }

  let action: HookAction = worst
    ? getHookAction(config.policy, worst)
    : 'report';

  // Floor: suppressed CRITICAL/HIGH → at least ask
  if (hasSuppressedCriticalOrHigh && (action === 'report' || !worst)) {
    action = 'ask';
  }

  switch (action) {
    case 'deny':
      return {
        permissionDecision: 'deny',
        reason: buildDenySummary(report),
      };
    case 'ask':
      return {
        permissionDecision: 'ask',
        reason: buildAskSummary(report),
      };
    case 'report':
      return {
        permissionDecision: 'allow',
        additionalContext: buildReportSummary(report),
      };
  }
}

function buildDenySummary(report: ScanReport): string {
  const lines = [
    `Skill Security Check FAILED (Grade: ${report.grade}, Score: ${report.score}/100)`,
  ];
  const criticals = report.results.filter((r) => r.severity === 'CRITICAL');
  if (criticals.length > 0) {
    lines.push(`Critical issues (${criticals.length}):`);
    for (const c of criticals.slice(0, 5)) {
      lines.push(`  - [${c.id}] ${c.title}: ${c.message}`);
    }
  }
  return lines.join('\n');
}

function buildAskSummary(report: ScanReport): string {
  const lines = [
    `Skill Security Check: Grade ${report.grade} (${report.score}/100)`,
    `Found: ${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium issues.`,
    'Review the findings before allowing installation.',
  ];
  return lines.join('\n');
}

function buildReportSummary(report: ScanReport): string {
  const lines = [
    `[Skill Checker] Grade: ${report.grade} (${report.score}/100)`,
    `Issues: ${report.summary.total} (${report.summary.critical}C/${report.summary.high}H/${report.summary.medium}M/${report.summary.low}L)`,
  ];
  if (report.results.length > 0) {
    lines.push('Top findings:');
    for (const r of report.results.slice(0, 3)) {
      lines.push(`  [${r.id}] ${r.severity}: ${r.title}`);
    }
  }
  return lines.join('\n');
}
