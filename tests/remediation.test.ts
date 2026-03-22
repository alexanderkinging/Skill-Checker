import { describe, it, expect } from 'vitest';
import { getRemediation, getRemediationRuleIds } from '../src/remediation.js';
import { scanSkillContent } from '../src/scanner.js';
import { formatTerminalReport } from '../src/reporter/terminal.js';

/** All 57 known rule IDs */
const ALL_RULE_IDS = [
  // STRUCT
  'STRUCT-001', 'STRUCT-002', 'STRUCT-003', 'STRUCT-004',
  'STRUCT-005', 'STRUCT-006', 'STRUCT-007', 'STRUCT-008',
  // CONT
  'CONT-001', 'CONT-002', 'CONT-003', 'CONT-004',
  'CONT-005', 'CONT-006', 'CONT-007',
  // INJ
  'INJ-001', 'INJ-002', 'INJ-003', 'INJ-004', 'INJ-005',
  'INJ-006', 'INJ-007', 'INJ-008', 'INJ-009', 'INJ-010',
  // CODE
  'CODE-001', 'CODE-002', 'CODE-003', 'CODE-004', 'CODE-005',
  'CODE-006', 'CODE-007', 'CODE-008', 'CODE-009', 'CODE-010',
  'CODE-011', 'CODE-012', 'CODE-013', 'CODE-014', 'CODE-015',
  'CODE-016',
  // SUPPLY
  'SUPPLY-001', 'SUPPLY-002', 'SUPPLY-003', 'SUPPLY-004',
  'SUPPLY-005', 'SUPPLY-006', 'SUPPLY-007', 'SUPPLY-008',
  'SUPPLY-009', 'SUPPLY-010',
  // RES
  'RES-001', 'RES-002', 'RES-003', 'RES-004', 'RES-005', 'RES-006',
];

describe('Remediation', () => {
  it('all 57 rules have remediation entries', () => {
    for (const id of ALL_RULE_IDS) {
      const entry = getRemediation(id);
      expect(entry, `Missing remediation for ${id}`).toBeDefined();
      expect(entry!.guidance.length).toBeGreaterThan(10);
      expect(['low', 'medium', 'high']).toContain(entry!.effort);
    }
  });

  it('unknown rule ID returns undefined', () => {
    expect(getRemediation('FAKE-999')).toBeUndefined();
  });

  it('scan results include remediation field', () => {
    const report = scanSkillContent('---\nname: test\ndescription: test\n---\nTODO: fix this placeholder');
    const cont001 = report.results.find((r) => r.id === 'CONT-001');
    expect(cont001).toBeDefined();
    expect(cont001!.remediation).toBeDefined();
    expect(cont001!.remediation).toContain('placeholder');
  });

  it('terminal output includes Fix: text', () => {
    const report = scanSkillContent('---\nname: test\ndescription: test\n---\nTODO: fix this placeholder');
    const output = formatTerminalReport(report);
    expect(output).toContain('Fix:');
  });

  it('INJ rule remediation does not mention suppression', () => {
    const injIds = ALL_RULE_IDS.filter((id) => id.startsWith('INJ-'));
    for (const id of injIds) {
      const entry = getRemediation(id);
      expect(entry).toBeDefined();
      expect(entry!.guidance).not.toContain('skill-checker-ignore');
    }
  });
});
