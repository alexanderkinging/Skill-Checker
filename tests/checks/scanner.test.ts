import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { scanSkillDirectory, scanSkillContent } from '../../src/scanner.js';

const FIXTURES = join(import.meta.dirname, '..', 'fixtures');

describe('Scanner', () => {
  it('safe skill gets grade A or B', () => {
    const report = scanSkillDirectory(join(FIXTURES, 'safe-skill'));
    expect(['A', 'B']).toContain(report.grade);
    expect(report.score).toBeGreaterThanOrEqual(75);
    expect(report.summary.critical).toBe(0);
  });

  it('malicious skill gets grade F', () => {
    const report = scanSkillDirectory(join(FIXTURES, 'malicious-skill'));
    expect(report.grade).toBe('F');
    expect(report.score).toBeLessThan(40);
    expect(report.summary.critical).toBeGreaterThan(0);
  });

  it('injection skill gets low score', () => {
    const report = scanSkillDirectory(join(FIXTURES, 'injection-skill'));
    expect(report.score).toBeLessThan(60);
    expect(report.results.some((r) => r.category === 'INJ')).toBe(true);
  });

  it('fake skill gets low score', () => {
    const report = scanSkillDirectory(join(FIXTURES, 'fake-skill'));
    expect(report.score).toBeLessThan(75);
    expect(report.results.some((r) => r.category === 'CONT')).toBe(true);
  });

  it('obfuscated skill detects code safety issues', () => {
    const report = scanSkillDirectory(join(FIXTURES, 'obfuscated-skill'));
    expect(report.results.some((r) => r.category === 'CODE')).toBe(true);
    expect(report.score).toBeLessThan(60);
  });

  it('respects config overrides', () => {
    const report = scanSkillContent(
      '---\nname: test\ndescription: test\n---\n```js\nconst key = process.env.API_KEY;\n```\nMore than fifty characters of body content here to be valid.',
      { policy: 'balanced', overrides: { 'CODE-006': 'LOW' }, ignore: [] }
    );
    const envResult = report.results.find((r) => r.id === 'CODE-006');
    if (envResult) {
      expect(envResult.severity).toBe('LOW');
    }
  });

  it('respects config ignore', () => {
    const report = scanSkillContent(
      '---\nname: test\ndescription: test\n---\n```js\nconst key = process.env.API_KEY;\n```\nMore than fifty characters of body content here to be valid.',
      { policy: 'balanced', overrides: {}, ignore: ['CODE-006'] }
    );
    expect(report.results.some((r) => r.id === 'CODE-006')).toBe(false);
  });
});
