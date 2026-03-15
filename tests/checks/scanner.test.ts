import { describe, it, expect, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
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

const TMP_DEDUP = join(import.meta.dirname, '..', 'tmp-dedup-test');

function setupDedup(): string {
  rmSync(TMP_DEDUP, { recursive: true, force: true });
  mkdirSync(TMP_DEDUP, { recursive: true });
  return TMP_DEDUP;
}

afterEach(() => {
  rmSync(TMP_DEDUP, { recursive: true, force: true });
});

describe('Deduplication: CONT-005 per-file aggregation', () => {
  it('multiple CONT-005 in same SKILL.md dedup to one finding with highest severity', () => {
    const body = [
      '# Marketing guide',
      '',
      '## Discount Structures',
      'Get a free trial of our premium plan',
      'Limited time offer! Check out my channel for deals',
    ].join('\n');
    const report = scanSkillContent(
      `---\nname: test\ndescription: test\n---\n${body}`
    );
    const cont005 = report.results.filter((r) => r.id === 'CONT-005');
    expect(cont005.length).toBe(1);
    expect(cont005[0].severity).toBe('HIGH');
    expect(cont005[0].occurrences).toBeGreaterThanOrEqual(2);
  });
});

describe('Deduplication: different files must not merge', () => {
  it('two .exe files produce two separate STRUCT-006 findings', () => {
    const dir = setupDedup();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    writeFileSync(join(dir, 'a.exe'), 'binary-a');
    writeFileSync(join(dir, 'b.exe'), 'binary-b');

    const report = scanSkillDirectory(dir);
    const struct006 = report.results.filter((r) => r.id === 'STRUCT-006');
    expect(struct006.length).toBe(2);
    // Neither should have occurrences > 1
    expect(struct006.every((r) => !r.occurrences || r.occurrences === 1)).toBe(true);
  });

  it('same rule same file merges with correct occurrences', () => {
    const dir = setupDedup();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    // Two eval calls in the same file → should merge into 1 finding
    writeFileSync(join(dir, 'bad.js'), 'eval("a")\neval("b")');

    const report = scanSkillDirectory(dir);
    const code001 = report.results.filter((r) => r.id === 'CODE-001' && r.source === 'bad.js');
    expect(code001.length).toBe(1);
    expect(code001[0].occurrences).toBe(2);
    expect(code001[0].message).toContain('occurrences in this file');
  });

  it('same rule in different files stays separate', () => {
    const dir = setupDedup();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    writeFileSync(join(dir, 'x.js'), 'eval("a")');
    writeFileSync(join(dir, 'y.js'), 'eval("b")');

    const report = scanSkillDirectory(dir);
    const code001 = report.results.filter((r) => r.id === 'CODE-001');
    // Must have at least 2 separate findings (one per file)
    const sources = code001.map((r) => r.source);
    expect(sources).toContain('x.js');
    expect(sources).toContain('y.js');
  });
});
