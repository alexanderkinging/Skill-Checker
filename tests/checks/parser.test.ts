import { describe, it, expect, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { parseSkill } from '../../src/parser.js';
import { structuralChecks } from '../../src/checks/structural.js';
import { codeSafetyChecks } from '../../src/checks/code-safety.js';

const TMP_BASE = join(__dirname, '..', 'tmp-parser-test');

function setupTmpDir(): string {
  rmSync(TMP_BASE, { recursive: true, force: true });
  mkdirSync(TMP_BASE, { recursive: true });
  return TMP_BASE;
}

afterEach(() => {
  rmSync(TMP_BASE, { recursive: true, force: true });
});

describe('Parser: hidden directory scanning', () => {
  it('scans files inside hidden directories (not .git)', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    mkdirSync(join(dir, '.hidden'), { recursive: true });
    writeFileSync(join(dir, '.hidden', 'payload.js'), 'eval("malicious code")');

    const skill = parseSkill(dir);
    const hiddenFile = skill.files.find((f) => f.path.includes('.hidden'));
    expect(hiddenFile).toBeDefined();
    expect(hiddenFile!.content).toContain('eval');
  });

  it('does not scan .git directory', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    mkdirSync(join(dir, '.git', 'objects'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), 'git config');

    const skill = parseSkill(dir);
    const gitFile = skill.files.find((f) => f.path.includes('.git'));
    expect(gitFile).toBeUndefined();
  });

  it('emits warning for node_modules', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    mkdirSync(join(dir, 'node_modules', 'evil-pkg'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'evil-pkg', 'index.js'), 'eval("bad")');

    const skill = parseSkill(dir);
    expect(skill.warnings.some((w) => w.includes('node_modules'))).toBe(true);
    // node_modules files should NOT be in the file list
    const nmFile = skill.files.find((f) => f.path.includes('node_modules'));
    expect(nmFile).toBeUndefined();
  });
});

describe('Parser: STRUCT-008 scan coverage warnings', () => {
  it('surfaces node_modules warning as STRUCT-008 finding', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    mkdirSync(join(dir, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'pkg', 'index.js'), 'code');

    const skill = parseSkill(dir);
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-008')).toBe(true);
  });
});

describe('Parser: hidden dir payload detection end-to-end', () => {
  it('detects eval in hidden directory via code-safety checks', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    mkdirSync(join(dir, '.sneaky'), { recursive: true });
    writeFileSync(join(dir, '.sneaky', 'payload.js'), 'const x = eval("payload")');

    const skill = parseSkill(dir);
    const results = codeSafetyChecks.run(skill);
    // CODE-001 detects eval()
    expect(results.some((r) => r.id === 'CODE-001')).toBe(true);
  });
});

describe('Parser: large file handling', () => {
  it('emits warning for large text file and still provides partial content', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    // Create a 6MB text file with eval at the start
    const bigContent = 'eval("evil")\n' + 'x'.repeat(6_000_000);
    writeFileSync(join(dir, 'big.js'), bigContent);

    const skill = parseSkill(dir);
    const bigFile = skill.files.find((f) => f.path === 'big.js');
    expect(bigFile).toBeDefined();
    // Content should be present (partial read)
    expect(bigFile!.content).toContain('eval');
    // Warning about partial scan
    expect(skill.warnings.some((w) => w.includes('big.js') && w.includes('partially'))).toBe(true);
  });
});
