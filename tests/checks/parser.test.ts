import { describe, it, expect, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { parseSkill } from '../../src/parser.js';
import { structuralChecks } from '../../src/checks/structural.js';
import { codeSafetyChecks } from '../../src/checks/code-safety.js';
import { scanSkillDirectory } from '../../src/scanner.js';

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

  it('6MB file with eval in first 512KB triggers CODE-001 and STRUCT-008', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');
    // 6MB file: eval at the start, padded with filler
    const bigContent = 'const x = eval("danger")\n' + 'a'.repeat(6_000_000);
    writeFileSync(join(dir, 'large.js'), bigContent);

    const report = scanSkillDirectory(dir);
    // CODE-001 must fire from partial read content
    expect(report.results.some((r) => r.id === 'CODE-001')).toBe(true);
    // STRUCT-008 must exist for the partial scan warning
    expect(report.results.some((r) => r.id === 'STRUCT-008')).toBe(true);
  });
});

describe('Parser: symlink handling', () => {
  it('skips symlink files and does not follow them', () => {
    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');

    // Create an external file with eval — outside the skill dir
    const externalDir = join(dir, '..', 'tmp-parser-external');
    mkdirSync(externalDir, { recursive: true });
    writeFileSync(join(externalDir, 'evil.js'), 'eval("malicious code")');

    // Create a symlink inside the skill dir pointing to the external file
    symlinkSync(join(externalDir, 'evil.js'), join(dir, 'link-to-evil.js'));

    const report = scanSkillDirectory(dir);

    // CODE-001 must NOT fire — symlink should be skipped, not read
    expect(report.results.some((r) => r.id === 'CODE-001')).toBe(false);

    // Warning about skipped symlink should exist
    const skill = parseSkill(dir);
    expect(skill.warnings.some((w) => w.includes('symlink'))).toBe(true);

    // Cleanup external dir
    rmSync(externalDir, { recursive: true, force: true });
  });
});

describe('Parser: FIFO/special file handling (POSIX)', () => {
  it('skips FIFO without blocking and emits warning', () => {
    // Skip on non-POSIX (Windows)
    if (process.platform === 'win32') return;

    const dir = setupTmpDir();
    writeFileSync(join(dir, 'SKILL.md'), '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks easily.');

    // Create a FIFO using mkfifo
    const fifoPath = join(dir, 'trap.fifo');
    execSync(`mkfifo "${fifoPath}"`);

    // parseSkill must return without blocking
    const skill = parseSkill(dir);

    // FIFO should not appear in files list
    expect(skill.files.some((f) => f.path === 'trap.fifo')).toBe(false);

    // Warning about skipped special file
    expect(skill.warnings.some((w) => w.includes('special file'))).toBe(true);
  });
});
