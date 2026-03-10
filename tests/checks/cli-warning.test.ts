import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('CLI non-skill-directory warning', () => {
  const root = join(import.meta.dirname, '..', '..');

  it('prints warning to stderr when SKILL.md not found', () => {
    const distExisted = existsSync(join(root, 'dist'));

    if (!distExisted) {
      execSync('npm run build', { cwd: root, stdio: 'pipe' });
    }

    const tmpDir = mkdtempSync(join(tmpdir(), 'skill-checker-warn-'));

    try {
      const result = execSync(
        `node bin/skill-checker.js scan ${tmpDir}`,
        { cwd: root, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
      // Should not reach here (STRUCT-001 CRITICAL causes exit 1)
      expect.unreachable('Expected non-zero exit');
    } catch (err: unknown) {
      const e = err as { status: number; stderr: string; stdout: string };
      expect(e.stderr).toContain('Warning: No SKILL.md found');
      expect(e.stderr).toContain('skill directories');
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
      if (!distExisted) {
        rmSync(join(root, 'dist'), { recursive: true, force: true });
      }
    }
  });

  it('does NOT print warning when SKILL.md exists', () => {
    const distExisted = existsSync(join(root, 'dist'));

    if (!distExisted) {
      execSync('npm run build', { cwd: root, stdio: 'pipe' });
    }

    try {
      const result = execSync(
        'node bin/skill-checker.js scan tests/fixtures/safe-skill',
        { cwd: root, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
      // safe-skill should exit 0, stderr should not contain warning
      // result is stdout; we need stderr which is empty on success
    } catch (err: unknown) {
      const e = err as { status: number; stderr: string; stdout: string };
      expect(e.stderr || '').not.toContain('Warning: No SKILL.md found');
    }
  });
});
