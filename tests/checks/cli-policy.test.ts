import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { existsSync, rmSync } from 'node:fs';

describe('CLI --policy validation', () => {
  const root = join(import.meta.dirname, '..', '..');

  it('rejects invalid policy with non-zero exit and clear error', () => {
    const distExisted = existsSync(join(root, 'dist'));

    if (!distExisted) {
      execSync('npm run build', { cwd: root, stdio: 'pipe' });
    }

    try {
      execSync(
        'node bin/skill-checker.js scan tests/fixtures/malicious-skill --format hook --policy nope',
        { cwd: root, encoding: 'utf-8', stdio: 'pipe' }
      );
      expect.unreachable('Expected non-zero exit');
    } catch (err: unknown) {
      const e = err as { status: number; stderr: string; stdout: string };
      expect(e.status).not.toBe(0);
      const output = (e.stderr || '') + (e.stdout || '');
      expect(output).toContain('invalid policy');
      expect(output).not.toContain('TypeError');
    } finally {
      if (!distExisted) {
        rmSync(join(root, 'dist'), { recursive: true, force: true });
      }
    }
  });
});
