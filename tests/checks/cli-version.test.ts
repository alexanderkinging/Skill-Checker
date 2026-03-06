import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { readFileSync, existsSync, rmSync } from 'node:fs';

describe('CLI version consistency', () => {
  it('CLI --version matches package.json version', () => {
    const root = join(import.meta.dirname, '..', '..');
    const distExisted = existsSync(join(root, 'dist'));

    try {
      // Ensure dist exists — build if missing
      if (!distExisted) {
        execSync('npm run build', { cwd: root, stdio: 'pipe' });
      }

      const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf-8'));
      const cliOutput = execSync('node bin/skill-checker.js --version', {
        encoding: 'utf-8',
        cwd: root,
      }).trim();

      expect(cliOutput).toBe(pkg.version);
    } finally {
      // Clean up dist only if we created it
      if (!distExisted) {
        rmSync(join(root, 'dist'), { recursive: true, force: true });
      }
    }
  });
});
