import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

describe('CLI version consistency', () => {
  it('CLI --version matches package.json version', () => {
    const pkgPath = join(__dirname, '..', '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    const expectedVersion = pkg.version;

    const cliOutput = execSync('node bin/skill-checker.js --version', {
      encoding: 'utf-8',
      cwd: join(__dirname, '..', '..'),
    }).trim();

    expect(cliOutput).toBe(expectedVersion);
  });
});
