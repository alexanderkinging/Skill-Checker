import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { join } from 'node:path';

const HOOK_PATH = join(__dirname, '..', '..', 'hook', 'skill-gate.sh');

function runHook(stdin: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execSync(`bash "${HOOK_PATH}"`, {
      input: stdin,
      encoding: 'utf-8',
      timeout: 5000,
      env: { ...process.env, PATH: process.env.PATH },
    });
    return { stdout: stdout.trim(), exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; status?: number };
    return {
      stdout: (e.stdout ?? '').trim(),
      exitCode: e.status ?? 1,
    };
  }
}

describe('skill-gate.sh: invalid JSON input robustness', () => {
  it('returns ask with exit 0 for completely invalid input', () => {
    const result = runHook('this is not json at all');
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.permissionDecision).toBe('ask');
  });

  it('returns ask with exit 0 for empty input', () => {
    const result = runHook('');
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.permissionDecision).toBe('ask');
  });

  it('returns ask with exit 0 for partial JSON', () => {
    const result = runHook('{"tool_input": {');
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.permissionDecision).toBe('ask');
  });

  it('returns allow for non-SKILL.md file path', () => {
    const result = runHook(JSON.stringify({
      tool_input: { file_path: '/some/path/readme.md', content: 'hello' },
    }));
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.permissionDecision).toBe('allow');
  });
});
