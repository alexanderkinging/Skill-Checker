import { describe, it, expect } from 'vitest';
import { codeSafetyChecks } from '../../src/checks/code-safety.js';
import { parseSkillContent } from '../../src/parser.js';

function makeSkill(body: string) {
  return parseSkillContent(`---\nname: test\ndescription: test\n---\n${body}`);
}

describe('Code Safety Checks', () => {
  it('CODE-001: detects eval', () => {
    const skill = makeSkill('```js\neval("alert(1)")\n```\nSome more text.');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-001')).toBe(true);
  });

  it('CODE-002: detects child_process', () => {
    const skill = makeSkill(
      '```js\nconst cp = require("child_process");\ncp.execSync("ls");\n```'
    );
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-002')).toBe(true);
  });

  it('CODE-003: detects rm -rf', () => {
    const skill = makeSkill('Run `rm -rf /tmp/build` to clean up everything.');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-003')).toBe(true);
  });

  it('CODE-004: detects hardcoded URLs', () => {
    const skill = makeSkill(
      '```js\nfetch("https://api.example.com/data")\n```'
    );
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-004')).toBe(true);
  });

  it('CODE-006: detects env var access', () => {
    const skill = makeSkill('```js\nconst key = process.env.API_KEY;\n```');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-006')).toBe(true);
  });

  it('CODE-009: detects multi-layer encoding', () => {
    const skill = makeSkill(
      '```js\natob(atob("nested encoded"))\n```'
    );
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-009')).toBe(true);
  });

  it('CODE-012: detects chmod', () => {
    const skill = makeSkill('Run `chmod +x script.sh` to make it executable.');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-012')).toBe(true);
  });

  it('no false positives for clean content', () => {
    const skill = makeSkill(
      '# Data Processor\n\nThis skill reads JSON files and generates reports.\n\n## Steps\n1. Read input file\n2. Parse JSON\n3. Generate report'
    );
    const results = codeSafetyChecks.run(skill);
    expect(results.length).toBe(0);
  });
});
