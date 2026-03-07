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

describe('CODE-013: API key/credential leakage detection', () => {
  it('detects Anthropic key as CRITICAL', () => {
    const skill = makeSkill('const key = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects OpenAI sk-proj key as CRITICAL', () => {
    const skill = makeSkill('api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects restricted sk-* token only with assignment context as CRITICAL', () => {
    const skill = makeSkill('const token = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcd";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects Slack token as CRITICAL', () => {
    const skill = makeSkill('SLACK_TOKEN = "xoxb-EXAMPLE-TOKEN-FOR-TESTING-ONLY-ABCDE"');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects AWS access key as CRITICAL', () => {
    const skill = makeSkill('const aws = "AKIA1234567890ABCDEF";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects GitHub PAT as CRITICAL', () => {
    const skill = makeSkill('const gh = "github_pat_11ABCDEFGHIJKLMNOPQRSTUV_1234567890abcdefghijklmnopqrstuvwxyz";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects high-entropy assignment as HIGH', () => {
    const skill = makeSkill('const apiKey = "Qw3rTy9LmN8vBc7XzP6aSd5Fg4Hj2Kp1";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('HIGH');
  });

  it('detects Authorization Bearer high-entropy token as HIGH', () => {
    const skill = makeSkill('Authorization: Bearer Qw3rTy9LmN8vBc7XzP6aSd5Fg4Hj2Kp1');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('HIGH');
  });

  it('detects X-API-Key high-entropy token as HIGH', () => {
    const skill = makeSkill('X-API-Key: Qw3rTy9LmN8vBc7XzP6aSd5Fg4Hj2Kp1');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('HIGH');
  });

  it('detects OPENAI_API_KEY assignment with sk-* as CRITICAL', () => {
    const skill = makeSkill('const OPENAI_API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcd";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects OPENAI_API_KEY key-value with sk-* as CRITICAL', () => {
    const skill = makeSkill('OPENAI_API_KEY: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcd');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects openai_api_key assignment with sk-* as CRITICAL', () => {
    const skill = makeSkill('openai_api_key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcd"');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('detects apikey assignment as HIGH', () => {
    const skill = makeSkill('const apikey = "Qw3rTy9LmN8vBc7XzP6aSd5Fg4Hj2Kp1";');
    const results = codeSafetyChecks.run(skill);
    const finding = results.find((r) => r.id === 'CODE-013');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('HIGH');
  });

  it('does not detect high-entropy monkey assignment', () => {
    const skill = makeSkill('const monkey = "Qw3rTy9LmN8vBc7XzP6aSd5Fg4Hj2Kp1";');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-013')).toBe(false);
  });

  it('does not detect high-entropy turkey assignment', () => {
    const skill = makeSkill('const turkey = "Qw3rTy9LmN8vBc7XzP6aSd5Fg4Hj2Kp1";');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-013')).toBe(false);
  });

  it('does not detect unrestricted sk-* without assignment or auth context', () => {
    const skill = makeSkill('Example literal token: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcd');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-013')).toBe(false);
  });

  it('does not detect low-entropy token assignment', () => {
    const skill = makeSkill('const token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-013')).toBe(false);
  });

  it('does not detect normal business string', () => {
    const skill = makeSkill('const message = "project setup completed successfully";');
    const results = codeSafetyChecks.run(skill);
    expect(results.some((r) => r.id === 'CODE-013')).toBe(false);
  });
});
