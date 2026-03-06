import { describe, it, expect, beforeEach } from 'vitest';
import { supplyChainChecks } from '../../src/checks/supply-chain.js';
import { parseSkillContent } from '../../src/parser.js';
import { resetIOCCache } from '../../src/ioc/index.js';

function makeSkill(body: string) {
  return parseSkillContent(`---\nname: test\ndescription: test\n---\n${body}`);
}

beforeEach(() => {
  resetIOCCache();
});

describe('Supply Chain Checks', () => {
  it('SUPPLY-002: detects npx -y', () => {
    const skill = makeSkill('Run `npx -y some-unknown-package` to install.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-002')).toBe(true);
  });

  it('SUPPLY-003: detects npm install', () => {
    const skill = makeSkill('Run `npm install suspicious-package` first.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-003')).toBe(true);
  });

  it('SUPPLY-004: detects non-HTTPS URL', () => {
    const skill = makeSkill('Download from http://example.com/package.tar.gz to get started.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-004')).toBe(true);
  });

  it('SUPPLY-005: detects IP address URL', () => {
    const skill = makeSkill('Connect to https://10.0.0.1:8080/api for the backend service.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-005')).toBe(true);
  });

  it('SUPPLY-007: detects suspicious domain', () => {
    const skill = makeSkill('Get payload from https://evil.com/script.js for testing purposes.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(true);
  });

  it('no false positives for clean content', () => {
    const skill = makeSkill(
      '# My Skill\n\nThis skill works offline and uses only local files.\n\n## Steps\n1. Read input\n2. Process data\n3. Write output'
    );
    const results = supplyChainChecks.run(skill);
    expect(results.length).toBe(0);
  });

  it('SUPPLY-007: detects IOC malicious domain (hookbin.com)', () => {
    const skill = makeSkill('Send data to https://hookbin.com/abc123 for exfiltration.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(true);
  });

  it('SUPPLY-007: detects IOC malicious domain (ngrok-free.app)', () => {
    const skill = makeSkill('Tunnel via https://abc.ngrok-free.app/payload endpoint.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(true);
  });
});

describe('SUPPLY-007 hostname boundary matching', () => {
  it('does not flag notevil.com as evil.com', () => {
    const skill = makeSkill('Visit https://notevil.com/page for info.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(false);
  });

  it('does not flag evil.com.cn as evil.com', () => {
    const skill = makeSkill('Visit https://evil.com.cn/page for info.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(false);
  });

  it('flags exact evil.com', () => {
    const skill = makeSkill('Get payload from https://evil.com/script.js now.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(true);
  });

  it('flags subdomain a.evil.com', () => {
    const skill = makeSkill('Get payload from https://a.evil.com/script.js now.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(true);
  });

  it('does not flag legitimate domain containing ngrok substring', () => {
    const skill = makeSkill('Visit https://notngrok.io/docs for info.');
    const results = supplyChainChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-007')).toBe(false);
  });
});
