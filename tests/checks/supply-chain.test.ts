import { describe, it, expect } from 'vitest';
import { supplyChainChecks } from '../../src/checks/supply-chain.js';
import { parseSkillContent } from '../../src/parser.js';

function makeSkill(body: string) {
  return parseSkillContent(`---\nname: test\ndescription: test\n---\n${body}`);
}

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
});
