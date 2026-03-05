import { describe, it, expect } from 'vitest';
import { structuralChecks } from '../../src/checks/structural.js';
import { parseSkillContent } from '../../src/parser.js';

describe('Structural Checks', () => {
  it('STRUCT-001: detects missing SKILL.md', () => {
    const skill = parseSkillContent('');
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-001')).toBe(true);
  });

  it('STRUCT-002: detects missing frontmatter', () => {
    const skill = parseSkillContent(
      'Just some text without frontmatter. This needs to be at least fifty characters long to pass.'
    );
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-002')).toBe(true);
  });

  it('STRUCT-003: detects missing name', () => {
    const skill = parseSkillContent(
      '---\ndescription: test\n---\nBody content that is long enough to pass the minimum character check easily.'
    );
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-003')).toBe(true);
  });

  it('STRUCT-004: detects missing description', () => {
    const skill = parseSkillContent(
      '---\nname: test-skill\n---\nBody content that is long enough to pass the minimum character check easily.'
    );
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-004')).toBe(true);
  });

  it('STRUCT-005: detects short body', () => {
    const skill = parseSkillContent('---\nname: test\ndescription: test\n---\nShort.');
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-005')).toBe(true);
  });

  it('STRUCT-007: detects non-hyphen-case name', () => {
    const skill = parseSkillContent(
      '---\nname: MySkill\ndescription: test\n---\nBody content that is long enough to pass the minimum character check easily.'
    );
    const results = structuralChecks.run(skill);
    expect(results.some((r) => r.id === 'STRUCT-007')).toBe(true);
  });

  it('passes for valid skill', () => {
    const skill = parseSkillContent(
      '---\nname: my-skill\ndescription: A great skill\n---\n# My Skill\n\nThis is a well-formed skill with enough body content to pass all structural checks.'
    );
    const results = structuralChecks.run(skill);
    expect(results.length).toBe(0);
  });
});
