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

function makeSkillWithFiles(files: Array<{ path: string; ext: string }>) {
  const skill = parseSkillContent(
    '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks.'
  );
  for (const f of files) {
    skill.files.push({
      path: f.path,
      name: f.path,
      extension: f.ext,
      sizeBytes: 100,
      isBinary: false,
      content: '#!/bin/bash\necho hello',
    });
  }
  return skill;
}

describe('STRUCT-006 script vs binary severity', () => {
  it('.sh file produces LOW severity (script)', () => {
    const skill = makeSkillWithFiles([{ path: 'setup.sh', ext: '.sh' }]);
    const results = structuralChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'STRUCT-006');
    expect(s006.length).toBe(1);
    expect(s006[0].severity).toBe('LOW');
  });

  it('.bash file produces LOW severity (script)', () => {
    const skill = makeSkillWithFiles([{ path: 'run.bash', ext: '.bash' }]);
    const results = structuralChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'STRUCT-006');
    expect(s006.length).toBe(1);
    expect(s006[0].severity).toBe('LOW');
  });

  it('.ps1 file produces LOW severity (script)', () => {
    const skill = makeSkillWithFiles([{ path: 'setup.ps1', ext: '.ps1' }]);
    const results = structuralChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'STRUCT-006');
    expect(s006.length).toBe(1);
    expect(s006[0].severity).toBe('LOW');
  });

  it('.exe file produces HIGH severity (binary)', () => {
    const skill = makeSkillWithFiles([{ path: 'tool.exe', ext: '.exe' }]);
    const results = structuralChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'STRUCT-006');
    expect(s006.length).toBe(1);
    expect(s006[0].severity).toBe('HIGH');
  });

  it('.dll file produces HIGH severity (binary)', () => {
    const skill = makeSkillWithFiles([{ path: 'lib.dll', ext: '.dll' }]);
    const results = structuralChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'STRUCT-006');
    expect(s006.length).toBe(1);
    expect(s006[0].severity).toBe('HIGH');
  });

  it('.wasm file produces HIGH severity (binary)', () => {
    const skill = makeSkillWithFiles([{ path: 'mod.wasm', ext: '.wasm' }]);
    const results = structuralChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'STRUCT-006');
    expect(s006.length).toBe(1);
    expect(s006[0].severity).toBe('HIGH');
  });
});
