import { describe, it, expect } from 'vitest';
import { contentChecks } from '../../src/checks/content.js';
import { parseSkillContent } from '../../src/parser.js';

function makeSkill(body: string, frontmatter = 'name: test\ndescription: test') {
  return parseSkillContent(`---\n${frontmatter}\n---\n${body}`);
}

describe('Content Checks', () => {
  it('CONT-001: detects TODO placeholder', () => {
    const skill = makeSkill('This is a TODO placeholder that needs to be filled in with real content later.');
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-001')).toBe(true);
  });

  it('CONT-002: detects lorem ipsum', () => {
    const skill = makeSkill('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod.');
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-002')).toBe(true);
  });


  it('CONT-003: detects excessive repetition', () => {
    const repeated = Array.from({ length: 8 }, () => 'Repeat this exact instruction line.').join('\n');
    const skill = makeSkill(repeated);
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-003')).toBe(true);
  });

  it('CONT-005: detects ad/promotional content', () => {
    const skill = makeSkill('Buy now and start your free trial today with promo code SAVE50.');
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-005')).toBe(true);
  });

  it('CONT-006: detects body mostly code with minimal instructions', () => {
    const skill = makeSkill(
      'Brief intro.\n```js\nconst v1 = 1;\nconst v2 = 2;\nconst v3 = 3;\nconst v4 = 4;\nconst v5 = 5;\nconst v6 = 6;\nconst v7 = 7;\nconst v8 = 8;\nconst v9 = 9;\nconst v10 = 10;\nconst v11 = 11;\nconst v12 = 12;\nconst v13 = 13;\nconst v14 = 14;\nconst v15 = 15;\nconst v16 = 16;\nconst v17 = 17;\nconst v18 = 18;\nconst v19 = 19;\nconst v20 = 20;\n```'
    );
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-006')).toBe(true);
  });

  it('CONT-007: detects skill name/body capability mismatch', () => {
    const skill = makeSkill(
      '# Guide\n\nThis skill only formats markdown headings and bullet spacing.',
      'name: database-backup-tool\ndescription: Basic formatter helper'
    );
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-007')).toBe(true);
  });

  it('does not trigger CONT-003/004/006/007 on high-quality aligned content', () => {
    const skill = makeSkill(
      '# Code formatter\n\nThis skill formats TypeScript files consistently.\n\n## Steps\n1. Parse TypeScript AST and collect formatting targets.\n2. Apply consistent indentation and spacing rules.\n3. Write the formatted file and summarize changes.\n\n## Notes\nUse the formatter on project files only and verify diff output.',
      'name: code-formatter\ndescription: Format TypeScript files with consistent style and spacing'
    );
    const results = contentChecks.run(skill);
    expect(results.some((r) => ['CONT-003', 'CONT-004', 'CONT-006', 'CONT-007'].includes(r.id))).toBe(false);
  });

});
