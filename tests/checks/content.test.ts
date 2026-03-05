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

  it('CONT-005: detects ad content', () => {
    const skill = makeSkill('Buy now at our store! Free trial available for premium features and more.');
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-005')).toBe(true);
  });

  it('no false positives for clean content', () => {
    const skill = makeSkill(
      '# Format Code\n\nThis skill formats your code using prettier.\n\n## Steps\n1. Find files\n2. Run formatter\n3. Report changes',
      'name: format-code\ndescription: Formats code using prettier'
    );
    const results = contentChecks.run(skill);
    expect(results.length).toBe(0);
  });
});
