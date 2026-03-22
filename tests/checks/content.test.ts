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
    const finding = results.find((r) => r.id === 'CONT-001');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
  });

  it('CONT-002: detects lorem ipsum', () => {
    const skill = makeSkill('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod.');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-002');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('CRITICAL');
  });


  it('CONT-003: detects excessive repetition', () => {
    const repeated = Array.from({ length: 8 }, () => 'Repeat this exact instruction line.').join('\n');
    const skill = makeSkill(repeated);
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-003');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
  });

  it('CONT-005: detects ad/promotional content', () => {
    const skill = makeSkill('Buy now and start your free trial today with promo code SAVE50.');
    const results = contentChecks.run(skill);
    expect(results.some((r) => r.id === 'CONT-005')).toBe(true);
  });

  // CONT-005 context-aware tests

  it('CONT-005: strong pattern stays HIGH regardless of context', () => {
    const skill = makeSkill('## Pricing Strategy Guide\nBuy now and get 50% off!');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005' && r.severity === 'HIGH' && !r.reducedFrom);
    expect(finding).toBeDefined();
  });

  it('CONT-005: strong CTA stays HIGH', () => {
    const skill = makeSkill('Click here to buy our product today!');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: soft pattern in non-educational context stays HIGH', () => {
    const skill = makeSkill('Get a discount on our premium plan');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: heading with soft pattern reduces to MEDIUM', () => {
    const skill = makeSkill('## Discount Structures');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.reducedFrom).toBe('HIGH');
  });

  it('CONT-005: label-value structure reduces to MEDIUM', () => {
    const skill = makeSkill('## Pricing\nDiscount type: One-time, recurring, LTD');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005' && r.snippet?.includes('Discount type'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.reducedFrom).toBe('HIGH');
  });

  it('CONT-005: soft pattern under educational header reduces to MEDIUM', () => {
    const skill = makeSkill('## Pricing Strategy Guide\nConsider offering a free trial to new users.');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005' && r.snippet?.includes('free trial'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.reducedFrom).toBe('HIGH');
  });

  it('CONT-005: soft pattern in code block reduces to MEDIUM', () => {
    const skill = makeSkill('Example:\n```\npromo code: SAVE20\n```');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.reducedFrom).toBe('HIGH');
  });

  it('CONT-005: heading with soft pattern + promotional intent stays HIGH', () => {
    const skill = makeSkill('## Limited time discount: 50% off everything!');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: label-value with urgency stays HIGH', () => {
    const skill = makeSkill('Discount: Save 30% today only');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: heading with discount + urgency stays HIGH', () => {
    const skill = makeSkill('## Exclusive discount: Act now for 50% off');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: cross-line urgency + soft pattern stays HIGH', () => {
    const skill = makeSkill('Limited time offer!\nDiscount type: one-time');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005' && r.snippet?.includes('Discount type'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: expanded intent pattern "offer ends" blocks reduction', () => {
    const skill = makeSkill('Offer ends Friday\n## Discount Structures');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005' && r.snippet?.includes('Discount'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: expanded intent pattern "last chance" blocks reduction', () => {
    const skill = makeSkill('## Free Trial Options\nLast chance to sign up');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005' && r.snippet?.includes('Free Trial'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-005: reduced finding preserves audit annotation', () => {
    const skill = makeSkill('## Discount Structures');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-005');
    expect(finding).toBeDefined();
    expect(finding!.message).toContain('[reduced:');
  });

  it('CONT-006: detects body mostly code with minimal instructions', () => {
    const skill = makeSkill(
      'Brief intro.\n```js\nconst v1 = 1;\nconst v2 = 2;\nconst v3 = 3;\nconst v4 = 4;\nconst v5 = 5;\nconst v6 = 6;\nconst v7 = 7;\nconst v8 = 8;\nconst v9 = 9;\nconst v10 = 10;\nconst v11 = 11;\nconst v12 = 12;\nconst v13 = 13;\nconst v14 = 14;\nconst v15 = 15;\nconst v16 = 16;\nconst v17 = 17;\nconst v18 = 18;\nconst v19 = 19;\nconst v20 = 20;\n```'
    );
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-006');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
  });

  it('CONT-007: detects skill name/body capability mismatch', () => {
    const skill = makeSkill(
      '# Guide\n\nThis skill only formats markdown headings and bullet spacing.',
      'name: database-backup-tool\ndescription: Basic formatter helper'
    );
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-007');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
  });

  it('CONT-004: detects description/body mismatch', () => {
    const skill = makeSkill(
      '# Guide\n\nThis skill formats markdown files and fixes indentation.',
      'name: test\ndescription: Monitors Kubernetes clusters for anomalies and alerts on pod failures'
    );
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-004');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
  });

  // CONT-001: instructional placeholder context reduction
  it('CONT-001: "create placeholder text for all sections" reduces to MEDIUM', () => {
    const skill = makeSkill('Create the initial document structure with placeholder text for all sections.');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-001');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.reducedFrom).toBe('HIGH');
  });

  it('CONT-001: "TODO: implement this" stays HIGH (strict pattern)', () => {
    const skill = makeSkill('TODO: implement this feature before release.');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-001');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.reducedFrom).toBeUndefined();
  });

  it('CONT-001: "Replace placeholder values" does not trigger (isTechnicalRef)', () => {
    const skill = makeSkill('Replace placeholder values with actual configuration.');
    const results = contentChecks.run(skill);
    const finding = results.find((r) => r.id === 'CONT-001');
    expect(finding).toBeUndefined();
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
