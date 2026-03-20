# Security Standard & Benchmark

> **Disclaimer**: This document describes an internal alignment exercise.
> Skill Checker does not claim third-party certification, external audit
> status, or compliance with any framework listed below.

## 1. Scope

Skill Checker statically analyzes Claude Code skill directories before
installation. The scanner examines:

- **SKILL.md** frontmatter (YAML) and body (Markdown)
- All non-binary files in the skill directory (up to depth 15)
- Binary files by metadata only (presence, extension, size)

Detection is organized into **6 rule categories** (57 rules total):

| Category | Prefix | Rules | Focus |
|----------|--------|-------|-------|
| Structural Validity | STRUCT | 8 | File presence, frontmatter schema, naming |
| Content Quality | CONT | 7 | Placeholder detection, information density |
| Injection Detection | INJ | 10 | Prompt injection, Unicode abuse, tag injection, social engineering |
| Code Safety | CODE | 16 | Dangerous APIs, reverse shell/exfiltration, credential leakage, persistence mechanisms, obfuscation, encoded payloads |
| Supply Chain | SUPPLY | 10 | Dependency risks, IOC threat intelligence |
| Resource Abuse | RES | 6 | Permission escalation, safety bypass attempts |

## 2. Standards Referenced

| Framework | Version | Usage |
|-----------|---------|-------|
| OWASP Top 10 for LLM Applications | 2025 | Primary risk taxonomy for LLM-specific threats |
| MITRE CWE (Common Weakness Enumeration) | 4.x | Weakness classification for code-level findings |
| MITRE ATT&CK | Enterprise v15 | Adversary technique mapping for behavioral patterns |

**Important**: Rule mappings below use "aligned with" and "maps to" to
indicate conceptual correspondence. Where a rule only partially aligns
with a framework entry, this is noted as "partial mapping" with an
explanation.

## 3. Rule Mapping Matrix

### A. Structural Validity (STRUCT)

| Rule ID | Severity | Risk Intent | OWASP LLM 2025 | CWE | ATT&CK | FP Notes |
|---------|----------|-------------|-----------------|-----|--------|----------|
| STRUCT-001 | CRITICAL | Missing SKILL.md | — | CWE-1188 (Initialization with Hard-Coded Credentials, partial: missing required resource) | — | No FP expected |
| STRUCT-002 | HIGH | Invalid frontmatter YAML | — | CWE-20 (Improper Input Validation) | — | Rare; strict YAML parse |
| STRUCT-003 | HIGH | Missing `name` field | — | CWE-20 | — | No FP expected |
| STRUCT-004 | MEDIUM | Missing `description` field | — | CWE-20 | — | No FP expected |
| STRUCT-005 | CRITICAL | Body too short (< 50 chars) | — | CWE-1188 (partial: insufficient content) | — | Intentionally minimal skills may trigger |
| STRUCT-006 | HIGH | Unexpected binary/executable files | LLM05 (Supply Chain, partial) | CWE-829 (Inclusion of Untrusted Functionality) | T1195.002 (Supply Chain: Software) | May flag legitimate helper binaries |
| STRUCT-007 | MEDIUM | Invalid skill name format | — | CWE-20 | — | No FP expected |
| STRUCT-008 | MEDIUM | Scan coverage warning | — | — | — | Informational; always emitted for partial scans |

### B. Content Quality (CONT)

| Rule ID | Severity | Risk Intent | OWASP LLM 2025 | CWE | ATT&CK | FP Notes |
|---------|----------|-------------|-----------------|-----|--------|----------|
| CONT-001 | HIGH | Placeholder content (TODO/FIXME) | — | CWE-1188 (partial: incomplete implementation) | — | Context-aware: excludes CSS classes, PPT terms, code block refs |
| CONT-002 | CRITICAL | Lorem ipsum filler | — | CWE-1188 | — | No FP expected |
| CONT-003 | MEDIUM | Low information density | — | — | — | Threshold: > 50% repeated lines |
| CONT-004 | MEDIUM | Description/body mismatch | — | — | — | Threshold: < 20% keyword overlap |
| CONT-005 | HIGH | Promotional/advertising content | — | — | — | Pattern-based; may flag legitimate product mentions |
| CONT-006 | MEDIUM | Excessive code examples (> 80%) | — | — | — | Reference-heavy skills may trigger |
| CONT-007 | HIGH | Name/body capability mismatch | — | — | — | Heuristic comparison; partial mapping to intent |

### C. Injection Detection (INJ)

All INJ rules enforce **zero context-based severity reduction** — findings
are always reported at their original severity regardless of surrounding
context (code block, documentation section, etc.).

| Rule ID | Severity | Risk Intent | OWASP LLM 2025 | CWE | ATT&CK | FP Notes |
|---------|----------|-------------|-----------------|-----|--------|----------|
| INJ-001 | CRITICAL | Zero-width Unicode characters | LLM01 (Prompt Injection) | CWE-116 (Improper Encoding/Escaping) | T1027 (Obfuscated Files) | No FP expected; zero-width chars have no legitimate use in skills |
| INJ-002 | HIGH | Homoglyph characters | LLM01 | CWE-116 | T1036 (Masquerading) | May flag legitimate multilingual content |
| INJ-003 | CRITICAL | RTL override characters | LLM01 | CWE-116 | T1036.005 (Match Legitimate Name) | No FP expected in English-language skills |
| INJ-004 | CRITICAL | System prompt override | LLM01 | CWE-74 (Injection) | T1059 (Command and Scripting Interpreter) | Pattern-based; catches "ignore previous instructions" variants |
| INJ-005 | HIGH | Tool output manipulation | LLM01 | CWE-74 | T1059 | Detects fake tool result patterns |
| INJ-006 | HIGH | Hidden instructions in comments | LLM01 | CWE-74 | T1027.009 (Embedded Payloads) | HTML/Markdown comments with directive content |
| INJ-007 | CRITICAL | Tag injection | LLM01 | CWE-74 | T1059 | Detects model/system tags like `<system>`, `<\|im_start\|>` |
| INJ-008 | CRITICAL | Encoded instructions (Base64) | LLM01 | CWE-74, CWE-116 | T1027 (Obfuscated Files) | Decodes Base64 and checks for instruction-like content |
| INJ-009 | MEDIUM | Delimiter confusion | LLM01 (partial) | CWE-74 (partial) | T1027 (partial) | Threshold-based; long markdown dividers may trigger |
| INJ-010 | CRITICAL/HIGH | Social engineering injection | LLM01 (Prompt Injection) | CWE-74 (Injection) | T1656 (Impersonation), T1059 (partial) | 4 sub-types: identity hijacking (CRITICAL), deception/secrecy (CRITICAL), config tampering (HIGH), verification bypass (HIGH); negative lookaheads reduce FP |

### D. Code Safety (CODE)

| Rule ID | Severity | Risk Intent | OWASP LLM 2025 | CWE | ATT&CK | FP Notes |
|---------|----------|-------------|-----------------|-----|--------|----------|
| CODE-001 | CRITICAL | eval/exec/Function execution | LLM02 (Sensitive Info, partial), LLM08 (Excessive Agency) | CWE-94 (Code Injection) | T1059 (Command Interpreter) | No context reduction; `platform.system()` excluded |
| CODE-002 | CRITICAL | Shell/subprocess execution | LLM02 (partial), LLM08 | CWE-78 (OS Command Injection) | T1059 | No context reduction; false positives list maintained |
| CODE-003 | CRITICAL | Destructive file operations (rm -rf) | LLM08 | CWE-732 (Incorrect Permission) | T1485 (Data Destruction) | Reduced to HIGH in code blocks |
| CODE-004 | HIGH | Hardcoded external URL/network request | LLM08 (partial) | CWE-918 (SSRF, partial) | T1071 (Application Layer Protocol) | Reduced to MEDIUM in code blocks; namespace URIs excluded |
| CODE-005 | HIGH | File write outside expected dirs | LLM08 | CWE-22 (Path Traversal) | T1565 (Data Manipulation) | No context reduction; sensitive paths only |
| CODE-006 | MEDIUM | Environment variable access | LLM02 | CWE-526 (Sensitive Info in Env) | T1082 (System Info Discovery) | Reduced to LOW in code blocks |
| CODE-007 | HIGH | Long encoded string (> 50 chars) | LLM01 (partial) | CWE-116 | T1027 | Base64/hex detection; may flag legitimate encoded data |
| CODE-008 | MEDIUM | High entropy string | LLM01 (partial) | CWE-798 (Hard-Coded Credentials, partial) | T1027 | Shannon entropy > 4.5 bits/char |
| CODE-009 | CRITICAL | Multi-layer encoding | LLM01 | CWE-116 | T1027 (Obfuscated Files) | No context reduction; nested encode/decode patterns |
| CODE-010 | HIGH | Dynamic code generation | LLM08 (partial) | CWE-94 (partial) | T1059 (partial) | No context reduction; compile/codegen patterns |
| CODE-011 | MEDIUM | Obfuscated variable names | — | CWE-1078 (Inappropriate Source Code Style, partial) | T1027 | Threshold: >= 3 hex-style identifiers |
| CODE-012 | HIGH | Permission escalation (sudo/chmod) | LLM08 | CWE-269 (Improper Privilege Mgmt) | T1548 (Abuse Elevation Control) | Reduced in documentation/install context |
| CODE-013 | CRITICAL/HIGH | API key / credential leakage | LLM02 (Sensitive Info Disclosure), LLM08 (Excessive Agency, partial) | CWE-798 (Use of Hard-coded Credentials) | T1552 (Unsecured Credentials) | Provider-specific patterns are CRITICAL; high-entropy assignment/header patterns are HIGH; no context reduction |
| CODE-014 | CRITICAL | Reverse shell pattern | LLM08 (Excessive Agency), LLM01 (Prompt Injection, partial) | CWE-78 (OS Command Injection) | T1059.004 (Unix Shell) | No context reduction; detects /dev/tcp, nc -e/--exec, and common language one-liners |
| CODE-015 | CRITICAL/HIGH | Remote pipeline execution / data exfiltration | LLM08 (Excessive Agency), LLM02 (Sensitive Info Disclosure, partial), LLM06 (Sensitive Information Disclosure, partial) | CWE-78 (pipeline exec), CWE-200 (Information Exposure, partial) | T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol) | CRITICAL for remote download-and-execute chains (curl\|sh, wget\|bash); HIGH for local file upload patterns (-d @file, --post-file) |
| CODE-016 | HIGH | Persistence mechanism detection | LLM08 (Excessive Agency) | CWE-78 (OS Command Injection, partial) | T1053 (Scheduled Task), T1543 (System Process), T1546 (Event Triggered), T1547 (Autostart), T1098.004 (SSH Keys), T1574.006 (LD_PRELOAD) | 9 sub-types: cron/launchd/systemd/shell profile/autostart/SSH keys/library injection/git hooks/macOS periodic; reduced to MEDIUM in code blocks; skipped in documentation context |

### E. Supply Chain (SUPPLY)

| Rule ID | Severity | Risk Intent | OWASP LLM 2025 | CWE | ATT&CK | FP Notes |
|---------|----------|-------------|-----------------|-----|--------|----------|
| SUPPLY-001 | HIGH | Unknown MCP server reference | LLM05 (Supply Chain) | CWE-829 (Untrusted Functionality) | T1195 (Supply Chain Compromise) | Reduced to MEDIUM in code blocks |
| SUPPLY-002 | MEDIUM | npx -y auto-install | LLM05 | CWE-829 | T1195.002 | Detects unconfirmed package execution |
| SUPPLY-003 | HIGH | Package install command | LLM05 | CWE-829 | T1195.002 | Reduced to MEDIUM in code blocks and docs |
| SUPPLY-004 | HIGH | Non-HTTPS URL | LLM05 (partial) | CWE-319 (Cleartext Transmission) | T1557 (Adversary-in-the-Middle) | Excludes LICENSE files, localhost; reduced in code blocks |
| SUPPLY-005 | CRITICAL | Raw IP address in URL | LLM05 | CWE-829 | T1071 (Application Layer Protocol) | Excludes localhost/127.0.0.1 and private ranges |
| SUPPLY-006 | MEDIUM | git clone command | LLM05 (partial) | CWE-829 (partial) | T1195.002 (partial) | Informational; verify source |
| SUPPLY-007 | CRITICAL/HIGH/MEDIUM/LOW | Suspicious domain (categorized) | LLM05 | CWE-829 | T1583 (Acquire Infrastructure) | 5 categories: exfiltration/tunnel/oast/paste/c2; context-aware: CRITICAL with sensitive combo, HIGH default, MEDIUM in code block, LOW in documentation |
| SUPPLY-008 | CRITICAL | Known malicious file hash | LLM05 | CWE-506 (Embedded Malicious Code) | T1195.002 | SHA-256 match against IOC database; empty hash excluded |
| SUPPLY-009 | CRITICAL | Known C2 IP address | LLM05 | CWE-506 | T1071.001 (Web Protocols) | IOC match; private/reserved IPs excluded |
| SUPPLY-010 | CRITICAL/HIGH | Typosquat name detection | LLM05 | CWE-829 | T1195.002 | CRITICAL for exact matches; HIGH for edit distance <= 2 |

### F. Resource Abuse (RES)

| Rule ID | Severity | Risk Intent | OWASP LLM 2025 | CWE | ATT&CK | FP Notes |
|---------|----------|-------------|-----------------|-----|--------|----------|
| RES-001 | HIGH | Instruction amplification | LLM08 (Excessive Agency) | CWE-834 (Excessive Iteration) | T1496 (Resource Hijacking, partial) | Detects recursive/repetitive instruction patterns |
| RES-002 | CRITICAL | Unrestricted tool access | LLM08 | CWE-269 (Improper Privilege Mgmt) | T1548 (Abuse Elevation Control) | Detects `Bash(*)`, `allowed_tools: *` |
| RES-003 | MEDIUM | Excessive allowed-tools list | LLM08 (partial) | CWE-250 (Unnecessary Privileges) | — | Threshold: > 15 tools in frontmatter |
| RES-004 | CRITICAL | Disable safety checks | LLM08 | CWE-693 (Protection Mechanism Failure) | T1562 (Impair Defenses) | Matches --no-verify, --force, disable safety |
| RES-005 | MEDIUM | Token waste pattern | LLM08 (partial) | CWE-400 (Uncontrolled Resource, partial) | T1496 (partial) | "repeat every response" and similar patterns |
| RES-006 | CRITICAL | Ignore project rules | LLM08 | CWE-693 | T1562 (Impair Defenses) | "ignore CLAUDE.md", override project config |

## 4. Benchmark Dataset

Skill Checker ships with six fixture skills under `tests/fixtures/` for
reproducible validation. Each fixture targets specific rule categories:

| Directory | Description | Expected Grade | Key Triggered Rules |
|-----------|-------------|----------------|---------------------|
| `safe-skill/` | Well-formed, benign skill | A (100/100) | None |
| `malicious-skill/` | Multiple malicious patterns combined | F (0/100) | INJ-004, INJ-006, INJ-007, CODE-002, CODE-004, CODE-009, CODE-015, SUPPLY-004, SUPPLY-005, SUPPLY-007, RES-002, RES-004, RES-006, CONT-005 |
| `injection-skill/` | Prompt injection attack samples | F | INJ-004, INJ-005, INJ-006, INJ-007, INJ-009, CODE-002, CODE-004, SUPPLY-004, RES-002 |
| `fake-skill/` | Placeholder and advertising content | Low | CONT-001, CONT-002, CONT-004, CONT-005, CONT-007 |
| `obfuscated-skill/` | Obfuscated code patterns | Low | INJ-008, CODE-002, CODE-007, CODE-008, CODE-009, CODE-011, RES-001, RES-002 |
| `mcp-reference-skill/` | Reference-heavy documentation skill | C (70/100) | SUPPLY-001, SUPPLY-003, CODE-003, CODE-004, CODE-006 (with severity reduction) |

To run the benchmark:

```bash
# Scan all fixtures
for d in tests/fixtures/*/; do
  echo "=== $(basename "$d") ==="
  node bin/skill-checker.js scan "$d"
  echo
done
```

## 5. Metrics & Scoring

### Score Calculation

Base score starts at **100**. Each finding deducts points by severity:

| Severity | Deduction | Example |
|----------|-----------|---------|
| CRITICAL | -25 | eval() execution, prompt override attempt |
| HIGH | -10 | Shell execution reference, promotional content |
| MEDIUM | -3 | Missing description, environment variable access |
| LOW | -1 | Minor style issues |

Score floor is **0** (no negative scores).

### Grade Thresholds

| Grade | Score Range | Interpretation |
|-------|------------|----------------|
| A | 90–100 | Safe to install |
| B | 75–89 | Minor issues; review recommended |
| C | 60–74 | Notable issues; careful review advised |
| D | 40–59 | Significant risk; manual audit needed |
| F | 0–39 | Not recommended for installation |

### Context-Aware Severity Reduction

Findings in certain contexts receive a one-level severity reduction:

| Context | Reduction | Safety Floor | Applicable Rules |
|---------|-----------|--------------|-----------------|
| Inside markdown code block | -1 level (HIGH → MEDIUM) | CRITICAL never below MEDIUM | CODE-003, CODE-004, CODE-006, CODE-016, SUPPLY-001, SUPPLY-003, SUPPLY-004, SUPPLY-007 |
| Documentation/install section | -1 level | Same | CODE-012, CODE-016 (skip), SUPPLY-003 |
| Documentation/install section | -2 levels (HIGH → LOW) | Same | SUPPLY-007 |
| Educational/descriptive context | -1 level | Same | CONT-005 (soft patterns only) |
| Combined with sensitive operation | +escalation to CRITICAL | — | SUPPLY-007 (curl -d @file, pipe to shell, sensitive file references) |

Rules that **never** receive reduction: CODE-001, CODE-002, CODE-005,
CODE-009, CODE-010, CODE-013, CODE-014, CODE-015, all INJ-* rules, all RES-* rules, IOC matches
(SUPPLY-008/009/010).

All reductions preserve an audit trail via `reducedFrom` and
`[reduced: reason]` annotations in the finding message.

### Per-File Deduplication

When the same rule triggers multiple times in the same file, findings are
deduplicated:

- **Key**: `ruleId + title + sourceFile`
- **Kept**: The finding with the highest severity (most conservative)
- **Annotation**: `(N occurrences in this file)` appended to message

Title is part of the key so that rules with multiple sub-types (e.g.
CODE-016 persistence groups, CODE-013 credential providers) produce
separate findings per sub-type rather than being incorrectly merged.

### Approval Policy Matrix

| Severity | strict | balanced (default) | permissive |
|----------|--------|--------------------|------------|
| CRITICAL | deny | deny | ask |
| HIGH | deny | ask | report |
| MEDIUM | ask | report | report |
| LOW | report | report | report |

Actions: **deny** = block installation, **ask** = prompt user for decision,
**report** = log finding but allow installation.

## 6. Limitations

1. **Static analysis only** — Skill Checker does not execute skill code.
   Runtime behavior, dynamic payloads loaded at execution time, and
   context-dependent logic paths are not observed.

2. **Heuristic detection** — Pattern matching and entropy analysis produce
   both false positives and false negatives. Obfuscation techniques not
   covered by current patterns will evade detection.

3. **Prompt injection is an unsolved problem** — No static tool can
   guarantee detection of all prompt injection variants. INJ rules cover
   known patterns but novel attacks may bypass them.

4. **IOC data timeliness** — The embedded threat intelligence seed data
   (C2 IPs, malicious hashes, typosquat names) is a snapshot. New threats
   require IOC database updates via `~/.config/skill-checker/ioc-override.json`.

5. **No semantic understanding** — The scanner does not understand what
   code does, only what it looks like. Semantically equivalent but
   syntactically different patterns may not be detected.

6. **Scan coverage ceiling** — Files are read up to configured size limits
   (512 KB partial read for 5–50 MB files). Very large or deeply nested
   skill directories may not be fully scanned (STRUCT-008 will report this).

## 7. Roadmap

- Remote skill loading (GitHub URL support)
- Inline suppression comments (`// skill-checker-ignore CODE-002`)
- Community rule contribution mechanism
- Expanded IOC database with automated feed ingestion
- Semantic analysis for code block content

---

*This document is not an external audit report, compliance certification,
or detection coverage guarantee. It describes the internal methodology and
alignment mapping of Skill Checker's rule set.*
