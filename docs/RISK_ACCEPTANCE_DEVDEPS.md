# Dev Dependency Risk Acceptance Record

## Background

`npm audit --json` reports **5 moderate** vulnerabilities on the development tooling chain:

- `vitest` -> `vite` -> `esbuild`

This finding is currently tied to an upgrade path that requires a Vitest major-version change.

## Impact Scope

- Affected scope: **dev/test toolchain only**
- Not affected: production runtime dependency path (`npm audit --omit=dev --json` shows 0 vulnerabilities)

## Upgrade Decision and Constraint

We are **not** upgrading to `vitest@4` in this cycle.

Reason:

- `vitest@4` requires Node `^20 || ^22 || >=24`
- Project policy in `package.json` currently declares `engines.node: >=18`
- Upgrading now would break current engine support strategy

## Risk Acceptance

- Residual risk: **Medium (dev-only)**
- Decision: **Temporarily accept and defer upgrade**

## Ownership

- Accepted by: **Alexander Jin**
- Responsible owner: **Alexander Jin**
- Acceptance date: **2026-03-07**
- Expiry / next review date: **2026-04-04**

## Review Triggers

Re-open this decision immediately if any trigger is met:

1. Node engine strategy is upgraded to `>=20`
2. Vitest/Vite publish non-major security fixes that can be adopted without breaking engine policy
3. Next scheduled security audit window is reached (latest by 2026-04-04)

## Fixed Review Commands

```bash
npm audit --omit=dev --json
npm audit --json
npm view vitest@4 engines --json
```
