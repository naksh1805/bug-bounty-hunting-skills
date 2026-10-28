# BAC Testing — Findings Report

**Target / program:** `<program name + URL>`
**Date:** `<YYYY-MM-DD>`
**Scope tested:** `<in-scope hosts actually covered>`
**Identities used:** `<handles + roles>` (login-blocked: `<handles, reason>` or none)

---

## Findings (sorted P1 → P4)

> Default format per finding: **Severity — `METHOD /endpoint` — one-line impact.**
> Nothing else unless the user asks for detail on a specific finding.

### P1 — Critical
- **P1 — `METHOD /endpoint`** — `<identity>` via `<technique>` `<exposed/modified what>`.

### P2 — High
- **P2 — `METHOD /endpoint`** — `<identity>` via `<technique>` `<exposed/modified what>`.

### P3 — Medium
- **P3 — `METHOD /endpoint`** — `<identity>` via `<technique>` `<exposed/modified what>`.

### P4 — Low
- **P4 — `METHOD /endpoint`** — `<identity>` via `<technique>` `<exposed/modified what>`.

*(Omit any severity band with no findings.)*

---

## Coverage note
- **Shapes tested / total queued:** `<n>/<m>` (see worklist).
- **Not covered, and why:** out-of-scope skips, scope-ambiguity skips (for the
  user to clarify with the program), login-blocked identities, endpoints that
  couldn't be reached.
- This bounds the result: "no finding" on an untested shape means untested, not
  secure.

---

## Appendix — detailed findings (only if requested)
For each finding, the full `templates/finding.md` record: class, attacker→victim,
technique, reproduction, minimized evidence, confirmation checklist, severity
rationale.
