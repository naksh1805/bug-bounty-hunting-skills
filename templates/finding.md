# Finding — <short title>

> One confirmed BAC finding. Keep the default report terse (severity + endpoint +
> one-line impact). The extra fields below are your working record and the
> evidence a program triager will want; include as much as the user asks for.

**Severity:** P1 | P2 | P3 | P4
**Endpoint + method:** `METHOD /path/{param}`
**Impact (one line):** which identity, via which technique, reached/modified what
that they shouldn't have.

---

## Class
IDOR (horizontal) | IDOR (cross-tenant) | Vertical privilege escalation | Mass
assignment | Forced browsing | Other authz bypass

## Attacker identity → victim resource
- **Sender:** `<handle>` (`<role>`, `<tenant>`), or unauthenticated
- **Target resource/action:** `<what, owned by whom>` (owner `<handle>`,
  `<tenant>`)
- **Boundary crossed:** horizontal (other user) | vertical (higher privilege) |
  cross-tenant (other org) | unauthenticated

## Technique
Which axis/technique from `references/05-test-matrix.md` produced it (e.g. "ID
swap in path param", "injected `role:admin` in body", "`X-Original-URL` to reach
`/admin`", "GraphQL `node(id:)` with re-encoded global ID").

## Reproduction
1. Authenticate as `<sender>` (or send no auth).
2. Send:
   ```http
   METHOD /path/{tampered} HTTP/1.1
   Host: <in-scope host>
   <relevant auth / tampered header>

   <tampered body, if any>
   ```
3. Observe: `<status>` with `<marker proving victim's data / the effect>`.

## Evidence
- **Bypass response:** status + the matching marker + the saved full body
  (`scripts/replay.py` writes one to `./evidence/` per identity/method by default).
- **Authorized baseline (owner):** `<status + shape>`
- **Denied baseline (should-be-denied, pre-bypass):** `<status + error>`

## Confirmation checklist (`references/08-confirmation.md`)
- [ ] Real success status (not a 200 wrapping an error)
- [ ] Genuine victim data returned / write-delete demonstrably effected
- [ ] Reproducible on a clean replay
- [ ] Target genuinely belongs to someone else / outside sender's role
- [ ] Not a duplicate of an already-reported root cause

## Severity rationale (`references/09-severity-rubric.md`)
Whose data/action, read vs. write, sensitivity, reach/ease, escalation path.
