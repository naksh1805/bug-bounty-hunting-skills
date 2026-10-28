# Reference 09 — Severity Rubric (P1–P4)

Classify every confirmed finding with bug-bounty-standard, impact-based
severity. Severity is about **real-world impact** — what an attacker actually
gains — not about how clever the bypass was. When a finding plausibly sits on a
boundary between two ratings, rate by the concrete demonstrated impact, and note
the escalation path if one exists.

Output is strictly P1 / P2 / P3 / P4. No CVSS vectors, no remediation essays in
the default report (add them only if the user asks).

## P1 — Critical

Severe, broad, or trivially-exploitable compromise. Any of:

- Cross-tenant / cross-org access to another customer's **sensitive** data (PII,
  credentials, billing, private documents) with no auth or via a simple ID swap.
- Full **account takeover**.
- Escalation to **admin/owner on another org/tenant**.
- **Mass data exposure** across many accounts through a single bypass.
- Unauthorized **write or delete on another tenant's** data.

Signal: "an attacker with a free account (or none) can read/modify other
customers' data, or take over accounts, at will."

## P2 — High

Serious impact, but bounded (single-user, or needs a valid low-priv account). Any
of:

- **Horizontal IDOR** exposing another user's sensitive data within scope (not
  full account takeover).
- **Vertical privilege escalation** to perform admin/owner actions — change a
  role, delete org resources, invite an admin — as a lower-privileged user.
- **Mass assignment** that grants elevated privileges (e.g. self-promote to admin
  via an injected `role` field).

Signal: "a logged-in low-priv attacker can reach one other user's sensitive data
or perform privileged actions they shouldn't."

## P3 — Medium

Real access-control gap, limited impact. Any of:

- **IDOR exposing limited or non-sensitive data** (metadata, a resource that
  isn't high-value).
- Privilege escalation with **limited real-world impact** — e.g. can *view* a
  restricted thing but not modify it.
- An access-control bug that requires **unusual preconditions** to exploit.

Signal: "the boundary is broken, but what leaks or what you can do is minor, or
it's hard to reach."

## P4 — Low

Minor, often informational. Any of:

- Minor **information disclosure** via an access-control gap — e.g. confirming a
  resource or user **exists** (enumeration) without exposing real data.
- Access-control issues with **negligible impact** or requiring significant
  additional steps to matter.

Signal: "technically an authz gap, but the attacker learns or gains almost
nothing."

## Deciding quickly

Ask, in order:

1. **Whose data/action?** Another *tenant's* → leans P1. Another *user's* in the
   same tenant → leans P2. The subject's own / public → not a finding.
2. **Read or write?** Unauthorized *write/delete* on others' data → up a notch
   (P1 cross-tenant, P2 same-tenant). Read-only → as above but not higher.
3. **How sensitive?** PII / credentials / billing / private docs → higher.
   Metadata / existence only → P3/P4.
4. **How many / how easy?** One trivial bypass exposing *many* accounts, or
   no-auth required → P1. Needs a valid account and hits one user → P2/P3.
5. **Escalation path?** If a P3-looking read is the first step to account
   takeover, rate by the realistic end state and say so.

## Examples

- No-auth `GET /api/v2/orgs/{id}/invoices/{id}` returns any org's billing →
  **P1** (cross-tenant sensitive data, no auth, simple ID swap).
- Low-priv member `PATCH`es `{"role":"admin"}` on their own membership and
  becomes org admin → **P2** (mass-assignment vertical escalation).
- Bob reads Alice's order *history list* (same org) by swapping `userId` →
  **P2** (horizontal IDOR, sensitive-ish).
- Any logged-in user can read another user's *display name and avatar URL* via
  IDOR → **P3** (limited data).
- Unauthenticated request confirms whether an email is registered (different
  response for exists vs. not) → **P4** (existence disclosure).

Confirmed + classified findings go into `templates/finding.md` and are assembled,
P1 → P4, in `templates/final-report.md`.
