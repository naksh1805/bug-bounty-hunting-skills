# Reference 08 — Confirming Findings / Killing False Positives

A candidate from the matrix is not a finding until it survives confirmation. BAC
testing produces a lot of decoys — `200`s that are really errors, empty lists,
cached responses, generic not-founds — and reporting those burns your
credibility with the program and wastes the triager's time. Confirm every
candidate here before it goes in the report.

## The four confirmation gates

A candidate counts only if, for an identity/method combination that **should be
denied**, all of these hold:

1. **Real success status.** 200/201/204/etc. that genuinely reflects success —
   **not** a `200 OK` whose body is an error, a login page, a redirect, or a
   `{"error": ...}`. Check the body, not just the status line.
2. **Genuine target data or a real effect.** For reads: the response contains
   the *actual* target resource's data (match the marker you recorded in
   `references/04-request-analysis.md` — the specific ID/email/object name that
   belongs to the other owner). For writes/deletes: the action *demonstrably took
   effect* — confirmed by a follow-up read, a state change you can observe, or
   the documented side effect — **not** an echoed-back request, an empty object,
   or a "queued/accepted" that never actually happens. An empty array or a
   generic not-found dressed as 200 is **not** data.
3. **Reproducible.** Re-send the request once on a clean replay to rule out a
   fluke, a cache hit, or a race. A one-off that doesn't reproduce isn't a
   finding (yet) — note it and move on, or investigate the condition.
4. **Genuinely cross-boundary.** Re-confirm, against the ownership map from
   `references/02-session-acquisition.md`, that the data/action really belongs to
   someone else or is outside that identity's role. "Bob can read order 1001"
   only matters if 1001 is *alice's* order, not an order bob co-owns or a public
   resource. This is the gate that separates a true IDOR from "the resource was
   shared/public all along."

## Common false positives, by cause

- **Soft 200 errors.** API returns `200` with `{"success": false}` or an error
  envelope. → Read the body; it's a denial.
- **Decoy data.** Endpoint returns a stub, a default object, or *your own* data
  regardless of the ID you sent (the ID param is ignored and the server uses the
  session). → Your marker won't match the victim; it's not IDOR.
- **Empty success.** `200 []` or `200 {}` for a resource that should have
  content. → No data exposed; not a finding.
- **Public-by-design.** The resource is intentionally public (a published
  profile, a shared link). → Not a boundary crossing.
- **Cache/CDN hit.** A cached copy returns to an unauthorized caller but the
  origin would deny. → Reproduce with cache-busting; confirm the origin actually
  serves it.
- **Reflected input.** A write "succeeds" by echoing your payload but nothing
  persisted. → Follow-up read shows no change; not a real write.
- **Self-owned resource.** You attacked an ID you actually have rights to. →
  Check the ownership map.
- **Already-denied straight, still denied after tricks.** A technique "changed"
  the status but to another denial (403→404, say). → Not access granted.

## Non-destructive confirmation

Confirming a *write/delete* IDOR means showing the action took effect — but you
must do that without harming a real user's data (see
`references/10-responsible-testing.md`). The clean way:

- Set up **two accounts you control** (victim = your own second account). Prove
  that attacker-account can modify/delete victim-account's resource. The effect
  is real, reproducible, and harms no third party.
- If you can only reach a *real* third party's resource, stop at the
  authorization decision: demonstrate you received a success/authorized response
  (and, for reads, minimal evidence of the data) rather than actually destroying
  or altering their data. Note in the finding that impact was confirmed to the
  point of the authz bypass and not exercised further, for safety.

## Deduplicate

Do **not** report the same underlying bug twice because the same
endpoint+method+bypass appeared on many near-identical captures in the Burp
history, or across several IDs of the same shape. One root cause = one finding.
If several *distinct* endpoints share a root cause (e.g. a whole `/api/v2/*`
family misses tenant checks), you can report the pattern once and list the
affected endpoints under it, rather than filing N copies.

## Evidence to keep

For each confirmed finding, retain the minimum that proves it (for the report and
for the program's triage):

- The exact request that bypassed (method, URL, the tampered parameter/header/
  body, which identity's session).
- The response proving impact — status + the matching marker, trimmed. **Redact
  or minimize** any real third-party PII; capture just enough to prove the class
  and impact, never a bulk dump.
- The baseline it's being compared against (owner's authorized response and the
  denied response), so the triager sees the delta.

Confirmed findings proceed to `references/09-severity-rubric.md`.
