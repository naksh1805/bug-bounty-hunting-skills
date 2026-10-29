# Reference 05 — The Test Matrix

This is the engine of the skill. For each queued request (as a shape, with its
model from `references/04-request-analysis.md`), replay it across three axes and
compare every result against the authorized known-good / known-bad baseline.

Axes compose: **for each identity (5a), run each method (5b), and on anything
that's still denied, try each technique (5c).** The cross-reference pass (5d) is
an extra lens, not a substitute.

Keep `references/06-bypass-cheatsheet.md` open as a fast lookup, and keep to the
scope locked in `references/01-scope-discovery.md` throughout.

## 5a. Identity axis — *who* sends the request

Replay the request as each of these senders:

- **No auth at all.** Strip the session cookie / token / auth header entirely.
  Tests unauthenticated access to an endpoint that should require login.
- **Same-org, lower-privilege user → another user's / the owner's resource.**
  Bob (low-priv member) acts on Alice's (owner's) resource within the same org.
  Catches horizontal access + intra-org vertical escalation.
- **Lower-priv user → admin/owner-only endpoint directly (forced browsing).**
  Bob hits `/admin/*`, role-change, delete-org-resource endpoints that the UI
  only shows to admins. Pure vertical escalation.
- **Custom-role user → each boundary that role should be denied.** If the program
  has granular roles (billing-only, read-only, support, etc.), probe each
  permission the role is *supposed* to lack.
- **Another org/tenant's user → this org's resource by ID.** Carol (Org B owner)
  requests an Org A resource by its ID. **Do this for every object-with-ID
  endpoint** — cross-tenant IDOR is the highest-value category of bug here.
- **Resource owner's own valid session, but with a forced/tampered resource
  ID.** Alice uses her real session but points the request at Carol's resource.
  This confirms the flaw is specifically broken access control (the server
  doesn't check ownership) and not merely "any logged-in session is accepted."

For each, the question is binary against the baseline: did a sender who *should*
be denied receive the authorized resource/action?

## 5b. Method axis — *how* the verb is set

This is a **mandatory baseline for every request**, not just a bypass trick. For
every shape, regardless of the method it was captured as, test the full relevant
method set for each identity in 5a:

- **GET, POST, PUT, PATCH, DELETE** — the CRUD surface.
- **OPTIONS** — ask the server what it *claims* is allowed (the `Allow` /
  `Access-Control-Allow-Methods` response). A discrepancy between what OPTIONS
  advertises and what the UI uses is a lead.

A server that accepts `PATCH` or `DELETE` on a resource for an identity that
only ever saw `GET` in the UI is itself a finding — the method is an access
boundary the backend forgot to enforce. Destructive verbs (PUT/PATCH/DELETE)
are tested the same as any other method — every identity in the matrix is an
account the user controls, so there's no extra gate before firing them.

## 5c. Technique axis — *further manipulation*

Run these against any identity/method combination that **failed** the baseline
check (returned 401/403/404), to see if any flips it into a real 200-with-data.
These only matter when the straight attempt was denied; if the straight attempt
already succeeded, you already have the finding.

- **ID manipulation** — increment/decrement; swap to another known-valid ID; try
  `0`, negative, and non-existent IDs; UUID-vs-sequential confusion if both
  exist; different casing of the ID.
- **Encoding tricks** — URL-encode and double-URL-encode the ID or path;
  hex/unicode/overlong-UTF-8; base64-wrap; `%00` null-byte suffix.
- **Path tricks** — add/remove trailing slash; change path case; insert `/./`,
  `..;/`, `%2e%2e/`, or duplicate slashes; append a fake extension (`.json`); try
  the same resource under a different API version or surface (`/v1/` vs `/v2/`
  vs `/internal/`).
- **Method-override headers** — `X-HTTP-Method-Override`, `X-Method-Override`,
  `X-HTTP-Method` layered on top of the raw method swap in 5b (a front-end that
  blocks `DELETE` may honor a `POST` carrying an override header).
- **Trusted-header spoofing** — forge `X-Forwarded-For`, `X-Forwarded-Host`,
  `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Scheme`, `Referer`, and
  internal-looking `X-Admin` / `X-Debug` / `X-Internal` style headers; also try
  *removing* the auth header while keeping a different "trusted" header the
  server might wrongly rely on.
- **Mass assignment / body injection** — add extra JSON fields the response
  schema hints at but the request doesn't normally send: `role`, `isAdmin`,
  `permissions`, `orgId`, `userId`, `ownerId`, `plan`, `verified`, `status`; flip
  booleans (`true`↔`false`). Tests whether the backend trusts client-supplied
  privilege fields.
- **Parameter pollution** — send the identifying param twice (one valid, one
  attacker-controlled) in the query string, in the form body, and in JSON (array
  form) to discover which value the backend actually honors.
- **JSON structure tricks** — wrap a single value in an array; nested object vs.
  flat field; key-casing variants (`userId` / `userID` / `UserId`); type
  confusion (string vs. integer vs. array of IDs).
- **GraphQL** — see `references/07-graphql-authz.md` for field-level authz,
  batched queries, introspection, and global-ID IDOR.
- **Response-trust check** — if an access decision appears to be enforced only
  client-side (the UI hides a control, but the API has no server-side check),
  that's still a valid BAC finding. Confirm by firing the raw request directly
  with an identity that shouldn't have the control.

## 5d. Cross-reference known public patterns

Before/while testing a given endpoint *category* — REST object endpoint, GraphQL
resolver, invite/role-change flow, billing endpoint, SSO/SAML-linked account
flow, file/attachment download, export/report generator — recall documented
bypass patterns from public disclosed reports for that category and apply any not
already covered in 5b/5c. Treat this as an extra pass layered on top of the
systematic matrix, never as a replacement for it.

## Running the matrix efficiently

- Use `scripts/replay.py` to fire one shape across the identity set and method
  set and diff the responses (status, length, markers) in one shot.
- Record each attempt's outcome against the baseline. A "candidate" is any
  should-be-denied sender that got the known-good shape. Candidates go to Step 4
  (`references/08-confirmation.md`) before they're ever called findings.
- Once you've shown bob can read *one* of alice's invoices he shouldn't, you
  have the IDOR — you don't need to enumerate every reachable ID to prove the
  class, though `scripts/replay.py` has no built-in limit if you want to map the
  reachable range.
