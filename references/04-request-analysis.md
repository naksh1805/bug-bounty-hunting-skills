# Reference 04 — Modeling a Request Before Testing It

Goal: before firing anything at a request, build a clear mental model of it. Most
false positives and wasted effort come from testing blind. Five minutes of
modeling per shape makes the matrix in Step 3 sharp and makes confirmation in
Step 4 trivial.

Answer four questions for the request under test.

## 1. What does this request *do*?

Classify the action, because it determines both the risk and how you'll safely
prove impact:

- **Read** — returns a resource or list (`GET /api/orders/{id}`). IDOR here
  exposes data; proof is "I received someone else's data."
- **Write (create/update)** — `POST`/`PUT`/`PATCH`. IDOR/priv-esc here modifies
  data; proof should be non-destructive where possible (see
  `references/10-responsible-testing.md`).
- **Delete** — removes a resource. Highest blast radius; prove via a
  self-controlled victim, never by deleting a real user's data.
- **Privileged action** — invite user, change role, transfer ownership, change
  billing/plan, toggle a feature flag, impersonate. These are the vertical
  privilege-escalation targets.

## 2. Where does the target resource's identity live?

Find every place the request names *which* resource/user it acts on — this is
what you'll tamper with:

- **Path param** — `/api/orders/1001`, `/users/42/settings`.
- **Query param** — `?orderId=1001`, `?account=42`, `?org=7`.
- **Body field** — `{"orderId": 1001}`, `{"targetUserId": 42}`.
- **Header** — a tenant/org selector like `X-Org-Id`, or an ID baked into a
  custom header.
- **Implicit from session only** — the server derives the resource from the
  authenticated identity (`GET /api/me/orders`) with no client-supplied ID. These
  are *lower* IDOR risk on the surface, but check whether an optional override
  param is silently honored (e.g. `GET /api/me/orders?userId=42`).

An endpoint can carry the identity in more than one place at once — note all of
them; parameter pollution (Step 3) exploits exactly that.

## 3. Which auth material actually gates access?

List everything auth-ish on the request, then reason about which piece the
server actually checks:

- **Session cookie / Bearer / JWT** — the primary gate, usually.
- **CSRF token** — anti-forgery bookkeeping, not an access-control gate.
  Removing it should break *writes*, but its presence doesn't prove authz is
  enforced.
- **API key** — may gate access, may just identify the client/app.
- **Custom headers** — some are load-bearing (a tenant selector), many are not.

The key experiment this sets up: **strip or swap each piece independently** and
see which one, when changed, actually changes the authorization outcome. A
server that returns the resource with the auth cookie *removed* but a CSRF token
present is trusting the wrong thing.

## 4. What does authorized success look like?

Capture the ground truth so you can tell a true bypass from a decoy. For the
request sent by its **legitimate owner** (the right identity), record:

- Status code (200/201/204…).
- Response shape — key fields, a sample of values, approximate body length, and
  a stable marker (an ID, email, or object name you can match on).
- And the **known-bad** baseline: the same request sent by an identity that
  *should* be denied, so you know what a correct denial looks like
  (401/403/404, a specific error body, a redirect to login).

With both a known-good and a known-bad response in hand, a bypass is
unmistakable: a should-be-denied identity receiving the known-good shape with
real data. This is the comparison every step of the matrix is measured against,
and it's what kills the most common false positive — a `200 OK` whose body is
actually an error, an empty list, or a generic "not found."

## Output of this step

Per shape, a short model:

```
Shape:    GET /api/orgs/{orgId}/invoices/{invoiceId}
Action:   read (sensitive — billing)
Resource id lives in: path (orgId, invoiceId)
Auth gate: session cookie (CSRF present but not a gate for GET)
Owner baseline (alice→Org A): 200, {invoiceId, amount, lineItems[...]}, ~4KB, marker invoice#INV-A-1001
Denied baseline (bob→alice's invoice): 403, {"error":"forbidden"}
IDOR attempt: bob & carol & no-auth → alice's invoiceId; alice → carol's invoiceId
```

Carry this into the matrix.
