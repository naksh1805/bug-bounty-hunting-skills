# Reference 01 — Scope Discovery

Goal: turn the program URL into an explicit, machine-usable scope you can check
every request against. Scope is the boundary of your authorization. Getting it
wrong in the permissive direction is the single worst mistake in this workflow —
it turns authorized research into an unauthorized intrusion.

## 1. Read the program URL

Fetch and read the program/policy page the user gave you. Depending on the
platform it will be one of:

- A HackerOne / Bugcrowd / Intigriti / YesWeHack program policy page.
- A self-hosted `/security`, `/security.txt` (`.well-known/security.txt`), or a
  responsible-disclosure / VDP page.
- A program brief the user pasted.

Extract, explicitly:

- **In-scope assets** — domains, subdomains, wildcard patterns
  (`*.example.com`), specific apps, API hosts, mobile backends, IP ranges.
- **Out-of-scope assets** — hosts/paths/subdomains explicitly excluded, plus
  third-party services the program says it does not own.
- **In-scope vulnerability classes** — confirm BAC/IDOR/authz is eligible. Some
  programs exclude certain classes or certain endpoints.
- **Rules of engagement** — automation/scanning limits, rate caps, required
  test-account usage, "no testing against prod data" clauses, header/marker
  requirements (some programs ask you to send an identifying header like
  `X-Bug-Bounty: <handle>`), and any "do not" list (no DoS, no social
  engineering, no automated fuzzing, no accessing other users' data beyond
  minimal proof, etc.).

Write these into the identity/worklist tracking so they are visible while you
test. If the program requires an identifying header on all traffic, add it to
every request you send.

## 2. Build an allowlist and a denylist

Produce two concrete lists:

```
IN  = [ example.com, *.example.com, api.example.com, app.example.com ]
OUT = [ blog.example.com, status.example.com, *.marketing.example.com,
        anything on a domain example.com doesn't own ]
```

Normalize wildcards into a matcher you apply per host. A request is testable
only if its host matches `IN` and does **not** match `OUT`.

## 3. The ambiguity rule

When scope is unclear for a given host or path — it isn't clearly listed either
way, the wildcard is ambiguous, or you can't tell who owns the asset — **treat
it as out-of-scope and skip it.** Do not guess in the permissive direction.
Note the skipped item so the user can clarify with the program if they want it
covered.

Common ambiguity traps:

- A subdomain that resolves to a third-party SaaS (support desk, status page,
  marketing platform) — usually out of scope and not the program's to authorize.
- An apex vs. `www` vs. API host distinction the policy doesn't spell out.
- Staging/dev hosts (`staging.`, `dev.`, `uat.`) — often explicitly out of
  scope; never assume they're fair game just because they're reachable.
- Links the traffic follows off-site (CDNs, auth providers, payment providers) —
  out of scope; the program can't authorize you against someone else's service.

## 4. Re-check scope per request

Scope discovery is not a one-time gate. Before you test any individual request
in Step 3, re-confirm its host/path is in-scope. The Burp export will contain
plenty of off-target traffic (third-party calls, redirects, embedded widgets);
the per-request re-check is what keeps those out of your testing.

## 5. Output of this step

- `IN` allowlist + `OUT` denylist (host matchers).
- Eligible-class confirmation (BAC is in scope).
- Rules of engagement notes: rate/automation limits, required markers,
  destructive-action restrictions, prod-data clauses.
- A list of anything skipped for scope ambiguity, for the user to clarify.

Only once this exists do you move on to session acquisition and the worklist.
