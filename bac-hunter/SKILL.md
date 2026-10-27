---
name: bac-hunter
description: "Use this skill when the user provides Burp Suite traffic (HTTP history/export), a bug bounty or VDP program URL, and test identities, and requests Broken Access Control testing such as IDOR, privilege escalation, mass assignment, or forced browsing. The skill does not crawl targets; it uses user-provided traffic and derives scope from the program URL."
---

# Broken Access Control (BAC) Hunter

## What the user provides vs. what this skill does itself

User provides (never ask them to do more than this):
- Full Burp Suite traffic / HTTP history export (already crawled manually by the user — never crawl the site yourself).
- The bug bounty / VDP **program URL** (e.g. the HackerOne/Bugcrowd/program policy page).
- A list of test identities: for each one, user ID/username + password + intended role/permission level (e.g. Owner, Admin, lower-priv member, custom-role user, another-org/tenant user).

This skill itself does:
- **Scope discovery** — fetch/read the program URL and derive in-scope domains, endpoints, asset types, and anything explicitly out-of-scope or disallowed. Re-check scope before testing anything; when scope is ambiguous for a given host/path, treat it as out-of-scope and skip it rather than guessing.
- **Session acquisition** — find the login request(s) in the Burp traffic, and for each given identity, replay the login flow with that identity's credentials to obtain a valid session (cookie/token). Validate each session against a known authenticated endpoint (e.g. a profile/me request) before using it. If a session stops working mid-testing (expired/invalidated), re-run the same login replay for that identity to mint a fresh one and continue — don't stop and ask unless login itself is failing (bad credentials, MFA block, CAPTCHA, account locked), in which case flag it to the user for that specific identity and continue testing with the identities that do work.

## Step 1 — Build the worklist from Burp history
Go through the full Burp history and queue **every in-scope request** for testing. Default is to test it, not to skip it. Only drop a request when it clearly has no access-control surface:
- Out-of-scope per the program URL's scope.
- Pure static assets (JS/CSS/images/fonts/sourcemaps) with no parameters and no data in the response.
- Third-party calls with no bearing on the application's own authorization (pure analytics/telemetry beacons, ad/tracking pixels) — not endpoints that merely render UI, since a UI-driving endpoint can still leak or modify data.
- Exact duplicate requests already queued earlier (identical method + path + param/body shape) — queue the unique shape once, not every repeated capture.

When unsure whether a request "has a use case" for BAC testing, queue it anyway — the cost of testing a harmless endpoint is low, the cost of skipping a real one is a missed bug.

## Step 2 — Understand each request before touching it
For the request under test, build a clear mental model before firing anything:
- What does this request *do* (read/write/delete/invite/change-role/etc.)?
- Where does the "identity" of the target resource live — path param, query param, JSON body field, a header, or is it implicit from the session/cookie only?
- What auth material is present — session cookie, Bearer/JWT, API key, CSRF token — and which of these actually gates access vs. which is just bookkeeping?
- What does a *successful, authorized* response look like (status code + body shape), so you can tell a true-positive bypass apart from a generic error page, redirect-to-login, or empty/null response that only *looks* like success.

## Step 3 — Test matrix (run this for every queued request)
For each request, replay it across **every available identity**, and for each identity run the full method set and the bypass techniques below. Always compare against the baseline "known-good, known-bad" response from Step 2.

### 3a. Identity axis (who is sending the request)
- **No auth at all** (strip session/token/cookie entirely) — unauthenticated access check.
- **Same-org, lower-privilege user** acting on another user's / the owner's resource — horizontal + vertical priv-esc.
- **Lower-priv user** hitting admin-only / owner-only endpoints directly (forced browsing / vertical).
- **Custom-role user** (if the program has granular roles) — check each permission boundary that role is supposed to be denied.
- **Another org/tenant's user**, same role, hitting this org's resource by ID — cross-tenant IDOR (do this for every object-with-ID endpoint, it's the highest-value category of bug).
- **Target user's own valid session**, but with a tampered/forced resource ID — confirms the vuln isn't just "any session works," it's specifically access-control that's broken.

### 3b. Method axis (mandatory baseline, not just a bypass trick)
For every request, regardless of what method it was originally captured as, test it with the full relevant method set — **GET, POST, PUT, PATCH, DELETE**, plus **OPTIONS** to enumerate what the server claims is allowed. This is run for every identity in 3a, not only as a one-off bypass attempt. A server that allows PATCH or DELETE on a resource for an identity that only ever saw GET in the UI is itself a finding.

### 3c. Bypass technique axis (how you further manipulate the request)
Run these against any identity/method combination that failed the baseline check, to see if any of them flip a 401/403/404 into a 200 with real data:
- **ID manipulation:** increment/decrement, swap to another known valid ID, try 0/negative/non-existent, UUID vs sequential-id confusion if both exist, try the ID in a different casing.
- **Encoding tricks:** URL-encode / double-URL-encode the ID or path, hex/unicode/overlong-UTF8 encode, base64 wrap, null-byte / `%00` suffix.
- **Path tricks:** add/remove trailing slash, path case change, `/./`, `..;/`, `%2e%2e/`, duplicate slashes, append a fake extension (`.json`), try the same resource under a different API version (`/v1/` vs `/v2/` vs `/internal/`).
- **Method override headers:** `X-HTTP-Method-Override` / `X-Method-Override` on top of the raw method swap in 3b.
- **Header manipulation:** add/forge `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Referer`, `X-Forwarded-Scheme`, internal-looking `X-Admin`/`X-Debug`/`X-Internal` style headers; try removing the auth header but keeping a different "trusted" header.
- **Body / mass-assignment:** add extra JSON fields the response schema hints at but the request doesn't normally send — `role`, `isAdmin`, `permissions`, `orgId`, `userId`, `ownerId`, `plan`, `verified`, `status` — and flip booleans (`true`↔`false`), to see if the backend trusts client-supplied privilege fields.
- **Parameter pollution:** send the identifying param twice (once valid, once attacker-controlled) in query string, form body, and JSON (array form) to see which value the backend actually honors.
- **JSON structure tricks:** array wrapping a single value, nested object vs flat field, key-casing variants (`userId` vs `userID` vs `UserId`), type confusion (string id vs integer id vs array of ids).
- **GraphQL-specific (if applicable):** test field-level authorization independent of the top-level query/mutation name; try batched queries to reach an otherwise-rate-limited or hidden resolver; check if introspection exposes admin-only mutations/fields worth targeting; test IDOR via `id`/`node(id:)` global-id style arguments across org boundaries.
- **Response-trust check:** if any access decision looks like it's enforced client-side (e.g., UI hides a button but the API itself has no server-side check), that's still a valid BAC finding — confirm by firing the raw request directly.

### 3d. Cross-reference with public writeups
Before/while testing a given request type (REST object endpoint, GraphQL resolver, invite/role-change flow, billing endpoint, SSO/SAML-linked account flow, etc.), recall known bypass patterns from public disclosed reports for that category of endpoint, and apply any that weren't already covered in 3b/3c. Treat this as an extra pass, not a replacement for the systematic matrix above.

## Step 4 — Confirm before reporting (kill false positives)
A finding only counts if, for an identity/method combination that should be denied:
- The response status is a real success (200/201/204 etc., not a 200 that actually wraps an error body).
- The response body contains genuine target-resource data, or the write/delete action demonstrably took effect (not an empty object/array, not a generic "not found" dressed as 200).
- It's reproducible on a clean replay (re-send once to rule out a fluke/cache hit).
- The impacted data/action genuinely belongs to someone else or to an action outside that identity's role — re-confirm resource ownership against what you learned in Step 2.

Do not report the same underlying bug twice because the same endpoint+method+bypass combination appeared on multiple near-identical requests in the Burp history — report it once.

## Step 5 — Severity classification (P1–P4 only)
Use bug-bounty-standard impact-based severity. Output **only** the P-rating + one-line description of the bug per finding — nothing else is needed in the final report (no remediation essays, no CVSS breakdowns, unless the user asks).

- **P1 (Critical):** Cross-tenant/cross-org access to another customer's sensitive data (PII, credentials, billing, private documents) with no auth or via simple ID swap; full account takeover; ability to escalate to admin/owner on another org; mass data exposure across many accounts via a single bypass; unauthorized write/delete on another tenant's data.
- **P2 (High):** Horizontal IDOR exposing another user's sensitive data within scope (not full account takeover); vertical privilege escalation to perform admin/owner actions (role change, delete org resources, invite admin) as a lower-priv user; mass assignment that grants elevated privileges.
- **P3 (Medium):** IDOR exposing limited/non-sensitive data; privilege escalation with limited real-world impact (e.g., can view but not modify); access-control bug that requires unusual pre-conditions to exploit.
- **P4 (Low):** Minor information disclosure via access-control gap (e.g., confirming existence of a resource/user without exposing real data); access-control issues with negligible impact or requiring significant additional steps to matter.

## Output format
For each confirmed finding, report:
1. Severity: P1 / P2 / P3 / P4
2. Endpoint + method
3. One-line description of the bypass and impact (which identity, which technique from Step 3, what was exposed/modified)

Nothing else — no extra commentary, no non-BAC bug classes (keep scope strictly to BAC: IDOR, horizontal/vertical priv-esc, mass assignment, forced browsing, and other authorization bypasses), unless the user explicitly asks for more detail on a specific finding.
