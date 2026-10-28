# Reference 02 — Session Acquisition

Goal: for each test identity the user supplied, obtain a **valid, validated**
session by replaying the login flow found in the Burp traffic, and keep it live
for the duration of testing. Clean sessions are what make the identity axis in
Step 3 trustworthy — if you're unsure whether an identity is really
authenticated, every result for it is noise.

Only ever authenticate with the identities the user explicitly provided. These
are accounts they control or were given for the engagement. Never reuse a real
third party's session captured in the traffic, and never try to brute-force,
guess, or reset credentials you weren't given.

## 1. Find the login flow in the traffic

Locate the authentication request(s) in the Burp history. It may be:

- A classic form POST (`/login`, `/signin`, `/session`) returning a
  `Set-Cookie`.
- A JSON API login (`/api/auth/login`) returning a token in the body
  (`access_token`, `jwt`, `id_token`) and/or a cookie.
- A multi-step flow: fetch a login page → read a CSRF/nonce token → POST
  credentials → receive session → maybe exchange for a Bearer token.
- An SSO/OIDC/SAML redirect chain. These are often **out of scope** (the IdP
  isn't the program's asset) and can involve MFA. If the only path to a session
  is through a third-party IdP with MFA/CAPTCHA, treat it as a login-blocked
  identity (see §5) rather than trying to automate the IdP.

Capture, for each identity, exactly which requests constitute "log in and become
authenticated," including any pre-request token fetch.

## 2. Replay login per identity

For each identity, replay the captured login flow substituting that identity's
credentials. Preserve everything the flow actually needs:

- Fresh **CSRF/anti-forgery tokens** — many login POSTs require a token scraped
  from the preceding GET. Fetch it fresh each time; a stale token yields a
  spurious failure that looks like bad credentials.
- Correct `Content-Type` and body encoding (form vs. JSON).
- Any device/fingerprint or `Origin`/`Referer` headers the server checks.

From the login response, extract the session material:

- **Cookies** — store the whole jar; the session may span several cookies.
- **Bearer/JWT tokens** — store the token and note where it goes
  (`Authorization: Bearer …`, or a custom header).
- **CSRF token for subsequent state-changing requests** — often different from
  the login CSRF token; capture the one used by authenticated write requests.

## 3. Validate every session before using it

Do not trust a 200 on the login response alone. Confirm the session actually
represents that identity by hitting a **known-authenticated probe** — a
`/me`, `/profile`, `/account`, or dashboard-data endpoint seen in the traffic —
and checking the response identifies the right account (right user ID, email,
org, role). Record this probe per identity in `templates/identities.md`; you'll
reuse it to detect expiry.

A session that returns the *wrong* identity on the probe, or an anonymous
response, is not usable — re-check your login replay before proceeding.

## 4. Refresh on expiry, don't stall

Sessions expire or get invalidated mid-run (idle timeout, rotation, server
restart, hitting a logout path by accident). When a request that should be
authorized suddenly returns a login redirect / 401 and the identity probe also
fails, **re-run that identity's login replay to mint a fresh session and
continue.** This is routine; don't stop and ask the user for it.

Build this as a small helper: "before (or on failure of) a test request,
confirm the probe; if it fails, re-login once, then retry." `scripts/replay.py`
takes session material per identity and you can refresh it between batches.

## 5. When login genuinely fails

Stop and flag to the user **only for the specific identity** when login itself
can't be completed:

- Bad/expired credentials (verify you used the right ones first).
- MFA / OTP challenge you can't satisfy.
- CAPTCHA or bot-detection on the login flow.
- Account locked or disabled.

Report which identity is blocked and why, then **continue testing with the
identities that do authenticate.** A blocked other-tenant user, say, shouldn't
stop you from running every other identity against the worklist. Note in the
final report which identities were unavailable, since it bounds what was tested.

## 6. Identity hygiene for the matrix

Keep the identities clearly separated so Step 3 is unambiguous:

| Identity | Role | Session carrier | Auth probe | Owns (for IDOR targets) |
|----------|------|-----------------|------------|--------------------------|
| alice    | Owner (Org A) | cookie jar A | GET /api/me → alice | Org A resources |
| bob      | Member (Org A, low-priv) | cookie jar B | GET /api/me → bob | Bob's own resources |
| carol    | Owner (Org B) | Bearer token C | GET /api/me → carol | Org B resources |
| (none)   | unauthenticated | — | — | — |

This table is the backbone of the identity axis: "can bob reach alice's
resource?", "can carol reach Org A's resource?", "can no-auth reach any of it?".
Keeping track of who legitimately owns what is also how you confirm, in Step 4,
that a bypass really crossed an ownership boundary.
