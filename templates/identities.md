# Identity Table

Fill one row per test identity the user supplied, after acquiring and validating
its session (`references/02-session-acquisition.md`). This table is the backbone
of the identity axis in the test matrix and the ownership map used to confirm
findings.

> Only list identities the user is authorized to use (accounts they control or
> were issued for the engagement). Do not record real third-party credentials.

| handle | role / privilege | tenant/org | session carrier | auth probe (known-authed endpoint) | legitimately owns (IDOR target set) | session status |
|--------|------------------|-----------|-----------------|-------------------------------------|-------------------------------------|----------------|
| alice  | Owner            | Org A     | cookie jar      | `GET /api/me` → alice               | all Org A resources                 | valid          |
| bob    | Member (low-priv)| Org A     | cookie jar      | `GET /api/me` → bob                 | bob's own resources                 | valid          |
| carol  | Owner            | Org B     | Bearer token    | `GET /api/me` → carol               | all Org B resources                 | valid          |
| dave   | custom: billing-only | Org A | cookie jar      | `GET /api/me` → dave                | billing scope only                  | valid          |
| —      | unauthenticated  | —         | none            | —                                   | nothing                             | n/a            |

## Notes

- **session carrier**: how the session travels — a cookie jar, `Authorization:
  Bearer <token>`, or a custom header. Note any separate CSRF token needed for
  writes.
- **auth probe**: the endpoint you re-hit to confirm the session is still live;
  if it fails mid-run, re-login once and continue.
- **legitimately owns**: what each identity is *allowed* to access. A bypass is
  only a finding when a sender reaches something outside its own row here.
- **self-victim pairing**: for safe write/delete proofs, pick a pair you control
  (e.g. attacker = bob, victim = a second account you own) so no real user's
  data is touched. Record that pairing here too if used.

### Login-blocked identities

List any identity whose login couldn't be completed, and why (bad creds / MFA /
CAPTCHA / lockout). Testing continues without it; note it in the final report's
coverage section since it bounds what was tested.

| handle | intended role | blocked because |
|--------|---------------|-----------------|
|        |               |                 |
