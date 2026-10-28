---
name: bac-hunter
description: Use this skill when the user provides Burp Suite traffic (HTTP history/export), the bug bounty / VDP program's URL, and a list of test user identities (user ID/username + password + role/permission level) for a program, and wants the requests tested for Broken Access Control (BAC) issues — IDOR, horizontal/vertical privilege escalation, mass assignment, forced browsing, and related authorization bypasses. This skill does NOT crawl the target site — the user manually crawls and supplies the Burp traffic. It DOES derive scope itself from the program URL, and DOES log in as each given identity and extract/refresh its own session. Findings are reported strictly as P1/P2/P3/P4 severity, nothing else.
---

# Broken Access Control (BAC) Hunter

## What the user provides vs. what this skill does itself

User provides (never ask them to do more than this):
- Full Burp Suite traffic / HTTP history export (already crawled manually by the user — never crawl the site yourself).
- The bug bounty / VDP **program URL**.
- A list of test identities: for each one, user ID/username + password + intended role/permission level (e.g. Owner, Admin, lower-priv member, custom-role user, another-org/tenant user) — accounts the user owns or was issued for testing.

This skill itself does:
- **Scope discovery** — fetch/read the program URL and derive in-scope domains, endpoints, asset types, and anything explicitly out-of-scope or disallowed (rate/automation limits, excluded paths). See `references/01-scope-discovery.md`. Re-check scope before testing anything; when ambiguous for a given host/path, treat it as out-of-scope and skip it rather than guessing.
- **Session acquisition** — find the login request(s) in the Burp traffic, and for each given identity, replay the login flow with that identity's credentials to obtain a valid session (cookie/token). Validate each session against a known authenticated endpoint before using it. See `references/02-session-acquisition.md`. If a session expires mid-run, re-login to refresh it. If login itself fails for an identity (bad creds, MFA, CAPTCHA, lockout), flag that identity and continue with the ones that work.

## Workflow

| Step | What happens | Reference |
|------|--------------|-----------|
| 0 | Derive and lock scope from the program URL | `references/01-scope-discovery.md` |
| 0 | Acquire + validate a session per identity | `references/02-session-acquisition.md` |
| 1 | Build the worklist from Burp history | `references/03-worklist-triage.md` |
| 2 | Model each request before touching it | `references/04-request-analysis.md` |
| 3 | Run the identity × method × technique matrix | `references/05-test-matrix.md` |
| 3 | Technique lookups while testing | `references/06-bypass-cheatsheet.md` |
| 3 | GraphQL-specific authz checks | `references/07-graphql-authz.md` |
| 4 | Confirm each hit, kill false positives | `references/08-confirmation.md` |
| 5 | Classify severity P1–P4 and report | `references/09-severity-rubric.md` |

## Step 1 — Build the worklist

Queue **every in-scope request** for testing by default. Only drop a request when it clearly has no access-control surface: out-of-scope; pure static assets with no params and no data; pure analytics/telemetry beacons; or an exact duplicate of a shape already queued. When unsure, queue it — the cost of testing a harmless endpoint is low, the cost of skipping a real one is a missed bug. Track with `templates/worklist.csv`.

## Step 2 — Model each request

Before firing anything: what does this request *do* (read/write/delete/invite/change-role)? Where does the target resource's identity live (path, query, body, header, or implicit from session)? Which auth material actually gates access vs. which is just bookkeeping? What does a genuinely authorized success look like, so you can tell a real bypass from an error page dressed as 200?

## Step 3 — The test matrix

For each queued request, replay it across:

- **Identity axis** — no-auth, same-org lower-priv, forced-browse to admin/owner endpoints, custom-role boundaries, other-tenant user, and the resource owner's own session with a forced/tampered ID.
- **Method axis** — GET/POST/PUT/PATCH/DELETE and OPTIONS, for every identity, regardless of the method originally captured. A server that allows a method for an identity that only ever saw GET in the UI is itself a finding.
- **Technique axis** — ID manipulation, encoding tricks, path tricks, method-override headers, trusted-header spoofing, mass assignment, parameter pollution, JSON structure tricks, and GraphQL field-level checks. See `references/06-bypass-cheatsheet.md` and `references/07-graphql-authz.md`.

Always compare against the baseline from Step 2. Cross-reference known public bypass patterns for the endpoint category as an extra pass, not a replacement for the matrix.

## Step 4 — Confirm before reporting

A hit only counts after it survives confirmation: real success status (not a 200 wrapping an error), genuine target-resource data returned or the write/delete demonstrably effected, reproducible on a clean replay, and the affected data/action genuinely belongs to someone else or is outside that identity's role. Report one finding per underlying bug, even if it appeared on many near-identical captures.

## Step 5 — Severity and output

Classify each confirmed finding as P1/P2/P3/P4 using `references/09-severity-rubric.md`. Output per finding:

1. Severity: P1 / P2 / P3 / P4
2. Endpoint + method
3. One-line description (which identity, which technique, what was exposed/modified)

Use `templates/finding.md` per finding and `templates/final-report.md` to assemble the set, sorted P1 → P4. Nothing else — no remediation essays, no CVSS breakdowns, no non-BAC bug classes — unless the user explicitly asks for more detail.

## Helper scripts

`scripts/` holds utilities that make the manual workflow faster and more consistent — plain HTTP/parse/report tooling, not a mass scanner.

- `scripts/parse_burp.py` — parse a Burp XML/HTTP export into a clean JSON worklist.
- `scripts/replay.py` — replay ONE request across the provided identities and methods and diff the responses. Run its real HTTP requests and report from the actual output — don't simulate responses.
- `scripts/report.py` — collate a findings JSON into a severity-sorted report.

## Ground rules

- Only test hosts/paths that are in-scope for the program URL given. If scope is unclear for something, skip it.
- Only authenticate with the identities the user provided — these are the user's own accounts across every identity in the matrix, including the cross-org/other-tenant ones.
- All methods (GET/POST/PUT/PATCH/DELETE/OPTIONS) are tested by default for every identity per Step 3b — `scripts/replay.py` does not gate this behind extra flags.
- `scripts/replay.py` saves the full response body for every (identity, method) pair by default (to `./evidence` unless `--save-evidence` points elsewhere) — read the actual body when confirming a finding (Step 4), don't rely on the heuristic flag alone.
- `--delay` defaults to 0; pass it explicitly if a program's rules of engagement require throttling.

See `scripts/requirements.txt` for dependencies (`requests` only).
