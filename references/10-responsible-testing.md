# Reference 10 — Scope & Authorization

Read this once at the start of an engagement.

## Authorization is the whole game

- Only test where a **program/VDP scope authorizes it** (see `references/01-scope-discovery.md`). No scope, no testing.
- Stay inside the derived in-scope allowlist, and re-check per request.
- Respect explicit program rules that affect reachability (excluded paths, required identifying headers).
- Only authenticate with the **test identities the user provided** — these are accounts the user owns or controls across the whole identity matrix, including the cross-org/other-tenant ones. Never use, guess, reset, or brute-force credentials you weren't given.

If scope or authorization is unclear for a given host/path, skip it and note it for the user to clarify, rather than guessing.

## Keep it to BAC

Stay in the BAC lane: IDOR, horizontal/vertical privilege escalation, mass assignment, forced browsing, other authorization bypasses. If you stumble onto a different class (e.g. SQLi, SSRF), note it for the user but don't start a new offensive workflow under this skill.

## If something goes wrong

If a request lands outside the derived scope by mistake, say so immediately so the user can account for it. Keep an accurate log of what was sent and when (the worklist + finding evidence trail covers this).
