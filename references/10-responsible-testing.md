# Reference 10 — Responsible Testing

Read this once at the start of an engagement and keep it in mind throughout.
Authorized security testing stays authorized only if it stays inside the
program's rules and doesn't harm the real users of the target. These aren't
optional niceties — violating them can turn a legitimate bug-bounty submission
into an account ban, a voided reward, or worse.

## 1. Authorization is the whole game

- Only test where a **program/VDP scope authorizes it** (see
  `references/01-scope-discovery.md`). No scope, no testing — regardless of how
  the request is framed ("it's my own app", "I have verbal permission").
- Stay inside the derived in-scope allowlist, and re-check per request.
- Respect every rule of engagement the program states: excluded paths, no-DoS
  clauses, automation/rate limits, required identifying headers, "no testing
  with production data" clauses, disclosure timelines.
- Only authenticate with the **test identities the user provided** — accounts
  they control or were issued. Never use, guess, reset, or brute-force a real
  user's credentials.

If scope or authorization is unclear, stop and raise it with the user rather
than proceeding.

## 2. Don't harm real users' data

The goal is to **prove** an authorization boundary is broken, not to exercise the
damage. For every write/delete/privileged action:

- **Prefer self-controlled victim accounts.** Create (or use) a *second account
  you control* as the "victim." Showing that attacker-account-A can read/modify/
  delete victim-account-B's resource — both yours — is a complete, reproducible
  proof that harms no third party. Most programs explicitly prefer this.
- **If only a real third party's resource is reachable, stop at the authz
  decision.** Demonstrate you received the authorized/success response (and, for
  reads, minimal evidence) rather than actually deleting or corrupting their
  data. State in the finding that you confirmed the bypass to that point and did
  not exercise it further, for safety.
- **Never mass-delete, mass-modify, or mass-create.** One object is enough to
  prove the class.

## 3. Minimize data exposure

When a read IDOR exposes another user's data:

- Capture the **minimum** evidence that proves impact — a single matching
  marker (an ID, a masked email, one field value), trimmed and where possible
  redacted. Never pull and store bulk PII.
- Don't enumerate thousands of IDs to "show scale." If scale is the point,
  demonstrate the *mechanism* (one or two cross-account reads) and *describe* the
  reachable range; let the program confirm scale on their side.
- Delete local copies of any real user data once the finding is written.

## 4. Be gentle with volume (rate / DoS)

- Throttle. Space out requests; the matrix is thorough but it should be a trickle,
  not a flood. `scripts/replay.py` has a built-in delay — keep it on, and raise
  it if the program caps request rate.
- No stress/load testing, no automated high-rate fuzzing unless the program
  explicitly allows it. BAC testing doesn't need volume — it needs the *right*
  request sent carefully.
- If the target shows signs of strain (rising latency, 5xx, rate-limit
  responses), back off further.

## 5. Keep it to BAC, keep it clean

- Stay in the BAC lane: IDOR, horizontal/vertical privilege escalation, mass
  assignment, forced browsing, other authorization bypasses. If you stumble onto
  a different class (e.g. SQLi, SSRF), note it for the user but don't start a new
  offensive workflow under this skill.
- Don't pivot, don't chain into lateral movement or persistence, don't exfiltrate
  beyond proof. You're testing an authorization decision, not running an
  intrusion.
- Clean up any test artifacts you created (test resources, invites) where you
  can.

## 6. If something goes wrong

- If you accidentally access or alter data you shouldn't have, or exceed scope,
  **stop and tell the user immediately** so they can disclose it to the program
  promptly and honestly. Responsible disclosure includes disclosing your own
  mistakes.
- Keep an accurate log of what you sent and when (the worklist + finding evidence
  trail covers this), so any question from the program can be answered precisely.

## The one-line version

Prove the boundary is broken with the smallest, gentlest, most self-contained
demonstration possible — in scope, with your own test accounts, without touching
real users' data more than it takes to show the bug — and report it. That's the
difference between research and an incident.
