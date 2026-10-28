# Review notes — bac-hunter

What changed when the original single-file `skill.md` draft was restructured into
this skill package, and why. The original methodology was already strong; nothing
substantive was removed. The work was (a) restructuring for how skills actually
load, (b) filling gaps that would bite in practice, and (c) adding the
safety/ethics layer that keeps authorized testing authorized.

## Structure

- **Split one long file into a lean `SKILL.md` + numbered references.** Skills
  load progressively: the frontmatter is always in context, the body loads when
  the skill triggers, and reference files load only when needed. A single ~90-line
  wall is harder to trigger well and harder to navigate mid-task. `SKILL.md` is now
  a tight workflow with a step→reference table; the detail lives in
  `references/01`–`10`.
- **Wrote a proper `description` frontmatter.** The original "Description"
  section was prose in the body. The real triggering mechanism is the YAML
  `description`, so it now spells out the three inputs, the trigger phrases
  (BAC/IDOR/access-control/priv-esc testing, "test these for authz issues"), what
  the skill does vs. doesn't do, and an explicit "do not use without an
  authorizing program."
- **Added templates and scripts** so each run is consistent and faster:
  identity/ownership table, worklist CSV, per-finding record, final-report
  skeleton; plus `parse_burp.py`, `replay.py`, `report.py`.

## Gaps filled (methodology)

These are things the original didn't cover that matter in real engagements:

- **Rules of engagement, not just scope domains.** Scope discovery now also
  captures automation/rate limits, required identifying headers, excluded paths,
  and "no prod-data" clauses — programs enforce these, and violating them voids a
  submission. (`references/01`)
- **CSRF / token freshness during login and writes.** Login replays and
  state-changing requests often need a token scraped fresh from a preceding GET;
  a stale token produces a false "login failed." Called out explicitly.
  (`references/02`)
- **Session re-validation via a per-identity probe**, and auto-refresh on
  expiry, formalized into the identity table so the identity axis stays
  trustworthy. (`references/02`, `templates/identities.md`)
- **Shape normalization + ownership map.** The worklist now collapses captures
  into shapes (one test per authorization surface) and records who legitimately
  owns each resource — which is what makes a "candidate" provably a cross-boundary
  finding in confirmation. (`references/03`, `08`)
- **A dedicated confirmation reference** enumerating the specific false positives
  BAC testing throws (soft 200 errors, decoy/own data, empty success, cache
  hits, reflected writes, public-by-design, self-owned resource). The original
  had the four gates; this expands the failure modes. (`references/08`)
- **A quick bypass cheatsheet** separate from the narrative matrix, for
  at-the-keyboard lookup. (`references/06`)

## Safety / ethics layer (the important addition)

The original was scoped to bug bounty / VDP — good — but didn't address how to
test without harming real users. Added throughout and centralized in
`references/10-responsible-testing.md`:

- **Self-controlled victim accounts** for any write/delete proof: show
  attacker-account-A can act on victim-account-B when both are yours, so no real
  user's data is touched. Most programs require this.
- **Non-destructive proof**: when only a real third party's resource is
  reachable, stop at the authorization decision rather than actually
  deleting/altering their data, and say so in the finding.
- **PII minimization**: capture the minimum marker that proves impact; never
  bulk-collect or enumerate thousands of IDs to "show scale."
- **Rate-limiting etiquette / no DoS**: throttle; `replay.py` has a built-in
  delay that's on by default.
- **"Prove it, don't exercise it"** framing: one object is enough; don't pivot,
  persist, or exfiltrate beyond proof; disclose your own mistakes promptly.

These also show up as guard rails in the tooling: `replay.py` refuses
PUT/PATCH/DELETE unless you pass both `--allow-destructive` and
`--i-am-using-a-self-owned-victim`, keeps a rate-limit delay on by default,
summarizes responses rather than dumping bodies unless you opt in, and flags
"2xx-but-error-like" responses so you don't over-report.

## What was deliberately kept

- The P1–P4-only output contract and the terse report format.
- The "default is to test it" worklist bias.
- The full identity / method / technique matrix — every technique from the
  original is preserved in `references/05` and `06`, just organized by axis.
- "Keep strictly to BAC; no other bug classes unless asked."

## Suggested next step (optional)

If you want to harden the skill empirically, the skill-creator flow can run it
against a few realistic test prompts (e.g. a small deliberately-vulnerable app's
Burp export + fake scope + test identities) and diff with/without the skill. Say
the word and this can be set up — it's the honest way to know the restructure
actually improved triggering and output quality, not just readability.
