# bac-hunter

A Claude skill for finding **Broken Access Control (BAC)** bugs in
manually-captured HTTP traffic, scoped to a single **authorized** bug bounty /
VDP engagement. It is a disciplined methodology — not a scanner and not a
crawler — that replays the traffic you captured across a set of test identities
to find IDOR, horizontal/vertical privilege escalation, mass assignment, forced
browsing, and other authorization bypasses, then reports them as P1–P4.

## What you provide

1. **Burp Suite traffic** — an HTTP-history / "Save items" export you crawled
   yourself. The skill never crawls or spiders the target.
2. **The program URL** — the HackerOne/Bugcrowd/VDP/`security.txt` page that
   authorizes the testing. The skill derives scope from this.
3. **Test identities** — for each: username/ID + password + intended role
   (Owner, Admin, low-priv member, custom-role, other-tenant). Accounts you
   control or were issued. The skill logs in as each and manages its own session.

## What the skill does

- Derives and locks **scope** from the program URL (and re-checks per request).
- **Logs in** as each identity, validates the session, refreshes it on expiry.
- Builds a **worklist** of in-scope request shapes from your Burp export.
- Runs the **identity × method × technique matrix** against each shape.
- **Confirms** each candidate (kills false positives) before calling it a finding.
- **Classifies** severity P1–P4 and produces a terse report.

## Authorization & safety — read first

This skill is strictly for **authorized** testing. No program scope → no testing.
It is built to prove authorization boundaries are broken using the smallest,
gentlest demonstration possible: in scope, with your own test accounts, without
touching real users' data more than it takes to show the bug. The full rules —
rate-limiting etiquette, non-destructive proof via self-controlled victim
accounts, PII minimization — are in `references/10-responsible-testing.md`, and
they override speed or thoroughness every time.

## Layout

```
bac-hunter/
├── SKILL.md                      # entry point + the 6-step workflow
├── README.md                     # this file
├── IMPROVEMENTS.md               # review notes: what changed vs. the original draft
├── references/
│   ├── 01-scope-discovery.md
│   ├── 02-session-acquisition.md
│   ├── 03-worklist-triage.md
│   ├── 04-request-analysis.md
│   ├── 05-test-matrix.md         # the engine
│   ├── 06-bypass-cheatsheet.md   # quick technique lookup
│   ├── 07-graphql-authz.md
│   ├── 08-confirmation.md        # false-positive killing
│   ├── 09-severity-rubric.md     # P1–P4
│   └── 10-responsible-testing.md # scope, safety, non-destructive proof
├── templates/
│   ├── identities.md             # identity + ownership table
│   ├── worklist.csv              # request-shape tracker
│   ├── finding.md                # per-finding record
│   └── final-report.md           # assembled report skeleton
└── scripts/
    ├── parse_burp.py             # Burp XML export -> JSON/CSV worklist (no traffic)
    ├── replay.py                 # replay ONE shape across identities + diff (rate-limited, destructive-guarded)
    ├── report.py                 # findings JSON -> severity-sorted report (no traffic)
    └── requirements.txt          # `requests` (for replay.py only)
```

## Installing as a skill

- **Claude Code / plugins:** drop the `bac-hunter/` folder into your skills
  directory (e.g. `.claude/skills/bac-hunter/`). The `name`/`description`
  frontmatter in `SKILL.md` drives when it triggers.
- **Claude.ai:** package it and upload. From the skill-creator tooling:
  `python -m scripts.package_skill path/to/bac-hunter` produces a `.skill` file
  you can save to your profile.

## Using the scripts

```bash
pip install -r scripts/requirements.txt          # only needed for replay.py

# 1) turn your Burp export into a worklist
python3 scripts/parse_burp.py export.xml --csv worklist.csv --in-scope example.com

# 2) test one shape across identities (safe methods; destructive blocked by default)
python3 scripts/replay.py --request req.json --identities ids.json \
    --owner alice --marker "INV-A-1001"

# 3) assemble confirmed findings into a report
python3 scripts/report.py findings.json --program "Acme VDP" --detailed -o report.md
```

See each script's header for its full argument list and the safety flags on
`replay.py`.
