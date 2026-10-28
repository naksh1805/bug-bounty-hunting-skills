#!/usr/bin/env python3
"""
report.py — collate confirmed BAC findings into a severity-sorted report.

Read-only; sends no traffic. Takes a findings JSON (the confirmed findings you
assembled from templates/finding.md) and emits the terse default report
(severity + endpoint + one-line impact), sorted P1 -> P4, plus an optional
detailed appendix.

INPUT  findings.json:
[
  {
    "severity": "P1",
    "method": "GET",
    "endpoint": "/api/orgs/{orgId}/invoices/{invoiceId}",
    "impact": "no-auth reads any org's invoices via direct ID (cross-tenant billing PII)",
    "class": "IDOR (cross-tenant)",
    "sender": "unauthenticated",
    "technique": "ID swap in path",
    "detail": "optional longer writeup for the appendix"
  },
  ...
]

USAGE
    python3 report.py findings.json
    python3 report.py findings.json --program "Acme VDP" --detailed -o report.md
"""
import argparse
import json
import sys
from datetime import date

ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
BANDS = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}


def main():
    ap = argparse.ArgumentParser(description="Collate BAC findings into a report.")
    ap.add_argument("findings", help="findings.json")
    ap.add_argument("--program", default="<program name + URL>")
    ap.add_argument("--scope", default="<in-scope hosts tested>")
    ap.add_argument("--identities", default="<handles + roles>")
    ap.add_argument("--detailed", action="store_true", help="include appendix")
    ap.add_argument("-o", "--out", help="write to file (default: stdout)")
    args = ap.parse_args()

    with open(args.findings) as f:
        findings = json.load(f)
    if not isinstance(findings, list):
        sys.exit("[!] findings.json must be a JSON array")

    for fi in findings:
        sev = str(fi.get("severity", "")).upper()
        if sev not in ORDER:
            sys.exit(f"[!] bad severity {fi.get('severity')!r} — must be P1..P4")
        fi["severity"] = sev

    findings.sort(key=lambda x: (ORDER[x["severity"]], x.get("endpoint", "")))

    lines = []
    lines.append("# BAC Testing — Findings Report\n")
    lines.append(f"**Target / program:** {args.program}  ")
    lines.append(f"**Date:** {date.today().isoformat()}  ")
    lines.append(f"**Scope tested:** {args.scope}  ")
    lines.append(f"**Identities used:** {args.identities}\n")
    lines.append("---\n")
    lines.append("## Findings (sorted P1 → P4)\n")

    counts = {k: 0 for k in ORDER}
    for sev in ("P1", "P2", "P3", "P4"):
        band = [f for f in findings if f["severity"] == sev]
        if not band:
            continue
        lines.append(f"### {sev} — {BANDS[sev]}")
        for f in band:
            counts[sev] += 1
            m = f.get("method", "?")
            ep = f.get("endpoint", "?")
            impact = f.get("impact", "")
            lines.append(f"- **{sev} — `{m} {ep}`** — {impact}")
        lines.append("")

    total = sum(counts.values())
    summary = ", ".join(f"{counts[s]}×{s}" for s in ("P1", "P2", "P3", "P4") if counts[s])
    lines.append("---\n")
    lines.append(f"**Total: {total} confirmed finding(s)**"
                 + (f" — {summary}." if summary else "."))
    lines.append("\n> Coverage: fill in shapes tested / total queued, and what "
                 "was not covered (out-of-scope, scope-ambiguity skips, "
                 "login-blocked identities). 'No finding' on an untested shape "
                 "means untested, not secure.\n")

    if args.detailed:
        lines.append("---\n")
        lines.append("## Appendix — detailed findings\n")
        for f in findings:
            lines.append(f"### {f['severity']} — `{f.get('method','?')} "
                         f"{f.get('endpoint','?')}`")
            if f.get("class"):
                lines.append(f"- **Class:** {f['class']}")
            if f.get("sender"):
                lines.append(f"- **Sender:** {f['sender']}")
            if f.get("technique"):
                lines.append(f"- **Technique:** {f['technique']}")
            lines.append(f"- **Impact:** {f.get('impact','')}")
            if f.get("detail"):
                lines.append(f"\n{f['detail']}\n")
            lines.append("")

    out = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        print(f"[+] wrote {args.out} ({total} findings)")
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
