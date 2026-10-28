#!/usr/bin/env python3
"""
replay.py — replay ONE request across the provided identities (and optionally
methods) and diff the responses, for BAC testing against targets/identities
you control under an authorized program scope.

  * It fires one request shape across the identities you give it (all methods
    you ask for, including PUT/PATCH/DELETE — no separate confirmation flags).
  * Full response bodies are always captured for each (identity, method) pair
    so you can actually read what came back, not just a heuristic summary.
  * --delay defaults to 0 (no artificial pacing). Pass --delay if you want to
    throttle against a program that caps request rate.

INPUT FILES
  --request request.json   the request under test:
      {
        "method": "GET",
        "url": "https://api.example.com/api/orders/1001",
        "headers": {"Accept": "application/json"},
        "body": null,                      // or a string, or a JSON object
        "json": {"foo": "bar"}             // optional: sent as JSON body
      }

  --identities identities.json   senders to replay as:
      {
        "no-auth":  {},                                  // strips all auth
        "bob":      {"cookies": {"session": "..."},      // low-priv, Org A
                     "headers": {}},
        "carol":    {"headers": {"Authorization": "Bearer ..."}},  // Org B
        "alice":    {"cookies": {"session": "..."}}      // owner (baseline)
      }

  Mark which identity is the legitimate owner with --owner (its response is the
  authorized "known-good" baseline everything else is compared against).

EXAMPLES
  # read IDOR: who else can read alice's order 1001?
  python3 replay.py --request req.json --identities ids.json --owner alice \
      --marker "INV-A-1001"

  # full method sweep, every identity, including PUT/PATCH/DELETE:
  python3 replay.py --request req.json --identities ids.json --owner alice \
      --methods GET,POST,PUT,PATCH,DELETE,OPTIONS

  # save full response bodies to a folder for review:
  python3 replay.py --request req.json --identities ids.json --owner alice \
      --save-evidence ./evidence

Requires: requests  (pip install -r requirements.txt)
"""
import argparse
import json
import sys
import time
import hashlib

try:
    import requests
except ImportError:
    sys.exit("[!] needs `requests`: pip install -r requirements.txt")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def build_session(identity_cfg):
    s = requests.Session()
    s.headers.clear()
    for k, v in (identity_cfg.get("headers") or {}).items():
        s.headers[k] = v
    for k, v in (identity_cfg.get("cookies") or {}).items():
        s.cookies.set(k, v)
    return s


def summarize(resp, marker):
    body = resp.content or b""
    text_sample = body[:4096].decode("utf-8", errors="replace")
    digest = hashlib.sha256(body).hexdigest()[:12]
    marker_hit = (marker is not None) and (marker in text_sample
                                           or (marker in body.decode("latin-1",
                                                                     errors="replace")))
    # crude "looks like an error body despite 200" signal
    low = text_sample.lower()
    soft_error = any(tok in low for tok in
                     ('"error"', 'forbidden', 'unauthorized', 'not found',
                      '"success":false', 'access denied', 'login'))
    return {
        "status": resp.status_code,
        "length": len(body),
        "body_sha12": digest,
        "marker_hit": marker_hit,
        "soft_error_signal": soft_error,
        "content_type": resp.headers.get("Content-Type", ""),
        "allow_header": resp.headers.get("Allow", ""),  # useful for OPTIONS
    }


def send(session, method, url, req, timeout, verify):
    kwargs = {"timeout": timeout, "allow_redirects": False, "verify": verify}
    if req.get("json") is not None and method in ("POST", "PUT", "PATCH"):
        kwargs["json"] = req["json"]
    elif req.get("body") is not None and method in ("POST", "PUT", "PATCH"):
        b = req["body"]
        kwargs["data"] = json.dumps(b) if isinstance(b, (dict, list)) else b
    return session.request(method, url, **kwargs)


def main():
    ap = argparse.ArgumentParser(description="Replay one request across identities.")
    ap.add_argument("--request", required=True, help="request.json")
    ap.add_argument("--identities", required=True, help="identities.json")
    ap.add_argument("--owner", help="identity name whose response is the authorized baseline")
    ap.add_argument("--methods", help="comma list of methods to try (default: the request's own)")
    ap.add_argument("--marker", help="string that, if present, indicates the victim's real data")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds between requests (default 0, set if you want throttling)")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true", help="disable TLS verify (avoid)")
    ap.add_argument("--save-evidence", default="./evidence",
                    help="dir to save full response bodies (default: ./evidence)")
    args = ap.parse_args()

    req = load_json(args.request)
    identities = load_json(args.identities)
    base_method = req.get("method", "GET").upper()
    methods = ([m.strip().upper() for m in args.methods.split(",")]
               if args.methods else [base_method])
    url = req["url"]
    verify = not args.insecure

    # carry request's own headers into each identity (identity auth overrides)
    base_headers = req.get("headers") or {}

    results = []  # (identity, method, summary)
    baseline = {}  # method -> summary for owner

    print(f"[i] target: {url}")
    print(f"[i] identities: {list(identities.keys())}  methods: {methods}  "
          f"delay: {args.delay}s\n")

    # run owner first per method so we have a baseline to compare
    order = list(identities.keys())
    if args.owner and args.owner in order:
        order.remove(args.owner)
        order.insert(0, args.owner)

    for ident in order:
        cfg = identities[ident]
        for method in methods:
            sess = build_session(cfg)
            # merge request's non-auth headers underneath identity headers
            for k, v in base_headers.items():
                sess.headers.setdefault(k, v)
            try:
                resp = send(sess, method, url, req, args.timeout, verify)
            except requests.RequestException as e:
                print(f"  {ident:<10} {method:<7} ERROR: {e}")
                if args.delay:
                    time.sleep(args.delay)
                continue
            summ = summarize(resp, args.marker)
            results.append((ident, method, summ))
            if ident == args.owner:
                baseline[method] = summ

            flag = classify(ident, method, summ, baseline.get(method), args.owner)
            print(f"  {ident:<10} {method:<7} {summ['status']}  "
                  f"len={summ['length']:<6} "
                  f"marker={'Y' if summ['marker_hit'] else '-'} "
                  f"softerr={'Y' if summ['soft_error_signal'] else '-'}  {flag}")

            save_evidence(args.save_evidence, ident, method, resp)
            if args.delay:
                time.sleep(args.delay)
        print()

    print(_legend())
    print("[i] A flagged CANDIDATE is only a finding after manual confirmation "
          "(references/08-confirmation.md).")


def classify(ident, method, summ, owner_summ, owner_name):
    """Heuristic flag — never authoritative."""
    denied_statuses = {401, 403, 404}
    if ident == owner_name:
        return "(owner baseline)"
    if summ["status"] in denied_statuses:
        return "denied (expected)"
    if summ["status"] >= 500:
        return "server error"
    if 200 <= summ["status"] < 300:
        if summ["soft_error_signal"]:
            return "2xx but error-like body — inspect"
        if summ["marker_hit"]:
            return ">>> CANDIDATE: got victim marker <<<"
        if owner_summ and summ["status"] == owner_summ["status"] \
                and abs(summ["length"] - owner_summ["length"]) <= max(
                    16, owner_summ["length"] // 20):
            return ">>> CANDIDATE: matches owner response <<<"
        return "2xx — inspect vs baseline"
    if summ["status"] in (301, 302, 307, 308):
        return "redirect (often to login = denied)"
    return "inspect"


def save_evidence(outdir, ident, method, resp):
    import os
    os.makedirs(outdir, exist_ok=True)
    safe = f"{ident}_{method}".replace("/", "_")
    path = os.path.join(outdir, f"{safe}.http")
    with open(path, "w") as f:
        f.write(f"{method} {resp.url}\nHTTP {resp.status_code}\n")
        for k, v in resp.headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")
        f.write(resp.content.decode("utf-8", errors="replace"))
    print(f"    [saved] {path}")


def _legend():
    return ("[legend] denied(401/403/404)=good;  CANDIDATE=should-be-denied "
            "sender got owner-like/marked data;  '2xx but error-like'=likely "
            "false positive — read the body.")


if __name__ == "__main__":
    main()
