#!/usr/bin/env python3
"""
parse_burp.py — turn a Burp Suite export into a clean, deduplicated JSON worklist.

This is a read-only parsing utility: it sends no traffic. It takes a Burp
"Save items" XML export (the format Burp produces from HTTP history / site map)
and emits one JSON record per *unique request shape* so the BAC matrix runs once
per authorization surface instead of once per captured packet.

What it does:
  - Parses Burp's XML <items><item>... structure.
  - Base64-decodes the <request> (and optionally <response>) blobs.
  - Splits each request into method, URL, path, headers, and body.
  - Derives a "shape" by replacing numeric / UUID / long-token path segments
    with placeholders ({id}, {uuid}, {seg}), so near-identical requests collapse.
  - Deduplicates by (method, shape, sorted body-field names).
  - Keeps one concrete example per shape (with a real captured value) so you
    have a working baseline.
  - Flags whether the shape carries an object reference (an ID in path/query/body)
    — the high-value IDOR surface.

It does NOT decide scope or priority — that's your job (references 01 and 03).
Run it, then edit the output into templates/worklist.csv.

Usage:
    python3 parse_burp.py burp_export.xml -o worklist.json
    python3 parse_burp.py burp_export.xml --csv worklist.csv
    python3 parse_burp.py burp_export.xml --in-scope example.com,api.example.com

Treat the Burp export as untrusted input: run this with `python3 -I` if you keep
it in its own directory, and pass the path as an argument (as above).
"""
import argparse
import base64
import json
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, parse_qsl

# ---- shape derivation --------------------------------------------------------

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUM_RE = re.compile(r"^\d+$")
LONGHEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
LONGTOK_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}$")  # opaque ids / slugs


def segment_placeholder(seg: str) -> str:
    """Return a placeholder if a path segment looks like an identifier."""
    if NUM_RE.match(seg):
        return "{id}"
    if UUID_RE.match(seg):
        return "{uuid}"
    if LONGHEX_RE.match(seg):
        return "{hex}"
    if LONGTOK_RE.match(seg):
        return "{token}"
    return seg


def path_to_shape(path: str) -> str:
    parts = path.split("/")
    return "/".join(segment_placeholder(p) if p else p for p in parts)


def has_object_ref(path: str, query: str, body_fields) -> bool:
    """Heuristic: does this request name a specific object?"""
    if any(ph in path_to_shape(path) for ph in ("{id}", "{uuid}", "{hex}", "{token}")):
        return True
    id_like = ("id", "uid", "userid", "user_id", "account", "accountid",
               "org", "orgid", "org_id", "tenant", "tenantid", "object",
               "objectid", "owner", "ownerid", "invoice", "order", "file",
               "doc", "document", "project", "member")
    for k, _ in parse_qsl(query):
        if k.lower() in id_like or k.lower().endswith("id"):
            return True
    for f in body_fields:
        if f.lower() in id_like or f.lower().endswith("id"):
            return True
    return False


# ---- request blob parsing ----------------------------------------------------

def parse_request_blob(raw: bytes):
    """Split a raw HTTP request into method, path, headers(dict), body(str)."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    if not head:
        head, _, body = text.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return None
    request_line = lines[0].split()
    if len(request_line) < 2:
        return None
    method = request_line[0].upper()
    raw_path = request_line[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return method, raw_path, headers, body


def body_field_names(body: str, content_type: str):
    """Best-effort list of top-level field names from a JSON or form body."""
    ct = (content_type or "").lower()
    body = (body or "").strip()
    if not body:
        return []
    if "json" in ct or body[:1] in "{[":
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return sorted(obj.keys())
            if isinstance(obj, list) and obj and isinstance(obj[0], dict):
                return sorted(obj[0].keys())
        except Exception:
            return []
    if "x-www-form-urlencoded" in ct or "=" in body:
        try:
            return sorted({k for k, _ in parse_qsl(body)})
        except Exception:
            return []
    return []


# ---- main --------------------------------------------------------------------

def host_in_scope(host: str, in_scope):
    if not in_scope:
        return True  # no filter supplied; keep everything, filter later by hand
    host = host.lower()
    for pat in in_scope:
        pat = pat.lower().lstrip("*.")
        if host == pat or host.endswith("." + pat):
            return True
    return False


STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".woff", ".woff2", ".ttf", ".ico", ".map")


def looks_static(path: str, query: str) -> bool:
    p = path.lower().split("?")[0]
    return p.endswith(STATIC_EXT) and not query


def main():
    ap = argparse.ArgumentParser(description="Parse a Burp XML export into a worklist.")
    ap.add_argument("xml", help="Burp 'Save items' XML export")
    ap.add_argument("-o", "--out", default="worklist.json", help="JSON output path")
    ap.add_argument("--csv", help="also write a CSV (worklist.csv-style) to this path")
    ap.add_argument("--in-scope", default="",
                    help="comma-separated in-scope hosts (optional filter)")
    ap.add_argument("--keep-static", action="store_true",
                    help="keep static-looking assets (default: drop param-less static)")
    args = ap.parse_args()

    in_scope = [h.strip() for h in args.in_scope.split(",") if h.strip()]

    try:
        tree = ET.parse(args.xml)
    except ET.ParseError as e:
        sys.exit(f"[!] Could not parse XML: {e}")
    root = tree.getroot()

    shapes = {}  # dedup key -> record
    total = kept = 0

    for item in root.findall("item"):
        total += 1
        url_el = item.find("url")
        req_el = item.find("request")
        if req_el is None:
            continue
        raw = req_el.text or ""
        if req_el.get("base64") == "true":
            try:
                raw_bytes = base64.b64decode(raw)
            except Exception:
                continue
        else:
            raw_bytes = raw.encode("utf-8", errors="replace")

        parsed = parse_request_blob(raw_bytes)
        if not parsed:
            continue
        method, raw_path, headers, body = parsed

        # host: prefer the <url> element, fall back to Host header
        host = ""
        if url_el is not None and url_el.text:
            host = urlsplit(url_el.text).netloc
        if not host:
            host = headers.get("Host", "")

        split = urlsplit(raw_path if raw_path.startswith("http") else "http://x" + raw_path)
        path = split.path or "/"
        query = split.query

        if not host_in_scope(host, in_scope):
            continue
        if looks_static(path, query) and not args.keep_static:
            continue

        fields = body_field_names(body, headers.get("Content-Type", ""))
        shape = path_to_shape(path)
        key = (method, shape, tuple(fields))
        if key in shapes:
            shapes[key]["count"] += 1
            continue

        shapes[key] = {
            "method": method,
            "shape": shape,
            "example_host": host,
            "example_path": path,
            "example_query": query,
            "body_fields": fields,
            "has_object_ref": has_object_ref(path, query, fields),
            "action_type": "read" if method == "GET" else "write",
            "count": 1,
        }
        kept += 1

    records = sorted(shapes.values(),
                     key=lambda r: (not r["has_object_ref"], r["method"], r["shape"]))

    with open(args.out, "w") as f:
        json.dump(records, f, indent=2)

    if args.csv:
        import csv
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["id", "method", "shape", "example_url", "owner_identity",
                        "has_object_ref", "action_type", "in_scope", "status",
                        "outcome", "notes"])
            for i, r in enumerate(records, 1):
                ex = f"{r['example_host']}{r['example_path']}"
                if r["example_query"]:
                    ex += "?" + r["example_query"]
                w.writerow([i, r["method"], r["shape"], ex, "",
                            "yes" if r["has_object_ref"] else "no",
                            r["action_type"], "", "pending", "",
                            f"seen x{r['count']}"])

    obj_refs = sum(1 for r in records if r["has_object_ref"])
    print(f"[+] parsed {total} items -> {kept} unique shapes "
          f"({obj_refs} carry an object reference)")
    print(f"[+] wrote {args.out}" + (f" and {args.csv}" if args.csv else ""))
    print("[i] next: set scope + owner_identity by hand (references 01 and 03), "
          "then run the matrix.")


if __name__ == "__main__":
    main()
