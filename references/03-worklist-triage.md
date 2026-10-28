# Reference 03 — Building the Worklist from Burp History

Goal: turn the raw Burp export into a deduplicated list of in-scope requests
worth testing, biased heavily toward **testing** rather than skipping.

## The default is "test it"

Go through the full Burp history and queue every in-scope request. For
access-control testing, false negatives (skipping a vulnerable endpoint) cost
far more than false positives (spending a little time on a harmless one). So
when you're unsure whether a request "has a use case," queue it.

`scripts/parse_burp.py` will do the mechanical parse and dedup for you; this
reference is the judgment layer on top of it.

## What to drop (and only these)

1. **Out of scope.** Host/path fails the `IN`/`OUT` check from
   `references/01-scope-discovery.md`. Re-check per request — the export is full
   of off-target traffic.
2. **Pure static assets with no params and no data.** `.js`, `.css`, images,
   fonts, `.map` sourcemaps — *when* they carry no parameters and the response
   is just the asset. Caveat: a "static-looking" path that returns user data
   (e.g. `/files/1234/invoice.pdf`, `/avatars/user/567`) is **not** static — it
   has an object reference and belongs in the worklist.
3. **Pure analytics / telemetry beacons.** Third-party tracking pixels, ad
   calls, RUM/telemetry with no bearing on the app's own authorization. Do
   **not** drop an endpoint just because it's an API call that renders UI — a
   UI-driving endpoint can still leak or modify data.
4. **Exact duplicate shapes.** Same method + path template + param/body shape
   already queued. Queue the unique *shape* once; you don't need every repeated
   capture of `GET /api/orders/{id}`. Keep one representative with a real,
   known-valid ID so you have a working baseline.

Everything else stays.

## Normalize into shapes

Collapse concrete requests into **shapes** so the matrix runs once per distinct
authorization surface, not once per captured packet:

- Replace concrete IDs in the path with a placeholder:
  `GET /api/v2/orgs/42/projects/908/members/771`
  → shape `GET /api/v2/orgs/{orgId}/projects/{projectId}/members/{memberId}`.
- Record, alongside the shape, the concrete known-valid values you captured
  (which org/project/member actually belongs to which identity) — you need real
  values to build the "authorized baseline" and real *other*-owner values to
  attempt IDOR.
- Note the body shape for write endpoints (field names and types), since mass
  assignment works off field names.

## Prioritize within the worklist

All in-scope requests get tested, but order them so the high-value surface comes
first (useful when traffic is large):

1. **Object-reference endpoints** — anything with an ID in the path/query/body
   (`/users/{id}`, `/orders/{id}`, `?account=…`). Highest-yield IDOR surface.
2. **State-changing actions** — create/update/delete, invite, change-role,
   transfer-ownership, billing/plan changes. Both IDOR and privilege-escalation
   live here.
3. **Admin / privileged endpoints** — anything under `/admin`, `/internal`,
   `/manage`, or returning other users/org-wide data. Forced-browsing targets.
4. **Everything else** that passed triage.

## Track it

Use `templates/worklist.csv`:

```
id,method,shape,example_url,owner_identity,has_object_ref,action_type,status,notes
1,GET,/api/orders/{id},/api/orders/1001,alice,yes,read,pending,
2,PATCH,/api/orders/{id},/api/orders/1001,alice,yes,write,pending,
3,DELETE,/api/orgs/{id}/members/{mid},/api/orgs/42/members/9,alice,yes,write,pending,"admin-only in UI"
```

Mark each row `pending` → `testing` → `done` as you work, and jot the outcome in
`notes`. This is also your evidence trail for which shapes were and weren't
covered, which belongs in the final report's coverage note.
