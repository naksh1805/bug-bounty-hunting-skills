# Reference 07 — GraphQL Authorization Testing

GraphQL concentrates a lot of surface behind one endpoint (usually
`/graphql`), and its authorization bugs look different from REST's. If the
traffic contains GraphQL operations, run these checks in addition to the general
matrix. Everything here still stays inside the scope locked in
`references/01-scope-discovery.md`.

## Why GraphQL authz breaks

In REST, each route tends to have its own handler and (hopefully) its own authz
check. In GraphQL, a single query can traverse many types and fields, each
resolved separately. Teams frequently guard the *top-level* query/mutation but
forget to re-check authorization on nested **field resolvers** — so data you
shouldn't see leaks through a field hanging off an object you *can* see.

## Checks to run

### 1. Field-level authorization

Take an operation the attacker identity is allowed to run and extend it to pull
fields it shouldn't have. Classic shape: you can read your own `user`, but the
`user` type exposes an `email`, `ssn`, `paymentMethods`, or `org { members }`
field that isn't re-checked.

```graphql
query {
  me {
    id
    organization {
      members { id email role }   # should a low-priv member see all of these?
    }
  }
}
```

Test each sensitive field independently — the bug is often one unchecked field,
not the whole query.

### 2. Global-ID / node() IDOR

Relay-style APIs expose `node(id: ID!)` and opaque global IDs (often
base64 of `Type:localId`, e.g. `Order:1001`). This is a direct IDOR primitive:

```graphql
query { node(id: "T3JkZXI6MTAwMQ==") { ... on Order { id total lineItems { sku } } } }
```

Decode a global ID you legitimately hold, re-encode it for a resource owned by a
*different* identity/tenant, and request it as the attacker. Also try passing a
raw local ID where a global ID is expected, and vice versa.

### 3. Mutation authorization

Mutations are the write surface — invites, role changes, transfers, deletes. Run
each privileged mutation as an identity that should be denied, and try mass
assignment on mutation input objects (extra `role`, `ownerId`, `orgId`,
`isAdmin` fields the input type accepts but the UI never sends).

### 4. Introspection as a map

If introspection is enabled, use it to find admin-only or internal types,
fields, and mutations worth targeting — then test whether they enforce authz:

```graphql
{ __schema { queryType { name } mutationType { fields { name } } types { name fields { name } } } }
```

Introspection being on is not itself a BAC finding (it's an info-disclosure at
most), but it tells you where the privileged resolvers are. If introspection is
off, infer field names from the captured operations and from client JS.

### 5. Batching

Many servers accept an array of operations in one HTTP request. Batching can:

- reach a resolver that's otherwise rate-limited or throttled per-request,
- sometimes slip past checks applied per-HTTP-request rather than per-operation.

```jsonc
[
  { "query": "query { node(id:\"<victim id 1>\") { ... } }" },
  { "query": "query { node(id:\"<victim id 2>\") { ... } }" }
]
```

Use batching to *demonstrate* a single authz gap cleanly — not to mass-harvest
data. One victim object is enough to prove the bug.

### 6. Aliases

Aliases let one operation request the same field many times under different
names. Combined with IDOR primitives this is powerful for proof, but again: show
the gap with a minimal example; don't turn it into a bulk extractor.

## Confirming GraphQL findings

GraphQL loves to answer `200 OK` with an `errors` array and `data: null`. A real
bypass has the sensitive data actually present under `data`, for an identity that
should have been denied. A `200` with `"data": null` and an authorization error
in `errors[]` is a correct denial, not a finding. Push candidates through
`references/08-confirmation.md`.
