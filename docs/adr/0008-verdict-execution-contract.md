# ADR-0008: Deny casts by default, pin the search path, and make shadow execution opt-in

- **Status:** Proposed
- **Date:** 2026-11-10
- **Deciders:** Arnav Dadarya
- **Related:** [ADR-0002](0002-typed-ast-fail-closed.md); [ADR-0003](0003-tenancy-semantics.md); [ADR-0004](0004-verdict-schema-and-reason-codes.md); [docs/policy-reference.md](../policy-reference.md); [docs/verdict.md](../verdict.md); [docs/authentication.md](../authentication.md)

## Context

A review of 0.0.2 found four places where a verdict promised more than the
system delivered. Each touches a stable contract (policy schema, verdict JSON,
config, SDK behaviour), so they are decided together.

1. **Casts were a denylist** in a system that is deny-by-default everywhere
   else. Only the `reg*` types were refused; `'x'::xml`, `CAST(x AS oid)` and
   casts to user-defined types passed. A cast runs the target type's input or
   conversion function, so this was an unlisted function call.
2. **The verdict assumed a search path nobody enforced.** Unqualified names are
   resolved against the policy's `search_path`; the session that ran the SQL
   could use another one (`ALTER ROLE ... SET search_path`), so a verified
   `orders` could be a different table.
3. **Shadow mode returned `allowed: true`** and every guarded executor ran on
   `allowed`. One reloaded policy line turned enforcement off, with no signal
   on the client.
4. **Static tokens authenticated a caller but not a tenant.** The request body
   supplied the whole context, so any holder of a service token could ask for a
   verdict, with its `bind_params`, for any tenant.

## Decision

**Casts.** A new policy section `casts` (`allow`, `extend`) is an allowlist of
cast target types. Its default is the built-in scalar types with pure input
functions (text, the integer and float types, numeric, bool, the date and time
types, uuid, json, jsonb, bytea). A bare name matches the type unqualified or
`pg_catalog.`-qualified; a type in another schema must be listed as
`schema.type`. `deny_casts` stays and wins over `casts`. The reason code is
unchanged (`E_CAST_DENIED`); the rule name `casts.allowlist` is new.

**Search path.** The verdict's `policy` object gains `search_path`. Executors
that own the transaction set it: the Python guard (and so the MCP server and
the Python integrations) with a transaction-local `set_config`, applied after
caller settings; the proxy at upstream startup, verified with `SHOW
search_path` before the first client statement. The TypeScript, Go and Java
guards run one statement on the caller's connection and do not change session
settings; they expose the field and document the requirement.

**Shadow mode.** The verdict is unchanged: `allowed: true` with
`shadow_reasons`. The guarded executors of all four SDKs and the MCP server
treat a verdict with non-empty `shadow_reasons` as a denial unless the
application opts in (`HALTSQL_ALLOW_SHADOW=1` or `guard.set_allow_shadow(True)`;
`allowShadow: true`; `AllowShadow()`; `.allowShadow()`). A shadow rollout
therefore needs a server-side switch and a client-side one.

**Token context.** `server.auth.tokens[]` accepts `context` and
`request_context_fields`, with the semantics mTLS identities already have: the
configured context is fixed, the body may add only the listed fields, anything
else is `403 CONTEXT_NOT_ALLOWED`. A token with neither key keeps the old
behaviour and the server logs a warning when its policy isolates tenants.
Audit records carry `context` and `context_source` (`authenticated` or
`request`).

## Alternatives considered

- **Keep casts a denylist and extend it.** Every new type or extension would
  need a new entry; the failure mode is an allow. Rejected.
- **Make `allowed: false` in shadow mode and add a separate "would run" flag.**
  Cleaner for clients, but it breaks every existing caller that implements
  shadow rollouts on `allowed`, and it changes the meaning of a field ADR-0004
  froze. The client-side opt-in gets the safety without changing the verdict.
- **Schema-qualify every name instead of pinning the search path.** HaltSQL
  never rewrites SQL, and requiring qualified names would deny most generated
  queries. Pinning makes the assumption true instead of forbidding its use.
- **Require a context on every token.** Correct for multi-tenant agents, wrong
  for a trusted backend that takes the tenant from its own session. A warning
  and a documented default-safe pattern were chosen over a breaking
  requirement; this can be tightened before 1.0.

## Consequences

- **Breaking:** queries that cast to a type outside the default list are now
  denied; shadow rollouts need the client opt-in; every policy's `version`
  hash changes because the canonical policy includes `casts`.
- The verdict JSON grows one field (`policy.search_path`). Clients ignore
  unknown fields, so older SDKs keep working, but they also do not pin.
- All four changes fail closed: an unlisted cast denies, a search path that
  cannot be set fails the transaction (the proxy ends the session), an
  un-opted shadow verdict does not run, a body field outside a bound token's
  allowance is refused.
- What stays outside the proof: views, function bodies, triggers and
  partitions. `haltsql schema check` reports the cases it can see (views,
  stale catalog entries, shadowing relations); row-level security remains the
  boundary.

## Follow-up

- Decide before 1.0 whether an unbound static token should be refused for a
  policy that isolates tenants.
- Give the TypeScript, Go and Java guards a transaction-owning mode so they
  can pin the search path too.
- Function allowlist entries are still by name; an entry allows every overload.
