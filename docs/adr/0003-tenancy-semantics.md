# ADR-0003: Tenant isolation by per-occurrence, per-scope conjunct proof

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** Arnav Dadarya
- **Related:** PLAN.md §6.3; [docs/tenancy.md](../tenancy.md)

## Context

The most valuable asset in a multi-tenant application is other tenants' rows.
An LLM agent under prompt injection will try to read them. Common bypass shapes
are well known: `OR 1=1`, a filter only in an outer query, a `UNION` branch
without a filter, a `LEFT JOIN` whose `ON` clause does not restrict the
preserved side, and a wrong tenant literal.

We need rules that are (a) sound, so that every allowed query is restricted to
the tenant, (b) simple enough to audit and explain to an agent, and (c)
checkable without a database.

## Decision

1. **Every occurrence** of a tenant-scoped relation, in **every scope** (CTE
   bodies, subqueries, `LATERAL`, `EXISTS`/`IN` subqueries, scalar subqueries,
   each set-operation branch), must have a tenant predicate for **each** of its
   tenant columns.
2. A tenant predicate is a **top-level conjunct** (part of the `AND` chain) of
   the scope's `WHERE`, or of a join `ON` clause that filters the occurrence:
   an inner join's `ON` covers both operands; an outer join's `ON` covers only
   its nullable side; `FULL JOIN ON`, `USING`, `HAVING`, and other scopes cover
   nothing. `OR`, `NOT`, and `CASE` break the proof.
3. Accepted shapes are deliberately narrow: `a.col = $n` (bound mode),
   `a.col = <literal>` (literal mode), and for sets of tenant values
   `a.col = ANY($n)` (bound) or `a.col IN (<literals>)` (literal).
4. **Bound mode** is the default and recommended. HaltSQL returns
   `bind_params` with the context value for each tenant parameter, and the
   caller must bind them. Every `$n` in the query must be a tenant parameter.
   The model never sees the tenant ID.
5. **Literal mode** requires exact equality with the context value (no
   trimming or case folding), type-checked against the catalog when known.
6. **Composite keys:** each tenant column maps to a named tenancy key; each
   needs its own predicate.
7. **Sets of tenant values** (context value is a list) allow hierarchical
   tenancy without weakening the proof.
8. **Equality propagation within one scope only.** An occurrence may be proven
   by a top-level `a.tenant_col = b.tenant_col` conjunct in one of its own
   locations when `b` is proven in the same `SELECT` and both columns carry the
   same tenancy key (added after 0.0.2; originally every occurrence needed a
   direct predicate). It does not cross subquery boundaries.

## Alternatives considered

- **Accept a tenant predicate anywhere in the query.** Unsound: an outer filter
  does not restrict what an inner aggregate reads. Rejected.
- **Rewrite queries to inject tenant predicates.** Changes the SQL the caller
  runs, hides problems from the agent, and requires a deparser in the trusted
  path. Out of scope for verify mode (it may appear in the proxy later).
- **Rely on Postgres RLS only.** RLS is strongly recommended as a second layer,
  but it gives the agent no actionable feedback and is easy to misconfigure.
  HaltSQL complements it.
- **Full logical implication (SMT) over predicates.** More permissive, much
  harder to audit and explain. Rejected for 0.x.

## Consequences

- Some safe queries are denied (for example a tenant equality that reaches
  into a correlated subquery). Agents get a precise hint and can add the direct
  predicate.
- The rules are short enough to document completely and test exhaustively.
- The enterprise lab uses Postgres RLS as an independent oracle: any allowed
  query that returns a row RLS would hide is an escape and a release blocker.
- The semantics in `docs/tenancy.md` are normative; changes require a new ADR.

## Follow-up

- Attack-corpus cases for each rule and each bypass shape.
- Property tests applying evasion transforms to allowed queries.
- Equality propagation within one scope is done (decision 8); propagation into
  correlated subqueries and `USING` joins is still open.
