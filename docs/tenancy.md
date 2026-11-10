# Tenancy semantics

This page defines exactly what HaltSQL must prove before it allows a query that
touches a tenant-scoped table. It is the most security-critical part of the
analyzer. The design decision behind it is
[ADR-0003](adr/0003-tenancy-semantics.md).

The short version: **every occurrence of a tenant-scoped table must be filtered
to the caller's tenant by a top-level `AND` condition in its own query level.**

## Terms

- **Tenancy key:** a named dimension of tenancy declared in `tenancy.keys`,
  mapped to a context field. Example: `tenant: ${ctx.tenant_id}`.
- **Tenant-scoped table:** a table with `tenant_column` or `tenant_columns` in
  the policy. A table without them is global.
- **Tenant value:** the context value for a key, from the caller's
  authenticated session. It is either one value (`"acme"`) or a set of values
  (`["acme", "acme-eu"]`).
- **Occurrence:** each place a table appears in a `FROM` clause or join tree.
  `FROM orders a JOIN orders b` has two occurrences of `orders`.
- **Scope:** one query level (one `SELECT ... FROM ... WHERE ...`). Every CTE
  body, subquery in `FROM`, `LATERAL` subquery, scalar subquery, `EXISTS` or
  `IN` subquery, and each branch of `UNION` / `INTERSECT` / `EXCEPT` is its own
  scope.
- **Top-level conjunct:** one of the terms of the `AND` chain that makes up a
  `WHERE` or `ON` expression. In `WHERE a AND (b OR c) AND d`, the top-level
  conjuncts are `a`, `(b OR c)`, and `d`.

## The rule

For **every occurrence** of a tenant-scoped table `R`, with alias `a` (the
table name if there is no alias), in **any scope**, and for **every tenant
column** `col` of `R`, HaltSQL must find a **tenant predicate** for `a.col`
in a place that filters that occurrence (see [where the predicate may
appear](#where-the-predicate-may-appear)). If any occurrence lacks one, the
query is denied with `E_TENANT_MISSING`.

A tenant predicate is a top-level conjunct of one of these forms:

| Mode | Single tenant value | Set of tenant values |
|---|---|---|
| `bound` | `a.col = $n` | `a.col = ANY($n)` |
| `literal` | `a.col = <literal>` | `a.col = <literal>` or `a.col IN (<literal>, ...)` |

The column reference must resolve to that occurrence (`a.col`, or an
unqualified `col` that is unambiguous in the scope). The tenant-value side must
be a parameter or literal as shown. Other shapes, such as an expression,
function call, subquery, or a column of another table, are not tenant
predicates. A query whose only filter has one of those shapes is denied, even
if it happens to be safe. This is deliberate: the proof rules are simple enough
to audit.

### What breaks the proof

Only the `AND` chain counts. A tenant comparison under any of these is not a
top-level conjunct and proves nothing:

- `OR`: `WHERE tenant_id = $1 OR status = 'open'`
- `NOT`: `WHERE NOT (tenant_id <> $1)`
- `CASE`: `WHERE CASE WHEN x THEN tenant_id = $1 ELSE true END`
- function arguments, `COALESCE`, or comparison of expressions:
  `WHERE coalesce(tenant_id, $1) = $1`
- `IS DISTINCT FROM`, `<>`, `LIKE`, and other operators: only `=` (and
  `= ANY` / `IN` for sets) count.
- `HAVING`: rows are filtered after grouping, so aggregates may already mix
  tenants. Only `WHERE` and `ON` count.

## Bound mode and literal mode

### Bound mode (recommended)

The model writes a parameter placeholder:

```sql
SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50
```

HaltSQL returns `bind_params: [{"param": 1, "value": "acme"}]`. The caller runs
the exact SQL with `$1` bound to `acme`. The model never sees the tenant ID, so
it cannot leak it, and prompt injection cannot change it.

Rules:

- The same `$n` may be used for every occurrence that uses the same tenancy key:
  `WHERE o.tenant_id = $1 AND c.tenant_id = $1`. It is bound once.
- One parameter may serve two different keys only if both keys resolve to the
  same context value. If the values differ, the query is denied
  (`E_TENANT_MISMATCH`). Mixing `= $1` and `= ANY($1)` for the same parameter is
  also `E_TENANT_MISMATCH`.
- Every parameter in the query must be a tenant parameter, because HaltSQL
  must supply every bound value itself. Any other `$n` is `E_PARAM_UNBOUND`.
- A tenant parameter may appear only as the value of a tenant predicate. Using
  it anywhere else (`$1::float8 IS NOT NULL`, `status = $1`, `SELECT $1`,
  `$1 = 'acme'` under an `OR`) is `E_PARAM_UNBOUND` (rule
  `params.tenant_reuse`). Such a use could change the type PostgreSQL infers
  for the parameter, and with it how the tenant value is compared. For
  example, `float8` rounds a large `bigint` tenant ID, so a neighbouring
  tenant's rows could match.
- A literal where a tenant parameter is expected is not accepted
  (`E_TENANT_MISMATCH`, or `E_TENANT_WRITE` in `INSERT ... VALUES`), so a model
  that learned a tenant ID cannot use it.

### Literal mode

The model writes the tenant value as a literal:

```sql
SELECT id, status FROM orders WHERE tenant_id = 'acme' LIMIT 50
```

The literal must equal the context value **exactly**: no trimming, no case
folding. `'acme '` and `'ACME'` do not match `acme`. A mismatch is
`E_TENANT_MISMATCH`.

- String literals compare by their exact text. Integer literals compare by
  their decimal text (`42` matches context `"42"` or `42`).
- When the catalog knows the column's type, the literal must be compatible with
  it; a string literal compared with an integer column, or the reverse, is
  denied rather than relying on Postgres's implicit casts.
- Parameters (`$n`) are not allowed in literal mode (`E_PARAM_UNBOUND`).

Literal mode means the model must know the tenant ID, which is exactly the
value an attacker would like to change. Prefer bound mode.

## Composite keys

A table can be scoped by several keys, for example an organization and a
workspace:

```yaml
tenancy:
  mode: bound
  keys:
    org: "${ctx.org_id}"
    workspace: "${ctx.workspace_id}"
tables:
  app.documents:
    columns: [id, org_id, workspace_id, title]
    tenant_columns: { org_id: org, workspace_id: workspace }
```

Every tenant column needs its own predicate, in the same scope:

```sql
-- allowed: bind_params = [{param 1: org}, {param 2: workspace}]
SELECT id, title FROM documents
WHERE org_id = $1 AND workspace_id = $2 LIMIT 20

-- denied: E_TENANT_MISSING (no workspace predicate)
SELECT id, title FROM documents WHERE org_id = $1 LIMIT 20
```

A row-value comparison such as `(org_id, workspace_id) = ($1, $2)` is not
recognized; write separate conjuncts.

## Sets of tenant values

The context value for a key can be a list, for example a parent organization
that may see its child organizations:

```json
{ "tenant_id": ["acme", "acme-eu", "acme-us"] }
```

Then:

- **Bound mode:** write `a.col = ANY($n)`. HaltSQL returns the whole list as
  the value to bind (`"value": ["acme", "acme-eu", "acme-us"]`); bind it as a
  Postgres array. With a set-valued context, `a.col = $n` and `a.col IN ($n)`
  are not proofs (`E_TENANT_MISSING`; the hint says to use `= ANY($n)`).
- **Literal mode:** `a.col = 'acme-eu'` is allowed if the literal is in the
  set; `a.col IN ('acme', 'acme-eu')` is allowed if every listed literal is in
  the set. Any literal outside the set is `E_TENANT_MISMATCH`.

An empty list allows nothing: every tenant-scoped query is denied with
`E_CONTEXT_MISSING`.

## Where the predicate may appear

The predicate must filter the occurrence **in its own scope**:

| Location | Which occurrences it can prove |
|---|---|
| `WHERE` of the scope | Every occurrence in that scope's `FROM` clause and join tree |
| `ON` of an `INNER JOIN` | Occurrences in either operand of that join |
| `ON` of a `LEFT JOIN` | Only occurrences on the right (nullable) side |
| `ON` of a `RIGHT JOIN` | Only occurrences on the left (nullable) side |
| `ON` of a `FULL JOIN` | None |
| `USING (...)` / `NATURAL` | None |
| `HAVING`, select list, `ORDER BY` | None |
| Any other scope (outer query, sibling subquery, other `UNION` branch) | None |

### Why outer predicates do not cover inner occurrences

A filter in an outer query runs **after** the inner query has already read the
table. The inner query can aggregate, join, or reshape rows from every tenant
before the outer filter sees them:

```sql
-- Denied: the filter is outside the subquery that reads orders.
SELECT * FROM (
  SELECT count(*) AS n, max(tenant_id) AS tenant_id FROM orders
) x
WHERE x.tenant_id = $1
LIMIT 1
```

Here `x.tenant_id` is just the largest tenant ID in the table, and `n` counts
every tenant's orders. The outer filter passes as long as the caller's ID is
the largest, so the query would leak a global count. HaltSQL therefore requires
the predicate in the scope that reads `orders`:

```sql
-- Allowed
SELECT * FROM (
  SELECT count(*) AS n FROM orders WHERE tenant_id = $1
) x
LIMIT 1
```

The same applies to CTEs, `LATERAL`, `EXISTS`, `IN (SELECT ...)`, and scalar
subqueries. A correlated reference does not help either:

```sql
-- Denied: o2 has no tenant predicate of its own, even though o does.
SELECT o.id FROM orders o
WHERE o.tenant_id = $1
  AND EXISTS (SELECT 1 FROM orders o2 WHERE o2.customer_id = o.customer_id AND o2.status = 'refunded')
LIMIT 10
```

Add `AND o2.tenant_id = $1` inside the subquery.

Each branch of a set operation is checked separately:

```sql
-- Denied: the second branch has no tenant predicate.
SELECT id FROM orders WHERE tenant_id = $1
UNION ALL
SELECT id FROM orders
LIMIT 10
```

### LEFT JOIN rules

An outer join's `ON` clause decides which rows of the nullable side are
matched; it does **not** remove rows from the preserved side:

```sql
-- Denied: customers (the preserved side) keeps every tenant's rows.
SELECT c.name, o.id
FROM customers c
LEFT JOIN orders o ON o.customer_id = c.id AND c.tenant_id = $1 AND o.tenant_id = $1
LIMIT 10
```

`o.tenant_id = $1` in the `ON` clause does prove `orders` (any `orders` row
that appears matched the condition). `c.tenant_id = $1` in the same `ON` clause
proves nothing about `customers`, because every `customers` row is returned
regardless. Move it to `WHERE`:

```sql
-- Allowed
SELECT c.name, o.id
FROM customers c
LEFT JOIN orders o ON o.customer_id = c.id AND o.tenant_id = $1
WHERE c.tenant_id = $1
LIMIT 10
```

A `WHERE` predicate on the nullable side is also accepted (it also removes the
null-extended rows, so the join behaves like an inner join). For `FULL JOIN`,
both sides need `WHERE` predicates.

## CTEs, views, and functions

- **CTEs:** the CTE body is its own scope and must prove its own occurrences.
  A reference to a CTE by name is not a base table and needs no predicate. CTE
  names shadow table names, following Postgres scoping.
- **Recursive CTEs:** both the anchor and the recursive branch are scopes and
  are checked separately.
- **Views:** a view is an opaque relation with its own policy entry. If it has
  a tenant column in the policy, its occurrences need predicates like a table.
  HaltSQL does not look inside view definitions; make sure the view itself
  exposes only what you intend (or use `security_barrier` views with RLS).
- **Set-returning functions in `FROM`:** must be allowed in `functions`, and
  are not tenant-scoped. Do not allow functions that read tenant tables
  internally.

## Equality propagation

HaltSQL 0.0.3 does **not** propagate equality through joins. This query is
denied, even though it is safe:

```sql
SELECT o.id, c.name
FROM orders o JOIN customers c ON c.id = o.customer_id AND c.tenant_id = o.tenant_id
WHERE o.tenant_id = $1
LIMIT 10
```

Write a direct predicate for each occurrence instead
(`AND c.tenant_id = $1`). Propagation through a union-find over equality
conjuncts is planned for a later release.

## Writes

When writes are enabled for a table:

- `INSERT` must set every tenant column to the tenant value in every row of
  `VALUES`, otherwise `E_TENANT_WRITE`. `INSERT ... SELECT` is not supported
  and is denied (`E_UNSUPPORTED`).
- `UPDATE` may never assign a tenant column (`E_TENANT_WRITE`) and needs a
  tenant predicate in its `WHERE` (`E_TENANT_MISSING`). Tables in
  `UPDATE ... FROM` need their own predicates.
- `DELETE` needs a tenant predicate in its `WHERE`. Tables in
  `DELETE ... USING` need their own predicates.

## Checklist for agents

To pass the tenancy rules, a query should:

1. Give every table an alias.
2. For every tenant-scoped table, in every query level where it appears, add
   `alias.tenant_column = $1` as an `AND` condition in that level's `WHERE`.
3. Never put the tenant condition inside `OR`, `NOT`, `CASE`, or a function.
4. Repeat the condition in every CTE, subquery, `EXISTS`, and `UNION` branch.
5. For `LEFT JOIN`, put the preserved side's condition in `WHERE`.

## Testing your understanding

The attack corpus (`test/corpus/`) contains one case per rule on this page. The
enterprise lab checks these semantics against real Postgres row-level security
as the oracle: any allowed query that returns a row RLS would hide is a failure.
See [testing.md](testing.md).
