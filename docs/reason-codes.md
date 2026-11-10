# Reason codes

Every denial carries one or more reasons, each with a stable `code`. Codes are
part of HaltSQL's public API: they are never renamed or reused, and new codes
may be added in minor releases. Clients should match on `code` and treat any
code they do not recognize as a denial.

The examples below assume this policy unless noted otherwise:

```yaml
apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: example }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 1000 }
limits: { max_joins: 4 }
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name]
    tenant_column: tenant_id
  app.currencies:
    columns: [code, name]
functions: { presets: [aggregates] }
```

and the context `{"tenant_id": "acme"}`.

The "Fix" column is written for the agent that produced the SQL. The `hint`
field of each reason carries a query-specific version of the same advice.

## Summary

| Code | Meaning |
|---|---|
| [`E_PARSE`](#e_parse) | SQL did not parse |
| [`E_EMPTY`](#e_empty) | No statement |
| [`E_LIMIT`](#e_limit) | Byte, depth, or node-count limit exceeded |
| [`E_MULTI_STATEMENT`](#e_multi_statement) | More than one statement |
| [`E_STATEMENT_KIND`](#e_statement_kind) | Statement kind not allowed |
| [`E_DATA_MODIFYING_CTE`](#e_data_modifying_cte) | Write inside a CTE |
| [`E_TABLE_DENIED`](#e_table_denied) | Relation not in the allowlist |
| [`E_COLUMN_DENIED`](#e_column_denied) | Column not allowed |
| [`E_COLUMN_UNRESOLVED`](#e_column_unresolved) | Ambiguous or unknown column |
| [`E_FUNCTION_DENIED`](#e_function_denied) | Function not in the allowlist |
| [`E_OPERATOR_DENIED`](#e_operator_denied) | Operator not in the allowlist |
| [`E_CAST_DENIED`](#e_cast_denied) | Cast to a type that is not allowed |
| [`E_TENANT_MISSING`](#e_tenant_missing) | Tenant-scoped relation without a provable tenant predicate |
| [`E_TENANT_MISMATCH`](#e_tenant_mismatch) | Tenant literal differs from the context value |
| [`E_TENANT_WRITE`](#e_tenant_write) | Write sets or changes a tenant column incorrectly |
| [`E_CONTEXT_MISSING`](#e_context_missing) | A context value the policy needs was not supplied |
| [`E_PARAM_UNBOUND`](#e_param_unbound) | A `$n` parameter HaltSQL cannot bind |
| [`E_LIMIT_REQUIRED`](#e_limit_required) | `LIMIT` missing |
| [`E_LIMIT_TOO_HIGH`](#e_limit_too_high) | `LIMIT` too large or not a constant |
| [`E_LOCKING_CLAUSE`](#e_locking_clause) | `FOR UPDATE` / `FOR SHARE` |
| [`E_SELECT_INTO`](#e_select_into) | `SELECT ... INTO` |
| [`E_JOIN_BUDGET`](#e_join_budget) | More joins than `limits.max_joins` |
| [`E_WRITE_DENIED`](#e_write_denied) | Write to a table or column the policy does not allow |
| [`E_UNSUPPORTED`](#e_unsupported) | Syntax HaltSQL does not analyze |
| [`E_INTERNAL`](#e_internal) | Analyzer bug; fails closed |
| [`E_EXTERNAL_POLICY`](#e_external_policy) | Denied by the external policy engine (OPA) |

## Input and parsing

### E_PARSE

The SQL is not valid PostgreSQL. `loc` points at the parser's error position
when it is known. Input containing a NUL byte is also rejected with this code.

```sql
SELEC id FROM orders WHERE tenant_id = $1 LIMIT 10
```

**Fix:** correct the syntax. Send only SQL, with no Markdown fences or prose
around it.

### E_EMPTY

The input contains no statement (empty, whitespace, or only comments).

```sql
-- just a comment
```

**Fix:** send exactly one SQL statement.

### E_LIMIT

The SQL exceeds `limits.max_bytes`, `limits.max_depth`, or `limits.max_nodes`.

```sql
SELECT id FROM orders WHERE tenant_id = $1 AND id IN (1, 2, 3, /* ...20,000 more... */) LIMIT 10
```

**Fix:** make the query smaller: fewer literals in `IN` lists, less nesting,
fewer subqueries.

### E_MULTI_STATEMENT

More than one statement was sent. HaltSQL verifies exactly one statement per
request.

```sql
SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10; DROP TABLE orders
```

**Fix:** send a single statement, with no semicolon-separated extras.

## Statement shape

### E_STATEMENT_KIND

The statement kind is not in `statements.allow`. DDL, `DO`, `CALL`, `COPY`,
`SET`, `LOCK`, `VACUUM`, `LISTEN`, transaction control, and similar statements
are always denied. Also used for `EXPLAIN` when `allow_explain` is false, and
for `EXPLAIN ANALYZE`.

```sql
DELETE FROM orders WHERE tenant_id = $1
```

**Fix:** use only the allowed statement kinds (usually a single `SELECT`).

### E_DATA_MODIFYING_CTE

A `WITH` clause contains `INSERT`, `UPDATE`, or `DELETE`, which would modify
data even though the outer statement is a `SELECT`.

```sql
WITH d AS (DELETE FROM orders WHERE tenant_id = $1 RETURNING id)
SELECT id FROM d LIMIT 10
```

**Fix:** remove the data-modifying CTE. Read-only CTEs (`WITH x AS (SELECT ...)`)
are fine.

### E_LOCKING_CLAUSE

The query uses `FOR UPDATE`, `FOR NO KEY UPDATE`, `FOR SHARE`, or
`FOR KEY SHARE`, which take row locks.

```sql
SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10 FOR UPDATE
```

**Fix:** remove the locking clause.

### E_SELECT_INTO

`SELECT ... INTO new_table` creates a table.

```sql
SELECT id INTO copy_of_orders FROM orders WHERE tenant_id = $1 LIMIT 10
```

**Fix:** remove `INTO`; return the rows instead.

### E_JOIN_BUDGET

The statement has more joins than `limits.max_joins`. Every join counts,
including comma-separated `FROM` lists and `CROSS JOIN`.

```sql
SELECT o.id FROM orders o, customers c
WHERE o.tenant_id = $1 AND c.tenant_id = $1 LIMIT 10
```

**Fix:** join with an explicit condition (`JOIN customers c ON c.id = o.customer_id`)
and use fewer joins.

## Tables, columns, functions

### E_TABLE_DENIED

A relation is not listed in `tables`. System schemas (`pg_catalog`,
`information_schema`, and so on) are always denied. Catalog-qualified names
(`db.schema.table`) are denied too.

```sql
SELECT usename FROM pg_catalog.pg_user LIMIT 10
```

**Fix:** query only the tables listed in the policy. Do not query system
catalogs.

### E_COLUMN_DENIED

A column that the policy does not allow is referenced anywhere in the query,
or `*` / a whole-row reference expands to include one.

```sql
SELECT email FROM customers WHERE tenant_id = $1 LIMIT 10
```

```sql
SELECT * FROM customers WHERE tenant_id = $1 LIMIT 10   -- if the table has columns beyond id, tenant_id, name
```

**Fix:** reference only allowed columns, and list them explicitly instead of
using `*`.

### E_COLUMN_UNRESOLVED

A column reference is ambiguous (it exists in more than one relation in scope)
or does not exist in any relation in scope. HaltSQL denies rather than guess.

```sql
SELECT id FROM orders o JOIN customers c ON c.id = o.customer_id
WHERE o.tenant_id = $1 AND c.tenant_id = $1 LIMIT 10
```

**Fix:** qualify every column with its table alias (`o.id`), and check the
column name against the schema.

### E_FUNCTION_DENIED

A function is not in `functions.allow` or an enabled preset. This includes
aggregates, window functions, and set-returning functions in `FROM`. Functions
that run a SQL string themselves (`ts_rewrite`, `ts_stat`, `query_to_xml`,
`dblink`, ...) are denied even when allowlisted (rule `functions.dynamic_sql`).

```sql
SELECT pg_sleep(10)
```

```sql
SELECT set_config('app.tenant_id', 'globex', false)
```

**Fix:** use only allowed functions. Do not call functions that change
settings, sleep, read files, or access other databases.

### E_OPERATOR_DENIED

An operator is not in the policy's operator list.

```sql
SELECT id FROM orders WHERE tenant_id = $1 AND (id # 1) = 0 LIMIT 10   -- # (bitwise XOR) is not in the default list
```

**Fix:** use an allowed operator, or rewrite the condition with comparison and
arithmetic operators.

### E_CAST_DENIED

A cast targets a type that is not in the policy's `casts` allowlist (casts are
denied by default), or a type in `deny_casts`, such as the `reg*`
object-identifier types that look up catalog objects by name.

```sql
SELECT 'app.orders'::regclass
```

**Fix:** remove the cast. There is no need to reference database objects by
OID.

## Tenancy and context

### E_TENANT_MISSING

A tenant-scoped relation occurs in a scope that does not prove it is filtered
to the caller's tenant. See [tenancy.md](tenancy.md) for the exact rules. Common
causes: no filter; the filter is inside an `OR`, `NOT`, or `CASE`; the filter is
only in an outer query; a `UNION` branch has no filter; the filter is in the
`ON` clause of a `LEFT JOIN` for the preserved side.

```sql
SELECT id FROM orders LIMIT 10
```

```sql
SELECT id FROM orders WHERE tenant_id = $1 OR status = 'open' LIMIT 10
```

```sql
SELECT id FROM (SELECT id, tenant_id FROM orders) o WHERE o.tenant_id = $1 LIMIT 10
```

**Fix:** add `alias.tenant_column = $1` as a top-level `AND` condition in the
`WHERE` clause of the same query level as the table (or in the `ON` clause of
an inner join that attaches it), for every occurrence of every tenant-scoped
table, including inside CTEs, subqueries, and each `UNION` branch.

### E_TENANT_MISMATCH

In literal mode, the tenant literal does not equal the context value. Also used
in bound mode when a tenant predicate uses a literal instead of a parameter.

Context `{"tenant_id": "acme"}`, literal mode:

```sql
SELECT id FROM orders WHERE tenant_id = 'globex' LIMIT 10
```

**Fix:** in literal mode, use exactly the tenant value you were given. In bound
mode, use the placeholder `$1` instead of a literal.

### E_TENANT_WRITE

A write would set or change a tenant column incorrectly: an `INSERT` that does
not set the tenant column to the tenant value in every row, or an `UPDATE`
that assigns a tenant column. (`INSERT ... SELECT` is denied outright as
`E_UNSUPPORTED`.) Only possible when writes are enabled.

```sql
UPDATE orders SET tenant_id = 'globex' WHERE tenant_id = $1 AND id = 7
```

**Fix:** never assign a tenant column in `UPDATE`; in `INSERT`, set it to `$1`
(bound mode) or the context value (literal mode) in every row.

### E_CONTEXT_MISSING

The policy needs a context value (for example `tenant_id`) that the request did
not supply. This is a caller integration error, not a problem with the SQL.

Context `{}`:

```sql
SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10
```

**Fix (application):** always pass the context fields named in the policy's
`tenancy.keys`, taken from the authenticated session. An agent cannot fix this.

### E_PARAM_UNBOUND

The query uses a `$n` placeholder that HaltSQL cannot bind: a parameter that is
not a tenant predicate value, a tenant parameter that is also used outside
its tenant predicate (for example cast with `$1::float8`, which would change
how PostgreSQL types the bound tenant value), a parameter used for two
different tenancy keys, or any parameter in literal mode. HaltSQL only allows placeholders whose value
it supplies in `bind_params`, so the caller never has to bind something the
model chose.

```sql
SELECT id FROM orders WHERE tenant_id = $1 AND status = $2 LIMIT 10
```

**Fix:** use `$n` only for tenant values; write other values as literals
(`status = 'open'`).

## Limits on results

### E_LIMIT_REQUIRED

`require_limit` is set and the query has no `LIMIT` (or uses `LIMIT ALL`).

```sql
SELECT id FROM orders WHERE tenant_id = $1
```

**Fix:** add `LIMIT n` with `n` no larger than the policy maximum.

### E_LIMIT_TOO_HIGH

The `LIMIT` is larger than `require_limit.max`, or is not an integer constant.

```sql
SELECT id FROM orders WHERE tenant_id = $1 LIMIT 100000
```

**Fix:** use a constant `LIMIT` no larger than the maximum. Paginate with
`OFFSET` or keyset conditions if you need more rows.

## Writes

### E_WRITE_DENIED

A write targets a table without the matching `writes` permission, an
`UPDATE` assigns a column not in `writes.update`, an `INSERT` has no explicit
column list, or an `INSERT` names a column that is not in the table's
`columns` list. Only possible when the
statement kind is allowed.

```sql
UPDATE orders SET total_cents = 0 WHERE tenant_id = $1 AND id = 7   -- writes.update: [status]
```

**Fix:** write only to tables and columns the policy allows.

## Fail-closed codes

### E_UNSUPPORTED

The query uses syntax that HaltSQL does not analyze, for example `TABLESAMPLE`,
`XMLTABLE`, `JSON_TABLE`, `ROWS FROM`, or another construct the converter does
not map. HaltSQL denies anything it cannot fully analyze.

`WITH RECURSIVE` is always `E_UNSUPPORTED`: a recursive CTE can produce
unbounded rows, and an outer `LIMIT` does not bound the work done by an
aggregate, `ORDER BY` or `DISTINCT` over it.

```sql
SELECT id FROM orders TABLESAMPLE SYSTEM (10) WHERE tenant_id = $1 LIMIT 10
```

**Fix:** rewrite the query with common SQL constructs. If you believe the
construct is safe and should be supported, open a feature request.

### E_INTERNAL

The analyzer hit an unexpected condition (a bug). The query is denied. Operators
should alert on any occurrence of this code.

**Fix (agent):** try a simpler query. **Fix (operator):** file a bug with the
SQL, policy, and HaltSQL version. If the input looks like a bypass attempt,
report it privately per [SECURITY.md](../SECURITY.md).

## External policy

### E_EXTERNAL_POLICY

Only haltsql-server emits this code, and only when the optional
[`opa`](config-reference.md#opa) check is configured. HaltSQL allowed the
query, then Open Policy Agent denied it, or OPA could not be asked (timeout,
error, undefined decision) and `opa.on_error` is `deny`. The rule is always
`opa.decision`; the message carries OPA's reasons (sanitized) or says the
external check failed. In a shadow-mode policy the reason appears in
`shadow_reasons` and the query stays allowed. OPA can never turn a HaltSQL
denial into an allow, so this code never appears next to an allow.

**Fix (agent):** the query is outside what the organization's OPA policy
allows for this caller; do not retry it unchanged. **Fix (operator):** read
the OPA decision log and the `haltsql_opa_decisions_total` metric; see
[opa.md](opa.md).
