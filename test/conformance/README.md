# Conformance: sql-guardrail

PLAN.md §8.1 asks for "the same verdicts as sql-guardrail's test cases (MIT,
attributed), each intentional difference documented". This directory holds that
port.

## Source and attribution

- Project: **sql-guardrail** — <https://github.com/nickusevich/sql-guardrail>
  ("SQL safety check for LLM-generated queries. Validates against a policy
  before the query reaches your database.")
- Commit: `eadfb9d0c725f4960621a7c67c23219103710c5b` (2026-06-09), shallow clone
- License: MIT, `Copyright (c) 2026 nickusevich`. The MIT notice is reproduced
  in the header of every `*.suite.yaml` file here.
- What was taken: SQL strings and the expected allow/deny intent from
  `tests/malicious/*.sql`, `tests/benign/*.sql`, `tests/test_corpus.py`,
  `tests/test_security.py` and `tests/unit/*.py`. No code was copied or run;
  the clone was read as data only. Their policies were rewritten in our
  format (`policies/`), against a catalog snapshot we wrote
  (`catalogs/sqlg.json`).
- Every case carries a `sqlg:<file>::<test>[param]` tag naming the original test.

The suites are generated from the ported data by a small script (kept out of
the repo). Regenerate rather than hand-editing, or hand-edit and drop the
"GENERATED" line from the header.

## Files

| Suite | Policy | Cases | Ported from |
|---|---|---:|---|
| `sql_guardrail.suite.yaml` | `sqlg_standard.yaml` | 259 | `tests/malicious/*` (46), `tests/benign/*` (10), `test_corpus.py`, `test_security.py` sections 2–9 |
| `sql_guardrail_nolimit.suite.yaml` | `sqlg_nolimit.yaml` | 132 | `unit/test_statement_kinds.py`, `test_readonly.py`, `test_preflight.py`, `test_predicates.py`, `test_cast_tolerance.py`, `test_predicate_advanced.py`, `TestOuterScopeAliasResolution`, `TestNaturalJoin` |
| `sql_guardrail_robustness.suite.yaml` | `sqlg_nolimit.yaml` | 3 | `TestRobustness` large inputs (kept apart so a loader size limit cannot take down other suites) |
| `sql_guardrail_writes.suite.yaml` | `sqlg_writable.yaml` | 29 | `writable_policy` DML tests, `test_locks.py`, MERGE cases |
| `sql_guardrail_functions.suite.yaml` | `sqlg_fn_count.yaml` | 22 | `TestFunctionAllowlist` with `allowed_functions: [count]` |
| `sql_guardrail_functions_small.suite.yaml` | `sqlg_fn_small.yaml` | 9 | operator-keyword (AND/OR/CASE/EXISTS) regression tests |
| `sql_guardrail_functions_canonical.suite.yaml` | `sqlg_fn_canonical.yaml` | 5 | canonical-name allowlist tests |
| `sql_guardrail_deny_only.suite.yaml` | `sqlg_deny_only.yaml` | 7 | deny-only column policy, `TestPublicApi` |
| `sql_guardrail_schemas.suite.yaml` | `sqlg_schemas.yaml` | 10 | schema-qualified policy entries |
| `sql_guardrail_schemas_tenant.suite.yaml` | `sqlg_schemas_tenant.yaml` | 5 | per-schema `require_predicate` |
| `sql_guardrail_sets.suite.yaml` | `sqlg_set.yaml` | 6 | `op: IN` tenant sets (adapted to bound `= ANY($1)`) |
| **Total** | | **487** | 180 allow, 307 deny |

Tag counts: `differs` 85 (different outcome), `differs-code` 44 (same outcome,
different reason), `sqlg-adapted` 61 (SQL changed or a companion case added
on the tenant table; the case name says how), `ambiguous` 26 (HaltSQL's spec
leaves the outcome or the reason code open; these assert only what is
certain, usually "deny" with no codes).

## Concept mapping

| sql-guardrail | HaltSQL |
|---|---|
| `verify(sql, policy, context=)` | `Haltsql.verify policy ctx sql` |
| `read_only: true` | `statements: { allow: [select] }` |
| `read_only: false` | `statements: { allow: [select, insert, update, delete] }` **plus** per-table `writes:` |
| `tables[*].name` / `schema` | key `schema.table` under `tables:`; unqualified SQL resolves via `search_path` |
| `allow_columns` | `columns:` (checked against the catalog snapshot) |
| `deny_columns` | absence from `columns:` (we are allowlist-only) |
| `require_predicate {column, op: "=", value: "${tenant_id}"}` | `tenant_column` + `tenancy: { mode: literal, keys: { tenant: "${ctx.tenant_id}" } }` |
| `require_predicate {op: IN, value: "${tenant_ids}"}` | context list + bound mode `col = ANY($n)` (`sqlg_set.yaml`) |
| `large: true` (per table) | `require_limit: { max: N }` (global, every outermost SELECT) |
| `limits.max_limit_value` | `require_limit.max` |
| `limits.max_sql_length` / `max_ast_nodes` | `limits.max_bytes` / `limits.max_nodes` |
| `limits.max_joins` | `limits.max_joins` |
| `limits.max_subquery_depth` | no direct equivalent; `limits.max_depth` bounds parse-tree depth |
| `limits.max_offset_value` | none (OFFSET is not capped) |
| `allowed_functions` (opt-in) | `functions: { presets, allow }` (always on, deny by default) |
| `forbid.select_star` | none as such: `*` / `t.*` / whole-row refs are allowed iff every catalog column is readable |
| `forbid.always_true_predicates` | none: tautologies cannot widen a tenant proof (OR breaks it) |
| `forbid.cartesian_join` | `limits.max_joins` (`E_JOIN_BUDGET`) |
| `forbid.recursive_cte` | always on: `WITH RECURSIVE` is denied (`E_UNSUPPORTED`) |

| Violation code | Reason code |
|---|---|
| `PARSE_ERROR` | `E_PARSE`, `E_EMPTY` (empty/comment-only input), `E_LIMIT` (oversized) |
| `MULTI_STATEMENT` | `E_MULTI_STATEMENT` |
| `STATEMENT_FORBIDDEN`, `WRITE_FORBIDDEN` | `E_STATEMENT_KIND`; `E_SELECT_INTO`; `E_WRITE_DENIED` |
| `DATA_MODIFYING_CTE` | `E_DATA_MODIFYING_CTE` |
| `LOCK_FORBIDDEN` | `E_LOCKING_CLAUSE` |
| `TABLE_DENIED` | `E_TABLE_DENIED` |
| `COLUMN_DENIED`, `SELECT_STAR` | `E_COLUMN_DENIED`; unknown/unresolvable columns `E_COLUMN_UNRESOLVED` |
| `FUNCTION_NOT_ALLOWED` | `E_FUNCTION_DENIED` (also `CURRENT_USER` & co.) |
| `MISSING_REQUIRED_PREDICATE` | `E_TENANT_MISSING`; wrong literal `E_TENANT_MISMATCH` |
| `POLICY_ERROR` (missing context var) | `E_CONTEXT_MISSING` |
| `LIMIT_REQUIRED` / `LIMIT_EXCEEDED` | `E_LIMIT_REQUIRED` / `E_LIMIT_TOO_HIGH` |
| `MAX_JOINS_EXCEEDED`, `CARTESIAN_JOIN` | `E_JOIN_BUDGET` |
| `ALWAYS_TRUE_PREDICATE`, `RECURSIVE_CTE`, `NATURAL_JOIN_FORBIDDEN`, `OFFSET_EXCEEDED`, `MAX_SUBQUERY_DEPTH` | no equivalent |

## Intentional differences

1. **No tautology rule.** sql-guardrail rejects `WHERE id = 1 OR 1 = 1` on any
   table. HaltSQL only cares whether each tenant-scoped relation has a provable
   tenant conjunct; on the global `users` table the OR is harmless and the query
   is allowed (`differs`). Every tautology leaf is also ported against the
   tenant table (`orders ... WHERE account_id = 42 OR (<leaf>)`), where it is
   denied with `E_TENANT_MISSING` (`sqlg-adapted`).
2. **`LIMIT` is global.** `require_limit` applies to the outermost SELECT of every
   query, not only to queries touching a `large` table; a LIMIT inside a CTE or
   inside each set-operation branch does not count. So `benign/cte_aggregation.sql`,
   `benign/union_simple.sql`, `benign/except_simple.sql` and
   `benign/intersect_simple.sql` are denied with `E_LIMIT_REQUIRED`. `LIMIT 0`
   is a constant within the cap, so it is allowed.
3. **No OFFSET cap** (`malicious/offset_dos.sql` is allowed). The set-op OFFSET
   bypasses are still denied, because they have no outer LIMIT.
4. **No subquery-depth or cartesian rules.** Cartesian products of tenant tables
   fail the per-occurrence tenant proof instead; `limits.max_joins` caps size.
5. **Cast on the column side never proves tenancy.** sql-guardrail accepts
   `account_id::text = '42'`; we deny with `E_TENANT_MISSING` (a cast can change
   equality semantics, e.g. text vs numeric).
6. **LEFT JOIN ON proves the nullable side.** `users u LEFT JOIN orders o ON ...
   AND o.account_id = 42` is allowed: rows of `orders` that reach the output are
   filtered; the preserved side's unmatched rows bring no `orders` data. The ON
   clause does *not* prove the preserved side (adapted companion case).
7. **Functions are deny-by-default.** With no `allowed_functions`, sql-guardrail
   allows any function; we deny `some_unknown_fn` with `E_FUNCTION_DENIED`.
   Conversely, casts (`cast(x AS text)`, `x::text`) and syntax nodes are not
   functions for us; only `reg*` casts are denied.
8. **Star is about columns, not syntax.** `SELECT *` is allowed when every
   catalog column of the table is readable; on these fixtures the catalog has
   extra columns, so star is denied with `E_COLUMN_DENIED` rather than
   `SELECT_STAR`. An output alias that happens to be named `password_hash`
   reads nothing and is allowed.
9. **Writes need per-table grants and `INSERT ... SELECT` is unsupported.**
   `INSERT ... VALUES` must set the tenant column to the tenant value
   (`E_TENANT_WRITE` otherwise); `INSERT ... SELECT` is `E_UNSUPPORTED`;
   `MERGE` is always `E_STATEMENT_KIND`; locking clauses are denied even when
   writes are enabled.
10. **Schemas are exact.** An unqualified policy entry does not match any schema:
    tables resolve through the policy's `search_path`, and an unlisted schema is
    `E_TABLE_DENIED`.
11. **Empty input is `E_EMPTY`**, not a parse error; non-PostgreSQL syntax
    (`QUALIFY`, `CONNECT BY`, `count(DISTINCT *)`) is `E_PARSE`.
12. **Literal tenancy compares typed values.** Context values are strings; a
    literal matches when it equals the context value after normalizing against
    the catalog column type (`account_id int8`): `42` and `'42'` match `"42"`;
    `43`, `'abc'`, `''`, `42.5` do not.
13. **`IN (42)`** (a single-element IN list) is treated as an equality conjunct
    and allowed, as in sql-guardrail; `42 = account_id` is treated as equality
    too (both tagged `ambiguous`).
14. **`COALESCE` is syntax, not a function.** It is always allowed, even when
    the policy's function allowlist does not list it (`differs`).
15. **`WITH RECURSIVE` is always denied** (`E_UNSUPPORTED`), with or without an
    outer LIMIT, because an aggregate or `ORDER BY` over an infinite recursive
    CTE defeats the LIMIT. This matches sql-guardrail's default.
16. **A tenant literal in bound mode is `E_TENANT_MISMATCH`** (the analyzer
    reports "compared to a literal, but this policy uses bound mode"), not
    `E_TENANT_MISSING`.

## Not ported (and why)

- `tests/unit/test_cli.py`, `test_config.py`, `test_result.py`, `tests/server/*`:
  CLI/HTTP/result-object behaviour of their tool, not verdict semantics.
- `TestPolicyHygiene` (unknown policy keys rejected): a loader property, covered
  by the policy-loader tests, not by `TestSuite` cases.
- `TestPublicApi` category mapping, error-message wording tests
  (`test_error_message_names_the_alias`, no-double-flag counts): no equivalent
  in our reason model (we assert presence of codes, not counts or wording).
- NUL-byte input: a YAML document cannot carry a raw NUL; covered by the fuzz
  harness instead.
- Float/bool coercion rows of `test_literal_coercion` (`float=int`, `int=float`,
  `float=float`, `int=quoted-float`, bool context): our context values are
  strings/ints only, and float normalization of tenant ids is unspecified.
- `test_flipped_inequality_does_not_misapply_to_order_ops`, BETWEEN/`<`
  `require_predicate` ops: we only support equality (and `= ANY`) tenant proofs.
- Constant leaves `(1 & 1) = 1` (bitwise operator membership in the default
  operator set is unspecified) and `substring('abc' from 1 for 1)` (SQL-syntax
  function naming is unspecified).
- Cartesian/max-depth/max-joins unit tests on placeholder tables `a`, `b`, `c`,
  `d` with toggles (`forbid.cartesian_join: false`, `max_subquery_depth`):
  those tables are not in any policy, so every case collapses to
  `E_TABLE_DENIED`; a few representatives are kept as `differs-code`.
- `test_cross_schema_large_tables_each_fire_limit_required`: asserts the number
  of violations.

Roughly 75 parametrized test instances were skipped for the reasons above.

## Ambiguities found while porting

These cases are tagged `ambiguous` and assert as little as possible:

- `LIMIT ALL`: denied, but `E_LIMIT_REQUIRED` vs `E_LIMIT_TOO_HIGH` is open.
- `NATURAL JOIN`: implicit join columns may be reported as denied columns,
  unsupported syntax, or a tenant gap.
- Comma joins / `CROSS JOIN` without a predicate: `Reason.E_JOIN_BUDGET` is
  documented as "too many joins or an unconstrained cross join", but the
  analyzer brief only mentions `max_joins`.
- `UPDATE ... FROM` / `DELETE ... USING`: unspecified (we only assert deny).
- Literal-mode string vs integer tenant literals (`'42'` against an `int8`
  column) and `IN (42)` / `42 = account_id` shapes.
- Branch-level `LIMIT` inside a parenthesized set operation.

## Open disagreements

None. The disagreements found while porting were resolved on 2026-11-07:

- Unbounded `WITH RECURSIVE`: now denied (`E_UNSUPPORTED`), see difference 15.
- `INSERT` into a column the policy does not expose (e.g. `users.password_hash`):
  now `E_WRITE_DENIED`. Inserted columns must appear in the table's `columns`
  list.
