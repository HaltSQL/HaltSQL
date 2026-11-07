# Generating row-level security from a policy

`haltsql rls generate` turns a HaltSQL policy into PostgreSQL DDL that enforces
the same rules inside the database: a dedicated role, column-level grants, and
row-level security (RLS) policies keyed on transaction-local settings.
`haltsql rls check` connects to a live database and reports where it has
drifted from the policy.

These are layers 1 and 2 of [defense in depth](defense-in-depth.md). If HaltSQL
has a bug, or the application forgets to call it, the database still enforces
the policy's tables, columns and tenant isolation.

## Quick start

```sh
haltsql rls generate -p policy.yaml --catalog catalog.json -o rls.sql
psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 -f rls.sql        # run as an admin or the table owner
PGPASSWORD=... haltsql rls check -p policy.yaml --catalog catalog.json \
  --dsn "postgres://admin@db:5432/app?sslmode=verify-full"
```

## What gets generated

The output runs in one transaction (`BEGIN` ... `COMMIT`) and works on
PostgreSQL 13 to 17. It is **idempotent**: running it again brings the database
back to the same state. It is **deterministic**: the same policy and options
always produce the same bytes, so you can commit it and review diffs. The
header records the policy name and its `sha256:` version.

| Policy | Generated SQL |
| --- | --- |
| (always) | A `DO` block creates `<role>` with `NOLOGIN NOBYPASSRLS` if it does not exist. If the role exists and is `SUPERUSER` or `BYPASSRLS`, the script raises an error and stops, because RLS would not apply to it. |
| every schema in `tables:` | `REVOKE ALL ON ALL TABLES` and `ON ALL SEQUENCES IN SCHEMA s`, `REVOKE CREATE ON SCHEMA s`, then `GRANT USAGE ON SCHEMA s`. |
| `columns: [a, b]` | `GRANT SELECT (a, b) ON TABLE ...` |
| `columns: "*"` | `GRANT SELECT ON TABLE ...` |
| `writes.insert: true` | `GRANT INSERT (<readable columns>)` (or table-level for `"*"`), plus `USAGE` on the table's owned (serial) sequences. |
| `writes.update: [c, ...]` / `"*"` | `GRANT UPDATE (c, ...)` / `GRANT UPDATE ON TABLE` |
| `writes.delete: true` | `GRANT DELETE ON TABLE ...` |
| tenant-scoped table | `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` (and `FORCE` with `--force-rls`). Then one `haltsql_tenant_<cmd>` policy per allowed command. |

Writes are granted only when the policy's `statements.allow` also includes that
statement kind. `SELECT` is always granted on the readable columns, because
`UPDATE ... WHERE`, `DELETE ... WHERE` and `RETURNING` need it.

The per-command policies are:

| Policy | Clause |
| --- | --- |
| `haltsql_tenant_select` | `FOR SELECT ... USING (pred)` |
| `haltsql_tenant_insert` | `FOR INSERT ... WITH CHECK (pred)` |
| `haltsql_tenant_update` | `FOR UPDATE ... USING (pred) WITH CHECK (pred)` |
| `haltsql_tenant_delete` | `FOR DELETE ... USING (pred)` |

All four names are dropped with `DROP POLICY IF EXISTS` before the allowed ones
are created, so a command the policy no longer allows loses its policy. With
`--drop-existing`, **every** policy on each managed tenant table is dropped
first. Use it when other permissive policies exist: PostgreSQL ORs permissive
policies together, so another policy that applies to the role widens what it
can see.

Global tables (no `tenant_column(s)`) get grants only, with no RLS.

### Tenant predicates

Each tenant column is compared with a custom setting named
`<prefix>.<context_field>`. The prefix comes from `--setting-prefix` (default
`haltsql`). The context field comes from the policy's tenancy keys, so
`tenant: ${ctx.tenant_id}` uses `haltsql.tenant_id`:

```sql
tenant_id = NULLIF(pg_catalog.current_setting('haltsql.tenant_id', true), '')
```

When a table has several tenant columns (a composite key), the comparisons are
joined with `AND`.

**A missing setting matches no rows.** `current_setting(name, true)` returns
NULL when the setting was never set, and `col = NULL` is never true. Once a
session has used the setting, PostgreSQL returns `''` (not NULL) after the
transaction that set it ends. `NULLIF(..., '')` turns that `''` back into NULL,
so a later transaction that forgets to set it still sees nothing. The
integration test checks both cases.

**Set-valued context.** For a context field that carries several tenants (for
example a parent org and its children, `{ "tenant_ids": ["acme", "acme-eu"] }`),
pass `--set-field tenant_ids`. The setting then holds the values joined with
commas, and the predicate becomes:

```sql
tenant_id = ANY (pg_catalog.array_remove(
  pg_catalog.string_to_array(NULLIF(pg_catalog.current_setting('haltsql.tenant_ids', true), ''), ','), ''))
```

Empty elements are ignored, and an empty list matches nothing. Tenant values
must not contain a comma. A set field is never guessed. Without `--set-field`,
a comma-joined value is compared as one string and matches nothing, which fails
closed. The generator warns when a field name ends in `_ids` and has no
`--set-field`.

**Column types.** The setting is text. When the catalog says a tenant column
is not text (`--catalog`, or the policy's own `catalog:`), the setting is cast
to that type, for example `...::int8` or `...::int8[]` for sets. A value that
does not parse raises an error (`22P02`), which also fails closed. Without
type information the setting is compared as text and the generator prints a
warning. If the column is actually `bigint`, `CREATE POLICY` fails with
"operator does not exist", so the mistake is loud. Array-typed tenant columns
and type names with quotes are rejected.

### Identifiers

Every identifier is quoted exactly as PostgreSQL's `quote_ident()` would quote
it. A name stays bare only if it is lower-case ASCII letters, digits and
underscores, and is not a reserved, column-name or type/function-name keyword
of the PostgreSQL 17 grammar. So `app."Customers"`, `"TenantId"`, `"user"`,
`"order"` and `"select"` are quoted, while `name` and `action` are not.
Embedded double quotes are doubled. String literals double single quotes, and
use `E'...'` when the value contains a backslash. `DO` bodies use a
dollar-quote tag that does not occur in the body.

## The session preamble (application side)

The generated header documents this. In the **same transaction** as the SQL
that HaltSQL allowed, the application sets each setting from the **same
context values it passed to HaltSQL**. These come from its authenticated
session, never from the model or the prompt. Then it switches to the role:

```sql
BEGIN;
SELECT pg_catalog.set_config('haltsql.tenant_id', $1, true);   -- $1 = ctx.tenant_id
SET LOCAL ROLE haltsql_agent;
<the exact SQL HaltSQL allowed, binding verdict.bind_params>
COMMIT;
```

- `set_config(name, value, true)` is transaction-local, like `SET LOCAL`. Pass
  the value as a bind parameter. `SET LOCAL haltsql.tenant_id = 'acme'` works
  too, but the value must then be written as a correctly quoted SQL literal.
- For set fields: `set_config('haltsql.tenant_ids', array_to_string($1::text[], ','), true)`.
- Do not use session-level `SET` or `set_config(..., false)`. A pooled
  connection would carry the tenant into the next request.
- HaltSQL denies `SET`, `set_config()` and `RESET` in agent SQL, so the model
  cannot change these settings.
- The login role the application uses must be able to `SET ROLE` to the agent
  role (`GRANT haltsql_agent TO app_login;`). The generated role is `NOLOGIN`.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `-p, --policy FILE` | (required) | Policy file. |
| `--catalog FILE` | policy's `catalog:` | Snapshot used for tenant column types. |
| `--role ROLE` | `haltsql_agent` | Role the grants and policies are for. `public`, `none`, `current_user` and similar, and names starting with `pg_`, are refused. |
| `--setting-prefix P` | `haltsql` | Setting namespace. Use dot-separated names of letters, digits and underscores. |
| `--set-field FIELD` | none | Context field holding a set (repeatable). Must be a tenancy context field of the policy. |
| `--owner-role ROLE` | none | Run the table DDL under `SET LOCAL ROLE ROLE`, the role that owns the tables. Only owners may enable RLS and create policies. Role creation still runs as the invoking user. |
| `--force-rls` | off | `FORCE ROW LEVEL SECURITY`: the table owner is subject to RLS too. With no policy for the owner, the owner then sees no rows. |
| `--drop-existing` | off | Drop every existing policy on managed tenant tables first. |
| `-o, --output FILE` | stdout | Write the SQL to a file. |
| `--json` | off | Print the plan as JSON (tables, grants, predicates, settings, warnings) with the SQL, or with `output` when `-o` is given. |

Exit codes: `0` success, `2` usage error, unloadable policy or catalog, or
invalid option. Warnings go to stderr.

## Checking for drift

```sh
PGPASSWORD=... haltsql rls check -p policy.yaml --dsn postgres://admin@db/app [--role ...] [--json]
```

Pass the same `--role`, `--setting-prefix`, `--set-field`, `--catalog` and
`--force-rls` that you used to generate. The check runs in a `READ ONLY`
transaction that is rolled back, and it only reads the system catalogs and the
`has_*_privilege` functions. Privileges are the role's **effective**
privileges, so grants to `PUBLIC` and to roles it is a member of count too.

| Kind | Severity | Meaning |
| --- | --- | --- |
| `role_missing` | critical | The role does not exist. |
| `role_bypasses_rls` | critical | The role is `SUPERUSER` or `BYPASSRLS`. |
| `role_can_login` | warning | The role can log in directly. |
| `schema_missing` / `table_missing` / `column_missing` | warning | Something the policy names does not exist. |
| `missing_grant` | warning | The database grants less than the policy (fails closed). |
| `over_broad_grant` | critical | Schema `CREATE`; table-level `SELECT`/`INSERT`/`UPDATE` where the policy lists columns; extra columns; `DELETE`/`TRUNCATE`/`REFERENCES`/`TRIGGER` not allowed; any privilege on a table outside the policy. |
| `rls_disabled` | critical | A tenant-scoped table has RLS off. |
| `rls_not_forced` | warning | `--force-rls` was requested, but the table is not FORCEd. |
| `role_owns_table` | critical | The role owns a tenant table, so RLS does not apply to it. |
| `policy_missing` / `policy_mismatch` | critical | A `haltsql_tenant_*` policy is absent, or has the wrong command, roles, or permissive flag, or a different `USING`/`WITH CHECK` expression. |
| `unexpected_policy` | warning | A `haltsql_tenant_*` policy exists for a command the policy does not allow. |
| `foreign_policy` | critical | Another permissive policy applies to the role (directly, through membership, or to `PUBLIC`) and widens what it can see. |

The expression comparison is a heuristic over `pg_get_expr` output. Each tenant
column and its setting literal must appear, with exactly one `current_setting`
per column. Nothing that could widen a conjunction may appear (`OR`, `NOT`,
`IS`, `CASE`, or an extra `true`).

Exit codes: `0` no drift, `1` drift, `2` usage, load or connection error.

### Connecting

`--dsn` (or `HALTSQL_DSN`) takes `postgres://user[:password]@host[:port]/db?sslmode=...&connect_timeout=N`.
Prefer `PGPASSWORD` over a password in the URL, because command lines are
visible to other users. Defaults follow libpq: `localhost`, port `5432`, user
`$PGUSER` or `$USER`, database equal to the user name, and `sslmode=prefer`.

HaltSQL ships its own small client instead of `pgx`, because `pgx` cannot do
SCRAM-SHA-256, the default since PostgreSQL 14. The client supports:

- SCRAM-SHA-256. The server's signature is verified in constant time, and a
  server that skips the final SCRAM step is rejected.
- MD5.
- Cleartext passwords, only over TLS.
- `sslmode=disable|prefer|require|verify-full`. `verify-ca` is treated as
  `verify-full`, which uses the system trust store and checks the host name.

Passwords never appear in output or error messages. The DSN is always shown
redacted.

## Limitations

- Policy names are fixed per table (`haltsql_tenant_<cmd>`). Generating for a
  **second role** over the same tables replaces the first role's policies. Use
  one agent role per database, or one role per policy over disjoint tables.
- RLS is enforced on tables and partitioned tables. Views run with their
  owner's privileges unless created with `security_invoker` (PostgreSQL 15+),
  so do not list views as tenant-scoped tables.
- `REVOKE` and `GRANT` only touch the role named. Grants to `PUBLIC` (for
  example functions and the `public` schema on PostgreSQL 14 and older) are
  not changed. `rls check` reports table privileges that reach the role
  through `PUBLIC`.
- Function privileges, `statement_timeout` and other role settings are out of
  scope. See [defense in depth](defense-in-depth.md).

## Tests

- `test/rlsgen/golden/*.sql`: golden output for `test/fixtures/policies/`
  `saas`, `composite`, `hierarchical` (with `--set-field tenant_ids`), `writes`
  and `mixed_case`, plus `options.sql`, which uses every option with a quoted
  role name. Every golden file must parse with the bundled PostgreSQL 17
  parser. To accept an intended change:
  `dune build @test/rlsgen/runtest --auto-promote`.
- `test/rlsgen/t_integration.ml`: runs against `make -C lab up`, or
  `HALTSQL_TEST_PG_DSN`. It creates `haltsql_rls_test`, loads
  `lab/schemas/saas_shared.sql` and applies the generated SQL twice. Then, as
  the role, it checks the following:
  - each tenant sees only its own rows;
  - a missing or reset setting sees nothing;
  - set fields work;
  - denied columns and tables raise `42501`;
  - inserts for another tenant and moving a row to another tenant fail;
  - other tenants' rows cannot be updated or deleted.

  `rls check` must report no drift, and then exactly the drift the test
  injects. The test drops its database and roles afterwards, and it is
  skipped with a message when Postgres is not reachable.
