# Defense in depth

HaltSQL should be **one of three layers**, never the only one:

1. **Database role:** a dedicated, read-only role with `SELECT` granted on
   exactly the policy's tables and columns, and a `statement_timeout`.
2. **Postgres row-level security (RLS):** tenant policies keyed on a session
   setting that your application sets, not the model.
3. **HaltSQL:** blocks bad queries before they reach the database, gives the
   agent a specific reason it can act on, and leaves an audit trail.

Each layer covers the others' failure modes. If HaltSQL has a bug, the role and
RLS still hold. If someone misconfigures RLS, HaltSQL still denies the query and
says why. If the application forgets to call HaltSQL, the database still
enforces the basics.

The examples below match this policy:

```yaml
search_path: [app]
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name, created_at]
    tenant_column: tenant_id
  app.currencies:
    columns: "*"
```

## Layer 1: a dedicated read-only role

Create a role used only for agent queries. It cannot log in directly with an
owner's privileges, cannot write, and can read only what the policy allows.

```sql
-- Run as an administrator.
CREATE ROLE agent_readonly LOGIN PASSWORD 'use-a-secret-manager'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 20;

-- Start from nothing.
REVOKE ALL ON SCHEMA public FROM agent_readonly;
REVOKE ALL ON ALL TABLES IN SCHEMA app FROM agent_readonly;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- default on PG 15+, explicit for older versions

GRANT USAGE ON SCHEMA app TO agent_readonly;

-- Column-level grants: exactly the columns in the policy.
GRANT SELECT (id, tenant_id, customer_id, status, total_cents, created_at)
  ON app.orders TO agent_readonly;
GRANT SELECT (id, tenant_id, name, created_at)
  ON app.customers TO agent_readonly;      -- email and phone are not granted
GRANT SELECT ON app.currencies TO agent_readonly;

-- Session defaults for this role.
ALTER ROLE agent_readonly SET search_path = app;              -- same as the policy's search_path
ALTER ROLE agent_readonly SET default_transaction_read_only = on;
ALTER ROLE agent_readonly SET statement_timeout = '5s';
ALTER ROLE agent_readonly SET lock_timeout = '1s';
ALTER ROLE agent_readonly SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE agent_readonly SET work_mem = '16MB';
ALTER ROLE agent_readonly SET temp_file_limit = '256MB';      -- requires superuser to set
```

Also review function privileges. By default, `PUBLIC` can execute most
functions. Revoke the dangerous ones from `PUBLIC` (or at least from this role's
reach) if your security baseline allows it:

```sql
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_sleep(double precision) FROM PUBLIC;
-- pg_read_file, lo_import, lo_export, dblink, etc. are already restricted to
-- superusers or specific roles in current Postgres versions; verify on yours:
SELECT p.oid::regprocedure, p.proacl
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'pg_catalog' AND p.proname IN ('pg_sleep', 'set_config', 'pg_read_file', 'lo_import');
```

Keep the role's `search_path` identical to the policy's `search_path`. If they
differ, an unqualified name could resolve to a different table in Postgres
than the one HaltSQL checked.

## Layer 2: row-level security keyed on a session setting

RLS makes the database itself filter rows to the current tenant. The tenant
comes from a setting your application sets on the connection, from its
authenticated session. The model never sets it, and HaltSQL denies
`set_config()` and `SET` statements so the model cannot change it either.

```sql
ALTER TABLE app.orders    ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.customers ENABLE ROW LEVEL SECURITY;
-- Apply RLS to the table owner too, so a misconfigured role does not bypass it.
ALTER TABLE app.orders    FORCE ROW LEVEL SECURITY;
ALTER TABLE app.customers FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app.orders
  FOR SELECT TO agent_readonly
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY tenant_isolation ON app.customers
  FOR SELECT TO agent_readonly
  USING (tenant_id = current_setting('app.tenant_id', true));
```

`current_setting('app.tenant_id', true)` returns `NULL` when the setting is
missing, so a connection that forgot to set it sees no rows (`tenant_id = NULL`
is never true). If `tenant_id` is not `text`, cast the setting:
`tenant_id = current_setting('app.tenant_id', true)::bigint`.

For sets of tenants (a parent organization seeing its children), store the
list in the setting and compare with `ANY`:

```sql
CREATE POLICY tenant_isolation ON app.orders
  FOR SELECT TO agent_readonly
  USING (tenant_id = ANY (string_to_array(current_setting('app.tenant_ids', true), ',')));
```

### Setting the tenant per request

Set the tenant inside a transaction with `SET LOCAL` (or
`set_config(..., true)`), so it cannot leak to the next request on a pooled
connection:

```sql
BEGIN READ ONLY;
SELECT set_config('app.tenant_id', $1, true);   -- $1 = tenant from the session, bound by your app
-- the verified agent query, exactly as checked, with bind_params bound:
SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50;
COMMIT;
```

This works with PgBouncer in transaction-pooling mode because the setting is
scoped to the transaction.

In bound mode, the same tenant value is bound twice: once by your application
for the RLS setting, and once for the `$n` in `bind_params`. Both come from
your session, never from the model.

## Layer 3: HaltSQL

HaltSQL runs before the query reaches the database:

- It denies queries the other layers would also stop, but with a precise,
  machine-readable reason (`E_COLUMN_DENIED`, `E_TENANT_MISSING`) that the agent
  can use to correct itself, instead of a generic permission error or a silent
  empty result.
- It denies things the other layers do not cover well: multiple statements,
  data-modifying CTEs, costly functions, missing `LIMIT`, unbounded joins.
- It records every decision with the policy version, query fingerprint, and
  SQL hash.

## Putting it together

```python
verdict = haltsql.verify(sql=agent_sql, context={"tenant_id": session.tenant_id})
if not verdict["allowed"]:
    return feedback_to_agent(verdict["reasons"])

with pool.connection() as conn, conn.transaction():
    conn.execute("SET TRANSACTION READ ONLY")
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", [session.tenant_id])
    params = [p["value"] for p in sorted(verdict["bind_params"], key=lambda p: p["param"])]
    rows = conn.execute(agent_sql, params).fetchall()   # the exact verified string
```

See [integrations.md](integrations.md) for complete client examples. The
enterprise lab uses exactly these database-side controls as oracles: if HaltSQL
allows a query that RLS or the column grants would block, the lab reports it as
an escape (see [testing.md](testing.md)).

## Checklist

- [ ] Dedicated role for agent queries, `NOSUPERUSER NOBYPASSRLS`.
- [ ] Column-level `GRANT SELECT` matching the policy's `columns`.
- [ ] `search_path` on the role equals the policy's `search_path`.
- [ ] `default_transaction_read_only = on` and queries run in `READ ONLY` transactions.
- [ ] `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` set.
- [ ] RLS enabled and forced on every tenant-scoped table.
- [ ] Tenant setting applied with `SET LOCAL` / `set_config(..., true)` per transaction.
- [ ] HaltSQL policy in `enforce` mode, bound tenancy, tokens pinned to policies.
- [ ] Audit logs shipped somewhere durable; alerts on `E_INTERNAL`.
