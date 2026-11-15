# Quickstart: your first deny in five minutes

This walks through installing the CLI, writing a small policy, and checking a
few queries an LLM might produce.

## 1. Install

Pick one:

```sh
# Release binary (Linux amd64 shown; also linux-arm64 and darwin-arm64)
curl -LO https://github.com/HaltSQL/HaltSQL/releases/download/v0.0.3/haltsql-v0.0.3-linux-amd64.tar.gz
tar -xzf haltsql-v0.0.3-linux-amd64.tar.gz
export PATH="$PWD/haltsql-v0.0.3-linux-amd64:$PATH"

# Or from source with opam (OCaml 5.1+)
opam pin add haltsql https://github.com/HaltSQL/HaltSQL.git

# Or Docker (the CLI is in the image too)
alias haltsql='docker run --rm -i -v "$PWD:/w" -w /w --entrypoint haltsql ghcr.io/haltsql/haltsql:0.0.3'
```

Check it works:

```sh
haltsql version
```

## 2. Write a policy

Save this as `policy.yaml`. It lets an analytics agent read two tables of a
multi-tenant app, hides customer email and phone, and requires a tenant filter
and a `LIMIT`.

```yaml
apiVersion: haltsql.dev/v1
kind: Policy
metadata:
  name: analytics-agent
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 1000 }
tenancy:
  mode: bound
  keys:
    tenant: "${ctx.tenant_id}"
tables:
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name, created_at]
    tenant_column: tenant_id
functions:
  presets: [aggregates]
  allow: [date_trunc]
```

Validate it:

```sh
haltsql validate policy.yaml
```

`validate` exits 0 and prints nothing alarming if the policy is well formed.
Typos are errors, not warnings: try changing `tenant_column` to
`tenant_colum` and run it again.

## 3. Check an allowed query

In **bound** mode the model writes `$1` where the tenant ID goes, and your
application binds the real value. The model never sees it.

```sh
haltsql verify --policy policy.yaml --context '{"tenant_id":"acme"}' \
  --sql 'SELECT status, count(*) FROM orders WHERE tenant_id = $1 GROUP BY status LIMIT 100'
echo "exit: $?"
```

The exit code is `0`. Add `--json` to see the full verdict, including what to
bind:

```json
"bind_params": [ { "param": 1, "value": "acme" } ]
```

Your application now runs that exact SQL string with `$1 = 'acme'`.

## 4. Get your first deny

Drop the tenant filter, the kind of query a prompt-injected model might write:

```sh
haltsql verify --policy policy.yaml --context '{"tenant_id":"acme"}' --json \
  --sql 'SELECT id, total_cents FROM orders LIMIT 100'
echo "exit: $?"
```

The exit code is `1` and the verdict contains:

```json
{
  "allowed": false,
  "reasons": [
    {
      "code": "E_TENANT_MISSING",
      "message": "...",
      "rule": "...",
      "hint": "..."
    }
  ]
}
```

A few more to try, each denied for a different reason:

| SQL | Expected code |
|---|---|
| `SELECT email FROM customers WHERE tenant_id = $1 LIMIT 10` | `E_COLUMN_DENIED` |
| `SELECT id FROM orders WHERE tenant_id = $1` | `E_LIMIT_REQUIRED` |
| `SELECT id FROM orders WHERE tenant_id = $1 OR true LIMIT 10` | `E_TENANT_MISSING` |
| `SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10; DROP TABLE orders` | `E_MULTI_STATEMENT` |
| `SELECT pg_sleep(10)` | `E_FUNCTION_DENIED` |
| `SELECT * FROM pg_catalog.pg_user LIMIT 1` | `E_TABLE_DENIED` |
| `DELETE FROM orders WHERE tenant_id = $1` | `E_STATEMENT_KIND` |

## 5. Understand a denial

`explain` prints the same verdict for people: the statement kind, the tables
and columns it found, each reason, and a hint.

```sh
haltsql explain --policy policy.yaml --context '{"tenant_id":"acme"}' \
  --sql 'SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.tenant_id = $1 LIMIT 10'
```

Here `customers` has no tenant predicate of its own. The fix is to add
`AND c.tenant_id = $1`. See [tenancy.md](tenancy.md) for why the filter on
`orders` does not cover `customers`.

## 6. Put it in CI

Write test cases next to the policy so a policy change cannot silently loosen
it. Save as `policy.test.yaml`:

```yaml
apiVersion: haltsql.dev/v1
kind: TestSuite
metadata: { name: analytics-agent }
policy: ./policy.yaml
defaults:
  context: { tenant_id: acme }
cases:
  - name: filtered aggregate is allowed
    sql: SELECT status, count(*) FROM orders WHERE tenant_id = $1 GROUP BY status LIMIT 100
    expect: allow
    bind: [{ param: 1, value: acme }]
  - name: missing tenant filter is denied
    sql: SELECT id FROM orders LIMIT 100
    expect: deny
    codes: [E_TENANT_MISSING]
```

```sh
haltsql test policy.test.yaml
```

## Next steps

- Wire HaltSQL into your agent with the [HTTP sidecar](http-api.md) and the
  [integration snippets](integrations.md).
- Read the [policy reference](policy-reference.md) and the
  [reason codes](reason-codes.md).
- Set up the [database-side controls](defense-in-depth.md). HaltSQL is one
  layer, not the only one.
