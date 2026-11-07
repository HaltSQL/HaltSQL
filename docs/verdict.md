# Verdict format

Every check returns a verdict. The library returns a `Haltsql.Verdict.t`
record; the CLI (`--json`) and the HTTP API return the same thing as JSON. The
JSON shape is part of HaltSQL's public API: fields are only added, never
renamed or removed, within `haltsql.dev/v1`.

## Example: denied

```json
{
  "allowed": false,
  "reasons": [
    {
      "code": "E_TENANT_MISSING",
      "message": "app.customers (alias c) has no tenant predicate in its scope",
      "rule": "tenancy.predicate",
      "loc": 43,
      "hint": "Add c.tenant_id = $1 to the WHERE clause or to the inner JOIN ... ON clause that attaches c."
    }
  ],
  "shadow_reasons": [],
  "policy": { "name": "analytics-agent", "version": "sha256:4f1c9a..." },
  "statement_kind": "select",
  "tables": ["app.customers", "app.orders"],
  "columns": ["app.customers.id", "app.customers.name", "app.orders.customer_id", "app.orders.id", "app.orders.tenant_id"],
  "bind_params": [],
  "fingerprint": "6c1e0b7f3a2d9e41",
  "sql_sha256": "c0ffee...",
  "elapsed_us": 187
}
```

## Example: allowed (bound tenancy)

```json
{
  "allowed": true,
  "reasons": [],
  "shadow_reasons": [],
  "policy": { "name": "analytics-agent", "version": "sha256:4f1c9a..." },
  "statement_kind": "select",
  "tables": ["app.orders"],
  "columns": ["app.orders.status", "app.orders.tenant_id"],
  "bind_params": [ { "param": 1, "value": "acme" } ],
  "fingerprint": "0a9d55c2e1f04b7c",
  "sql_sha256": "5e8f...",
  "elapsed_us": 94
}
```

Messages, hints, and hash values above are illustrative.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `allowed` | boolean | `true` if the caller may run this exact SQL string. In `enforce` mode, `true` exactly when `reasons` is empty. In `shadow` mode, always `true`. |
| `reasons` | array of [Reason](#reason) | Why the query was denied. Empty when allowed. |
| `shadow_reasons` | array of [Reason](#reason) | Shadow mode only: the reasons the query *would* have been denied. Always empty in enforce mode. |
| `policy.name` | string | `metadata.name` of the policy used. |
| `policy.version` | string | `sha256:<hex>` hash of the normalized policy (identical for YAML and JSON forms). Log it to know exactly which policy made a decision. |
| `statement_kind` | string or null | `select`, `insert`, `update`, or `delete` when the statement parsed and is one of those kinds; otherwise `null`. |
| `tables` | array of strings | Qualified relations the statement reads or writes (`schema.table`), sorted and unique. May be partial when the query was denied early. |
| `columns` | array of strings | Columns read, as `schema.table.column`, sorted and unique. May be partial when denied. |
| `bind_params` | array of `{param, value}` | Bound tenancy mode: for each `$n`, the value the caller **must** bind. `value` is a string, or an array of strings when the context value is a set. Always empty when denied. |
| `fingerprint` | string or null | libpg_query fingerprint: equal for queries that differ only in literal values. Useful for grouping in logs and dashboards. `null` if the SQL did not parse. |
| `sql_sha256` | string | Lower-case hex SHA-256 of the exact input string. Lets audit logs refer to the query without storing it. |
| `elapsed_us` | integer | Time spent verifying, in microseconds. Informational; not deterministic. |

### Reason

| Field | Type | Meaning |
|---|---|---|
| `code` | string | Stable reason code, for example `E_TENANT_MISSING`. See [reason-codes.md](reason-codes.md). Match on this, never on `message`. |
| `message` | string | Human-readable explanation. May change between releases. |
| `rule` | string | Identifier of the rule that produced the reason, for example `tenancy.predicate`. Useful for debugging; may change between releases. |
| `loc` | integer (optional) | Byte offset (0-based) into the SQL string where the problem is. Absent when unknown. |
| `hint` | string (optional) | A short instruction an LLM agent can follow to fix its query. May change between releases. |

## How to use a verdict

1. If `allowed` is `false`, do not run the query. Return the `reasons` (codes,
   messages, and hints) to the agent so it can try again.
2. If `allowed` is `true`, run **exactly** the SQL string you verified. Do not
   reformat, append to, or template it.
3. Bind every entry in `bind_params` as the value of its `$n` placeholder. If
   your driver needs other parameters too, the query would have been denied
   with `E_PARAM_UNBOUND`, so there are none.
4. Log `policy.version`, `fingerprint`, `sql_sha256`, `allowed`, and the reason
   codes for audit.

## Stability guarantees

Within `haltsql.dev/v1`:

- Existing fields keep their name, type, and meaning.
- New fields may be added. Clients must ignore fields they do not recognize.
- Reason `code` values are never renamed or reused. New codes may be added in
  minor releases, so clients must handle unknown codes (treat them as a deny).
- `message`, `hint`, and `rule` text may change at any time.
- For the same SQL, policy, and context, `allowed`, `reasons[].code`,
  `tables`, `columns`, and `bind_params` are deterministic.

See [ADR-0004](adr/0004-verdict-schema-and-reason-codes.md) for the reasoning.
