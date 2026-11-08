# Policy reference

A policy says which SQL a caller may run. It is a YAML or JSON document with
`kind: Policy`. Both formats mean exactly the same thing and are validated
against the same JSON Schema (`haltsql schema export` writes it as
`policy.schema.json`).

Policies are **deny by default**: anything not allowed here is denied.

## Complete example

```yaml
apiVersion: haltsql.dev/v1
kind: Policy
metadata:
  name: analytics-agent
  owner: data-platform
  description: Read-only analytics over orders and customers.
dialect: postgres
search_path: [app]
catalog: ./schema.snapshot.json
limits: { max_bytes: 16384, max_depth: 64, max_nodes: 20000, max_joins: 8 }
statements:
  allow: [select]
require_limit:
  max: 1000
tenancy:
  mode: bound
  keys:
    tenant: "${ctx.tenant_id}"
tables:
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name, created_at]   # email/phone intentionally absent
    tenant_column: tenant_id
  app.currencies:
    columns: "*"                                 # global reference table
functions:
  presets: [aggregates, datetime]
  allow: [coalesce, lower, upper]
allow_explain: false
mode: enforce
```

The same policy in JSON:

```json
{
  "apiVersion": "haltsql.dev/v1",
  "kind": "Policy",
  "metadata": { "name": "analytics-agent", "owner": "data-platform" },
  "search_path": ["app"],
  "statements": { "allow": ["select"] },
  "require_limit": { "max": 1000 },
  "tenancy": { "mode": "bound", "keys": { "tenant": "${ctx.tenant_id}" } },
  "tables": {
    "app.orders": {
      "columns": ["id", "tenant_id", "customer_id", "status", "total_cents", "created_at"],
      "tenant_column": "tenant_id"
    },
    "app.currencies": { "columns": "*" }
  },
  "functions": { "presets": ["aggregates", "datetime"], "allow": ["coalesce"] },
  "mode": "enforce"
}
```

## Loading rules

These apply to every HaltSQL document, not only policies.

- **Format** comes from the file extension: `.yaml`/`.yml` or `.json`.
- **YAML 1.2 core schema.** `no`, `on`, `yes`, and `off` stay strings, and
  `012` is not octal. Quote values when in doubt.
- **Unknown keys are errors.** A typo such as `tenant_colum` fails to load
  instead of silently loosening the policy.
- **Duplicate keys are errors.**
- **Custom YAML tags are rejected**, and alias expansion and document size are
  capped.
- **All errors are reported at once**, with file, line, column, and key path,
  for example `policy.yaml:14:5: tables."app.orders".tenant_column: unknown column`.
- **Placeholders:** the only placeholder allowed in a policy is `${ctx.NAME}`,
  filled from the request context at verify time. `${env:...}` and
  `${file:...}` are not allowed in policies, so a policy gives the same result
  on every machine.
- **Version hash.** Each loaded policy has a `policy_version` of the form
  `sha256:<hex>`, computed over the normalized policy. The same policy written
  in YAML or JSON gets the same version.

## Identifiers

Names in a policy follow Postgres rules:

- Unquoted names are folded to lower case: `App.Orders` means `app.orders`.
- To match a name that needs case or special characters, write it with double
  quotes inside the key, for example `'app."Orders"'` in YAML.
- Unqualified table names are qualified with the **first** `search_path`
  entry.

## Top-level keys

| Key | Type | Required | Default |
|---|---|---|---|
| [`apiVersion`](#apiversion) | string | yes | none |
| [`kind`](#kind) | string | yes | none |
| [`metadata`](#metadata) | object | yes | none |
| [`dialect`](#dialect) | string | no | `postgres` |
| [`search_path`](#search_path) | list of strings | no | `[public]` |
| [`catalog`](#catalog) | string (path) or inline snapshot | no | none (empty) |
| [`limits`](#limits) | object | no | see below |
| [`statements`](#statements) | object | no | `{ allow: [select] }` |
| [`require_limit`](#require_limit) | object | no | not required |
| [`tenancy`](#tenancy) | object | no | no tenancy keys |
| [`tables`](#tables) | map | no | `{}` (nothing readable) |
| [`functions`](#functions) | object | no | no functions allowed |
| [`operators`](#operators) | object | no | built-in default list |
| [`deny_casts`](#deny_casts) | list, or object | no | built-in default list |
| [`allow_explain`](#allow_explain) | boolean | no | `false` |
| [`mode`](#mode) | string | no | `enforce` |

### apiVersion

Must be `haltsql.dev/v1`. Documents with a different version are rejected.
Every released schema version will keep loading, or fail with a clear
migration error.

### kind

Must be `Policy`.

### metadata

| Key | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Policy name. Tokens in the server config pin to this name; it appears in every verdict. |
| `owner` | string | no | Team or person responsible. Informational. |
| `description` | string | no | Free text. Informational. |

### dialect

`postgres` or a major-specific form such as `postgres-17`. Only PostgreSQL is
supported. HaltSQL parses with the Postgres 17 grammar of its vendored
libpg_query; run `haltsql version` to see the exact version.

### search_path

The schemas used to resolve unqualified table names, in order, just as
Postgres's `search_path` would. Unqualified names in `tables` are qualified with
the first entry.

Set this explicitly. HaltSQL does not read the database's `search_path`, and
the database role that runs the queries should have the same `search_path`
(see [defense-in-depth.md](defense-in-depth.md)). If the two differ, a name could
resolve to a different table in HaltSQL than in Postgres.

System schemas (`pg_catalog`, `information_schema`, `pg_toast`, and similar) are
never readable, even if listed.

### catalog

Optional schema snapshot: either a path to a snapshot file (relative to the
policy file), or the snapshot written inline as an object. The catalog lists the **complete** set of
columns of each table, with types, so that:

- `SELECT *` and `t.*` expand to the real column list (and are denied if that
  includes a column the policy does not allow);
- unknown or ambiguous columns can be detected precisely;
- tenant literals can be type-checked in literal mode.

Snapshot format:

```json
{
  "tables": {
    "app.orders": {
      "columns": [
        { "name": "id", "type": "int8" },
        { "name": "tenant_id", "type": "text" },
        "status"
      ]
    }
  }
}
```

Column entries may be objects with `name` and optional `type`, or plain
strings. Generate a snapshot from a live database (`information_schema`) so it
includes types; the analyzer only trusts entries that carry column types,
because an entry must be the **complete** column list of the real table.

Without a catalog, the catalog is empty. HaltSQL never builds one from the
column lists in `tables`, since the real table may have columns the policy
leaves out. Consequences without a snapshot:

- `SELECT *`, `t.*` and whole-row references are allowed only on tables with
  `columns: "*"`; on any other table they are denied (`E_COLUMN_DENIED`), with a
  hint to list the columns;
- unqualified columns in multi-table queries may be `E_COLUMN_UNRESOLVED`; the
  hint says to qualify them.

The catalog contents are included in `policy_version`.

### limits

Resource limits checked before and during analysis. Exceeding one gives
`E_LIMIT` (or `E_JOIN_BUDGET` for joins).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `max_bytes` | integer | `16384` | Maximum SQL length in bytes, checked before parsing. |
| `max_depth` | integer | `64` | Maximum nesting depth of the parse tree. |
| `max_nodes` | integer | `20000` | Maximum number of parse-tree nodes. |
| `max_joins` | integer | `8` | Maximum number of joins in one statement. |

Omitted keys take their defaults.

### statements

```yaml
statements:
  allow: [select]          # any of: select, insert, update, delete
```

The statement kinds a caller may run. Everything else (DDL, `DO`, `CALL`,
`COPY`, `SET`, `LOCK`, `VACUUM`, transaction control, and so on) is always
denied with `E_STATEMENT_KIND`. Write kinds also need per-table
[`writes`](#writes). Only one statement per request is ever allowed.

Write support is limited in 0.1.0; read-only policies are the main target.

### require_limit

```yaml
require_limit:
  max: 1000
```

When set, every `SELECT` (including each set-operation result) must end with a
constant `LIMIT n` (or `FETCH FIRST n ROWS ONLY`) where `n <= max`.

- No `LIMIT`, or `LIMIT ALL`: `E_LIMIT_REQUIRED`.
- `n` greater than `max`, or not an integer constant (for example `LIMIT $2`
  or `LIMIT (SELECT ...)`): `E_LIMIT_TOO_HIGH`.

### tenancy

Declares which context values identify the tenant, and how tenant predicates
must be written. The full semantics are in [tenancy.md](tenancy.md).

```yaml
tenancy:
  mode: bound                       # bound | literal
  keys:
    tenant: "${ctx.tenant_id}"      # key name -> context field
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `bound` or `literal` | `bound` | How the tenant value appears in SQL. |
| `keys` | map of key name to `${ctx.FIELD}` | none | Named tenancy keys and the context field each one reads. Key names use letters, digits, and `_`. Must not be empty if present. |
| `value` | `${ctx.FIELD}` | none | Shorthand for a single key named `tenant`: `value: ${ctx.tenant_id}` equals `keys: { tenant: ${ctx.tenant_id} }`. Use `value` or `keys`, not both. |

**`mode: bound` (recommended).** Tenant predicates compare the tenant column
with a parameter placeholder, `tenant_id = $1`. HaltSQL returns
`bind_params: [{param: 1, value: <context value>}]` and the caller **must**
bind exactly that value when running the query. The model never sees or emits
the tenant ID.

**`mode: literal`.** Tenant predicates compare with a literal,
`tenant_id = 'acme'`. The literal must equal the context value exactly (no
trimming or case folding); otherwise the verdict is `E_TENANT_MISMATCH`.

**Keys.** Each key names one dimension of tenancy and maps to a context field.
Most policies have one key. Composite tenancy (for example organization plus
workspace) uses several:

```yaml
tenancy:
  mode: bound
  keys:
    org: "${ctx.org_id}"
    workspace: "${ctx.workspace_id}"
```

If the context value for a key is a list (for example a parent organization
and its children), the predicate may match any value in the set; see
[tenancy.md](tenancy.md#sets-of-tenant-values).

A key whose context field is missing at verify time causes `E_CONTEXT_MISSING`
for any query that touches a table using that key.

### tables

A map from table name to its rules. Only tables listed here can be read (or
written). Views are listed the same way and are treated as opaque relations;
HaltSQL does not look inside view definitions.

```yaml
tables:
  app.orders:
    columns: [id, tenant_id, status]
    tenant_column: tenant_id
    writes:
      insert: false
      update: [status]
      delete: false
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `columns` | list of strings, or `"*"` | required | Readable columns. `"*"` means every column. |
| `tenant_column` | string | none | Tenant column, for a policy with exactly one tenancy key. |
| `tenant_columns` | map of column to key name | none | Tenant columns for composite tenancy. |
| `writes` | object | no writes | Write permissions (see below). |

#### columns

The columns a query may reference anywhere: select list, `WHERE`, `JOIN ... ON`,
`GROUP BY`, `ORDER BY`, function arguments, and `*` expansion. A reference to
any other column is `E_COLUMN_DENIED`. Whole-row references (`t`, `t.*`,
`row_to_json(t)`) are treated as references to every column of the table.

`"*"` allows every column. Use it only for tables with no sensitive data.

The tenant column must be in the column list (it is referenced by the tenant
predicate).

#### tenant_column / tenant_columns

A table with a tenant column is **tenant-scoped**: every occurrence of it in a
query must carry a tenant predicate (see [tenancy.md](tenancy.md)). A table
with neither key is **global** and needs no tenant predicate.

- `tenant_column: tenant_id` is shorthand for a policy with exactly one tenancy
  key: the column is bound to that key.
- `tenant_columns` maps each tenant column to a key name, for composite
  tenancy. Every listed column needs its own predicate.

```yaml
tables:
  app.documents:
    columns: [id, org_id, workspace_id, title]
    tenant_columns:
      org_id: org
      workspace_id: workspace
```

Use one or the other, not both. Every key name must exist in `tenancy.keys`.

#### writes

Write permissions for the table. Enabling a write whose statement kind is not
in `statements.allow` is a load error.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `insert` | boolean | `false` | `INSERT ... VALUES` allowed, with an explicit column list. Every inserted column must be in the table's `columns` list, so a hidden column (e.g. `password_hash`) cannot be written either. `INSERT ... SELECT` and `ON CONFLICT` are not supported. |
| `update` | list of columns, or `"*"` | not allowed | Columns an `UPDATE` may assign. `false` means not allowed; `true` is an error (be explicit). |
| `delete` | boolean | `false` | `DELETE` allowed. |

A tenant column may not appear in `update` (load error). Tenant rules for
writes: an `INSERT` must set every tenant column to the tenant
value in every row; an `UPDATE` may never assign a tenant column and needs a
tenant predicate; a `DELETE` needs a tenant predicate. Violations give
`E_TENANT_WRITE` or `E_TENANT_MISSING`; writes to tables or columns not allowed
here give `E_WRITE_DENIED`.

### functions

```yaml
functions:
  presets: [aggregates, datetime]
  allow: [coalesce, lower, upper, app.safe_fn]
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow` | list of strings | `[]` | Function names that may be called, unqualified (`lower`) or schema-qualified (`app.safe_fn`). Names must not be quoted. |
| `presets` | list of strings | `[]` | Named, built-in groups of functions to include. |

Every function call, including aggregates, window functions, and
set-returning functions in `FROM`, must be allowed; anything else is
`E_FUNCTION_DENIED`. Names are case-insensitive unless quoted. An unqualified
entry such as `lower` also matches `pg_catalog.lower`.

Built-in functions that run a SQL string (or dump a whole table, schema or
database) passed as an argument are always `E_FUNCTION_DENIED`, even when they
are listed in `allow`: `ts_rewrite`, `ts_stat`, `query_to_xml*`,
`cursor_to_xml*`, `table_to_xml*`, `schema_to_xml*`, `database_to_xml*` and
the `dblink` family. HaltSQL only sees a string literal there, so table,
column and tenancy rules could not apply to the SQL they run.

Built-in presets. The authoritative lists are in
`Policy_load.function_presets` (`lib/load/policy_impl.ml`); they may grow in
minor releases, but never to include functions with side effects. An unknown
preset name is a load error.

| Preset | Contents (0.1.0) |
|---|---|
| `aggregates` | `count`, `sum`, `avg`, `min`, `max`, `bool_and`, `bool_or`, `every`, `string_agg`, `array_agg`, `stddev`, `stddev_pop`, `stddev_samp`, `variance`, `var_pop`, `var_samp`, `percentile_cont`, `percentile_disc`, `mode` |
| `math` | `abs`, `ceil`, `ceiling`, `floor`, `round`, `trunc`, `sign`, `sqrt`, `cbrt`, `power`, `mod`, `div`, `ln`, `log`, `log10`, `exp`, `pi`, `degrees`, `radians` |
| `string` | `lower`, `upper`, `length`, `char_length`, `character_length`, `octet_length`, `substring`, `substr`, `trim`, `btrim`, `ltrim`, `rtrim`, `replace`, `concat`, `concat_ws`, `left`, `right`, `position`, `strpos`, `split_part`, `starts_with`, `initcap`, `lpad`, `rpad`, `reverse`, `translate` |
| `regex` | `regexp_replace`, `regexp_match`, `regexp_like`, `regexp_count`, `regexp_instr`, `regexp_substr`, `regexp_split_to_array`. Separate because user-supplied patterns can be slow; enable it knowingly. |
| `datetime` | `now`, `date_trunc`, `date_part`, `extract`, `date_bin`, `age`, `make_date`, `make_time`, `make_timestamp`, `make_timestamptz`, `make_interval`, `to_char`, `to_date`, `to_timestamp`, `justify_days`, `justify_hours`, `justify_interval`, `isfinite` |
| `json` | `jsonb_extract_path`, `jsonb_extract_path_text`, `json_extract_path`, `json_extract_path_text`, `jsonb_array_length`, `json_array_length`, `jsonb_typeof`, `json_typeof`, `jsonb_build_object`, `json_build_object`, `jsonb_build_array`, `json_build_array`, `jsonb_agg`, `json_agg`, `jsonb_object_agg`, `json_object_agg`, `to_jsonb`, `to_json` |
| `conditional` | `num_nulls`, `num_nonnulls` |
| `window` | `row_number`, `rank`, `dense_rank`, `percent_rank`, `cume_dist`, `ntile`, `lag`, `lead`, `first_value`, `last_value`, `nth_value` |

`row_to_json` is intentionally in no preset, because it serializes whole rows.
Be careful with `to_json`/`to_jsonb` on whole-row arguments; the column rules
still apply to them.

Never allow functions with side effects or access to the server, for example
`set_config`, `nextval`, `setval`, `pg_sleep`, `pg_read_file`, `lo_import`,
`lo_export`, `dblink`, `pg_terminate_backend`, `query_to_xml`, or any
function that runs dynamic SQL.

### operators

```yaml
operators:
  allow: ["=", "<>", "<", "<=", ">", ">=", "+", "-", "*", "/", "||", "~~", "~~*"]   # replaces the default list
  extend: ["<->"]                                                                     # added to allow (or to the default)
```

The operator symbols a query may use. Any other operator is
`E_OPERATOR_DENIED`.

| Key | Type | Meaning |
|---|---|---|
| `allow` | list of strings | Replaces the default list. |
| `extend` | list of strings | Added to `allow`, or to the default list when `allow` is omitted. |

The default list (`Policy_load.default_operators`) in 0.1.0 is:

- comparison: `=`, `<>`, `!=`, `<`, `>`, `<=`, `>=`
- arithmetic (also date and interval arithmetic): `+`, `-`, `*`, `/`, `%`
- string concatenation: `||`
- `LIKE`/`ILIKE` and POSIX regular expressions: `~~`, `!~~`, `~~*`, `!~~*`, `~`, `~*`, `!~`, `!~*`. `LIKE`, `ILIKE` and `SIMILAR TO` are checked as the operators `~~`, `~~*` and `~` (and their `!` negations), so removing them from `operators` disables that syntax too.
- JSON/JSONB: `->`, `->>`, `#>`, `#>>`, `@>`, `<@`, `?`, `?|`, `?&`
- arrays: `&&` (and `@>`, `<@` above)

To disallow regular expressions (slow patterns), set `allow` to the list above
without the `~` operators.

`AND`, `OR`, `NOT`, `IS NULL`, `IN`, `BETWEEN`, and `CASE` are syntax, not
operators, and are always available.

### deny_casts

```yaml
deny_casts:
  extend: [inet]            # recommended form: the defaults plus your additions
```

Cast target types that are denied (`'x'::regclass`, `CAST(... AS regproc)`),
lower case and unqualified. A denied cast gives `E_CAST_DENIED`.

- Omitted: the built-in default list (`Policy_load.default_deny_casts`):
  `regclass`, `regproc`, `regprocedure`, `regoper`, `regoperator`, `regtype`,
  `regconfig`, `regdictionary`, `regnamespace`, `regrole`, `regcollation`,
  `txid_snapshot`. The `reg*` object-identifier types can look up catalog
  objects by name.
- `{ extend: [...] }`: the default list plus the given types.
- A plain list: **replaces** the default list. Keep the `reg*` types in it.

### allow_explain

`false` by default. When `true`, plain `EXPLAIN <statement>` is allowed if the
inner statement would itself be allowed. `EXPLAIN ANALYZE` runs the statement
and is always denied, as are other `EXPLAIN` options that execute the query.

### mode

| Value | Behavior |
|---|---|
| `enforce` (default) | Denials set `allowed: false` and are listed in `reasons`. |
| `shadow` | `allowed` is always `true`; would-be denials are listed in `shadow_reasons`. |

Use shadow mode to roll out a new or stricter policy: log the verdicts, review
`shadow_reasons`, then switch to `enforce`. A shadow policy enforces nothing,
so never use it as the only control.

## Validating and converting

```sh
haltsql validate policy.yaml              # check one or more documents
haltsql convert policy.yaml --to json     # YAML -> JSON (lossless)
haltsql schema export --out schemas/      # JSON Schemas for editors
```

To get editor autocomplete in VS Code with the YAML extension, add a modeline:

```yaml
# yaml-language-server: $schema=./schemas/policy.schema.json
apiVersion: haltsql.dev/v1
kind: Policy
```
