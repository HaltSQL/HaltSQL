# Shadow reports and policy suggestions

A new or stricter policy usually starts in [shadow mode](policy-reference.md#mode):
queries are still allowed, and the would-be denials go to the audit log as
shadow reasons. `haltsql report` reads those audit logs and tells you what
the policy would have blocked, and why. It then suggests small, conservative
changes, each with the exact YAML to add. It can also write a patched policy
for you to review.

The same report is served live by haltsql-server at
[`GET /v1/admin/report`](#server-endpoint-get-v1adminreport).

```sh
haltsql report /var/log/haltsql/audit.jsonl --since 7d
haltsql report audit/ --suggest --policy-file policy.yaml --pii pii.json
haltsql report audit.jsonl --apply-to policy.yaml -o policy.next.yaml
```

## Inputs

The report reads the JSON-lines audit records of both producers. Records of
both kinds can be mixed in one run.

| Producer | Where the records are | What a record carries |
|---|---|---|
| haltsql-server | `audit.sinks`: `stdout`, `file`, and the `s3`/`gcs` objects (download them; the report searches directories recursively) | `caller`, `policy`, `policy_version`, `allowed`, `shadow`, `codes`, `fingerprint`, `sql_sha256`, `[sql]` |
| haltsql-proxy | its audit sink | `user`, `policy`, `allowed`, `reasons`, `shadow_reasons`, `tables`, `fingerprint`, `[sql]`, and local denials (`event: parse`, `bind`, `function_call`) |

The record formats are described in [audit-sinks.md](audit-sinks.md) and
[proxy.md](proxy.md).

- **INPUT** is a file, a directory (searched recursively for `*.jsonl`,
  `*.ndjson`, `*.json` and `*.log`, in name order), or `-` for stdin.
- Lines that are not audit records, such as log lines or other JSON, are
  skipped and counted.
- For each file, the report states whether its hash chain verifies
  (`hash chain ok (N records)`, `HASH CHAIN BROKEN at line N`, or
  `not hash-chained`). Run [`haltsql audit verify`](audit-verify.md)
  for a strict check from genesis.

### Raw SQL and detail

An audit record has reason **codes** only. A record says
`E_COLUMN_DENIED`, but not which column was denied. To name the column,
function, table or LIMIT, the report needs one of these:

- **Raw SQL in the records plus the policy.** Set `audit.log_raw_sql: true`
  (server) or `audit.log_raw_sql` (proxy), and pass `--policy-file`. The
  report re-verifies each denied record's SQL against that policy. It keeps
  only the reasons whose codes the record itself carries: the record decides
  *what* happened, and the re-verification only names the objects.
- **The server endpoint.** It sees the full verdict of every request, so it
  can name the objects even without raw SQL.

Without detail, the summary still works, but suggestions can't be made for
those records. The report counts them as `missing_detail`.

Raw SQL can contain sensitive literals. The report prints SQL only from
records that already contain it.

## The summary

| Section | What it shows |
|---|---|
| Totals | Records, and how many were allowed, denied (enforce mode) or shadow-denied (allowed, but the shadow policy would have denied them). |
| By reason code | Records carrying each code. |
| By table / By column | Relations and `schema.table.column` the records touched or were denied on. |
| By caller / By policy | Server `caller` (token name, OIDC subject, mTLS identity) or proxy `user`, and the policy name. |
| Over time | Counts per time bucket. The bucket is 5 minutes for spans up to 6 h, 1 h up to 3 days, otherwise 1 day. Override it with `--bucket 15m`. |
| Top denied queries | Groups by query fingerprint, worst first, with their codes and callers. Each group shows an example SQL only when a record contains one. |

## Suggestions

Add `--suggest` to get suggestions. Each suggestion has:

- a stable id, used by `--accept`;
- an evidence count of records, split into denied and shadow-denied, plus
  distinct queries and callers;
- a one-line summary;
- the exact YAML to merge;
- review notes, if any.

For example:

```text
[shop/column/app.orders.region]
  23 shadow-denied queries by caller analytics read app.orders.region
  (E_COLUMN_DENIED); add region to tables.app.orders.columns
    tables:
      app.orders:
        columns: [id, tenant_id, status, total_cents, created_at, region]
```

Only four kinds of change are ever suggested:

| Code | Suggestion | Conditions |
|---|---|---|
| `E_COLUMN_DENIED` | Add the column to the table's `columns`. | The table is already in the policy. The column is not sensitive (see [PII](#sensitive-columns)). |
| `E_FUNCTION_DENIED` | Add the function to `functions.allow`. | The function is not on the deny list: no side effects, no dynamic SQL, no server state (`pg_*`, `lo_*`, `dblink*`, `set_config`, `current_setting`, `nextval`, `query_to_xml`, `ts_stat`, `row_to_json`, ...). It is not schema-qualified: user-defined functions need a human to read their definition. Identity functions such as `CURRENT_USER` are never allowed. |
| `E_LIMIT_TOO_HIGH` | Raise `require_limit.max` to the largest constant LIMIT seen. | At most 10 times the current maximum, and at most 100000. Anything larger is listed for review ("make the queries page instead"). `LIMIT $n` and non-constant limits need a query fix. |
| `E_TABLE_DENIED` | Add the table, with the columns the queries actually read. | Never a system schema. When the policy has tenancy, the new table is **always tenant-scoped**, on the tenant column(s) that every existing tenant-scoped table uses. If that is ambiguous (composite or mixed tenant columns), or the catalog shows the table without that column, the suggestion is listed for review instead. |

`--min-count N` sets an evidence threshold: a change must be seen in at
least N records to be suggested. The default is 1.

To find a new table's columns, the report re-verifies the queries with the
table temporarily added. This needs records with raw SQL. Without SQL, the
table suggestion is still shown, but as *not applicable automatically*, with
an empty column list for you to fill in. Columns are always listed
explicitly, never `"*"`.

### Never suggested

These are never turned into a policy change. Each one is listed with its
record count and advice:

| Category | Codes | Advice |
|---|---|---|
| Never relaxed: tenancy | `E_TENANT_MISSING`, `E_TENANT_MISMATCH`, `E_TENANT_WRITE`, `E_CONTEXT_MISSING` | Fix the query's tenant predicate, or have the caller send its context. Tenant isolation is never weakened. |
| Never relaxed: writes | `E_WRITE_DENIED`, `E_STATEMENT_KIND`, `E_DATA_MODIFYING_CTE`, `E_SELECT_INTO`, `E_LOCKING_CLAUSE` | Grant writes deliberately, by hand. |
| Never relaxed: external policy | `E_EXTERNAL_POLICY` | Denied by OPA; change the OPA policy, not the HaltSQL policy. |
| Needs a query fix | `E_PARAM_UNBOUND`, `E_UNSUPPORTED`, `E_PARSE`, `E_EMPTY`, `E_MULTI_STATEMENT`, `E_LIMIT`, `E_LIMIT_REQUIRED`, `E_COLUMN_UNRESOLVED`, `E_OPERATOR_DENIED`, `E_CAST_DENIED`, `E_JOIN_BUDGET`, `E_INTERNAL` | The query must change, not the policy. |

A record can carry both a fixable code and a tenancy code, for example a
denied column in a query that has no tenant predicate. In that case the
column may be suggested, but the record stays denied for tenancy, and
`--apply-to` checks that it does (see below).

Individual objects that are not suggested are also listed, with a category:

- `unsafe`: a function or system catalog on the deny lists;
- `query_fix`: `SELECT *`, or a table that is already listed but did not
  resolve through `search_path`;
- `already_allowed`: older records, from before the policy changed;
- `needs_review`: a LIMIT far above the current maximum, or undecidable
  tenancy.

### Sensitive columns

A column flagged as sensitive is reported under *Sensitive columns (flagged,
never suggested)*. It is never added to a policy, and it is left out of new
tables. A column is flagged when either of these marks it:

- **A PII manifest** passed with `--pii FILE` (repeatable). This is the
  output of [`haltsql schema import`](schema-and-pii.md). To read a raw
  dbt, DataHub, Unity Catalog, Atlan or Collibra export directly, add
  `--pii-source dbt` (or `datahub`, `unity`, `atlan`, `collibra`).
- **The column-name heuristic**, the same as `haltsql policy draft`. A name
  whose words include `email`, `phone`, `ssn`, `pii`, `secret`, `personal`,
  `sensitive`, and the other default terms is flagged. Turn the heuristic off
  with `--no-pii-heuristics`.

## Applying suggestions: `--apply-to`

```sh
haltsql report audit/ --pii pii.json --apply-to policy.yaml -o policy.next.yaml
haltsql report audit/ --apply-to policy.yaml --accept shop/function/md5 -o next.json
```

`--apply-to FILE` implies `--suggest` and loads FILE as a policy. It applies
every applicable suggestion for that policy, or only the ones you name with
`--accept ID`. It then writes the result to `-o OUT`. It never edits FILE in
place.

The edits are structural, made on the policy document:

- append to `tables.<t>.columns`;
- append to `functions.allow`;
- set `require_limit.max`;
- add a `tables` entry with `columns` and `tenant_column` (or
  `tenant_columns`).

Everything else stays as written: presets, the catalog reference, tenancy,
writes and `mode`. A relative `catalog:` path is rewritten so that it still
points at the same file from OUT's directory. The output format follows
OUT's extension.

The result is validated with the policy loader before anything is written.
If it does not validate, nothing is written and the exit code is 1.

**YAML comments are not preserved.** The document is re-serialized. The
output starts with a comment that lists the applied suggestion ids and
says that comments were dropped. Review the diff, or copy the per-suggestion
YAML snippets into your file by hand to keep its comments.

After writing, the report re-verifies the denied records that have raw SQL
against the patched policy, and reports two counts:

- how many no longer hit any of their recorded codes;
- how many tenancy denials are still denied.

If any tenancy denial were to become an allow, the command exits 1. That
can't happen by construction: the test suite checks it with a property test
over random queries, using the real verifier.

## Output formats and options

| Option | Meaning |
|---|---|
| `--format text\|json\|markdown` | `text` (default) for terminals. `markdown` for pull requests and wikis: tables, plus fenced YAML for the suggestions. `json` for tools: the same data, see the shape below. |
| `--since TIME`, `--until TIME` | An RFC 3339 timestamp, `YYYY-MM-DD`, or a duration before now (`24h`, `7d`). Records without a timestamp are excluded when either is given. |
| `--policy NAME` | Only records of this policy. |
| `--policy-file FILE` | A policy the records were verified against (repeatable), used for detail and exact snippets. |
| `--top N`, `--rows N` | Top denied queries (default 20), and rows per breakdown table in text and markdown (default 15). |

Text and Markdown output strip control characters from every value taken
from audit records. Markdown output also escapes table cells.

Exit codes: 0 on success; 1 when the patched policy fails validation (or a
tenancy denial would become an allow); 2 on usage or load errors.

JSON shape (abridged):

```json
{
  "generated_at": "2026-11-07T10:00:00Z", "since": null, "until": null,
  "inputs": [{"input": "audit.jsonl", "status": "120 record(s), 0 skipped line(s), hash chain ok (120 records)"}],
  "summary": {
    "records": 120, "totals": {"total": 120, "allowed": 90, "denied": 2, "shadow_denied": 28},
    "by_code": [{"code": "E_COLUMN_DENIED", "total": 23, "allowed": 0, "denied": 0, "shadow_denied": 23}],
    "by_table": [], "by_column": [], "by_caller": [], "by_policy": [], "by_source": [],
    "bucket_seconds": 3600, "buckets": [{"start": "2026-11-07T09:00:00Z", "total": 120}],
    "top_denied": [{"fingerprint": "...", "count": {"total": 23}, "codes": [], "callers": [], "example_sql": null}]
  },
  "suggest": {
    "suggestions": [{"id": "shop/column/app.orders.region", "policy": "shop", "code": "E_COLUMN_DENIED",
                     "change": {"kind": "add_column", "table": "app.orders", "column": "region"},
                     "summary": "...", "yaml": "tables:\n  app.orders:\n ...", "notes": [],
                     "applicable": true,
                     "evidence": {"records": 23, "denied": 0, "shadow_denied": 23, "distinct_queries": 2,
                                  "callers": [{"caller": "analytics", "count": 23}]}}],
    "pii_flagged": [], "not_suggested": [],
    "codes": [{"code": "E_TENANT_MISSING", "category": "never_weaken", "records": 4, "advice": "..."}],
    "missing_detail": 0
  },
  "notes": []
}
```

## Server endpoint: `GET /v1/admin/report`

When [`server.admin`](config-reference.md#serveradmin) is enabled,
haltsql-server keeps a rolling window of its own recent verdicts. It serves
the same report as JSON (the shape above) to the configured admin callers.
Unauthenticated callers can never use it. The window is bounded in three
ways:

- **By age:** records older than `report_window` (default 24h) are dropped.
- **By distinct queries:** at most `max_tracked_queries` fingerprints
  (default 10000) are tracked. When a new one arrives at the limit, the least
  recently seen fingerprint and its records are evicted.
- **Per query:** at most 32 recent records of one fingerprint are kept.
  Older ones are counted in `sampled_out`, so counts for very frequent
  queries are lower bounds. Only one record per query keeps its raw SQL, and
  only when `audit.log_raw_sql` is on. Its re-derived details are shared with
  the query's other records.

Nothing is kept while the admin API is disabled. Disabling it on reload drops
the window.

| Query parameter | Default | Meaning |
|---|---|---|
| `since` | start of the window | RFC 3339, `YYYY-MM-DD`, or a duration (`1h`). It is clamped to the window. |
| `policy` | all | Only this policy. |
| `suggest` | `true` | Include suggestions. The server flags sensitive columns with the column-name heuristic. It has no PII manifest, so run the CLI with `--pii` for manifest-based flagging. |
| `top` | `20` | Top denied queries, 1 to 100. |

An unknown or repeated parameter gives `400 BAD_REQUEST`. A disabled admin
API gives `404 NOT_FOUND`. The body adds `window_seconds`,
`max_tracked_queries`, `tracked_queries`, `tracked_records`,
`evicted_queries`, `records_per_query` and `sampled_out` to the report
fields.

## A rollout loop

1. Deploy the new policy with `mode: shadow`, with `audit.log_raw_sql: true`
   if your data allows it.
2. After real traffic, run
   `haltsql report audit/ --suggest --policy-file policy.yaml --pii pii.json --format markdown`
   and review it with the policy owner.
3. Apply what you agree with:
   `--apply-to policy.yaml --accept ID ... -o policy.yaml.next`. Review the
   diff, run `haltsql test`, and commit.
4. Fix the agents' queries for everything listed under *Needs a query fix*.
5. When the shadow-denied rate is acceptable, switch to `mode: enforce`.
