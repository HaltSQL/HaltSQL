# HaltSQL Console: HTTP API

Base path `/api/v1`. JSON in and out (`content-type: application/json`).
Timestamps are RFC 3339 UTC strings with milliseconds. Counts are integers.
The machine-readable contract is [openapi.yaml](openapi.yaml).

## Conventions

**Errors** always look like the verifiers' errors:

```json
{ "error": { "code": "FORBIDDEN", "message": "role analyst lacks permission restart_verifiers" } }
```

| Status | Code | When |
|---|---|---|
| 400 | `BAD_REQUEST` | Malformed JSON, missing or invalid field or parameter, or a path parameter that decodes to `/`, `\`, NUL, `.` or `..`. |
| 401 | `UNAUTHENTICATED` | No or invalid credentials. Checked before routing, so unknown endpoints also answer `401` to unauthenticated callers. |
| 403 | `FORBIDDEN` | Authenticated, but the role lacks the permission. |
| 403 | `REASON_REQUIRED` | The permission is "with a reason" and none was given. |
| 403 | `CSRF` | A state-changing request came from another site (see *Requests* below). |
| 403 | `HOST_NOT_ALLOWED` | Dev mode only: the `Host` header is not a loopback name or address (see *Requests* below). |
| 404 | `NOT_FOUND` | Unknown route or object (authenticated callers only). |
| 405 | `METHOD_NOT_ALLOWED` | The route exists but not for this method. |
| 409 | `CONFLICT` | State conflict (for example a case already resolved). |
| 413 | `TOO_LARGE` | The request body is over 1 MiB. |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | A request body that is not `application/json`. |
| 429 | `RATE_LIMITED` | Too soon to repeat the action (for example `POST /data/refresh`). |
| 500 | `INTERNAL` | Unexpected server error (details are only logged). |
| 501 | `NOT_IMPLEMENTED` | The action needs verifier support that does not exist yet. |
| 502 | `UPSTREAM` | A verifier, catalog, GitHub or Kubernetes call failed. Message has no secrets. |
| 503 | `NOT_CONFIGURED` | The feature needs configuration that is missing (for example no GitHub integration). |
| 503 | `OVERLOADED` | More than 512 requests are in flight; retry later. |
| 503 | `TIMEOUT` | The request took longer than 30 seconds and was abandoned. |

**Requests.** Every `/api/` request is authenticated first, then routed. For
methods other than `GET`, `HEAD` and `OPTIONS`:

- a non-empty body must be sent as `content-type: application/json`
  (parameters such as `; charset=utf-8` are fine), else `415`;
- an `Origin` header, when present, must be allowed, and
  `Sec-Fetch-Site: cross-site` is refused, else `403 CSRF`. When `public_url`
  or `allowed_origins` is configured, the Origin (scheme, host and port) must
  be one of those and `Host` is not looked at, so a reverse proxy may rewrite
  `Host`. Otherwise the Origin must name the same host and port as the `Host`
  header (a missing port means the Origin scheme's default), and a reverse
  proxy in front of the console must preserve `Host`.

In dev mode every `/api/` request, `GET` included, must carry a `Host` header
naming a loopback host (`localhost`, `127.0.0.0/8` or `[::1]`, any port), else
`403 HOST_NOT_ALLOWED`. This stops a web page from reaching a local dev
console through DNS rebinding.

Bodies are read as a stream and refused with `413` as soon as they pass
1 MiB (or immediately when `Content-Length` says so).

**Reasons.** Permissions marked *Reason* need a non-empty reason, sent as the
`x-haltsql-reason` header or a `"reason"` field in the body (the body wins).
It is stored in the activity log with what the person saw or did.

**Pagination.** List endpoints take `limit` (default 50, max 500) and an
opaque `cursor`; responses have `"next_cursor": "..."` or `null`.

**Time ranges.** `range=1h|24h|7d` (default `24h`), or explicit `since` and
`until` (RFC 3339). Explicit wins.

## Authentication

In order:

1. **OIDC bearer token**: `Authorization: Bearer <JWT>` verified against a
   configured `auth.oidc` provider (JWKS, `iss`, `aud`, expiry). Name from
   `name`/`email`/`sub`, groups from the provider's `groups_claim`.
2. **Trusted auth proxy** (`auth.proxy`, off by default): an identity-aware
   proxy in front of the console (oauth2-proxy, AWS ALB OIDC, Google IAP,
   Azure App Service auth) sets the user and groups headers named in config.
   The headers are only trusted from a peer inside `auth.proxy.trusted_proxies`
   and/or when `auth.proxy.secret_header` carries the shared secret (one of the
   two is required); otherwise the request gets `401`. `auth.proxy.group_prefix`
   is prepended to proxy groups.
3. **Service token**: `Authorization: Bearer <token>` matched (constant time)
   against `auth.tokens[].sha256`; the token carries a fixed role.
4. **Dev mode** (`auth.dev`, never in production): every request is the
   configured dev user and role (default `dev`). Dev mode must be the only auth
   method and `listen` must be a loopback address; the console refuses to start
   otherwise. `--dev ROLE` clears the other methods and applies the same check.

OIDC sign-ins older than `auth.session_hours` (from `auth_time`, else `iat`)
are rejected with `401`.

Groups map to roles through `auth.roles`. A user gets every role their groups
map to (see *Several roles* below). A user with no mapped group gets `401`.

## Roles

`dev` (agent developer), `analyst` (security analyst), `owner` (policy owner),
`audit` (compliance), `admin` (platform admin).

| Permission | id | dev | analyst | owner | audit | admin |
|---|---|---|---|---|---|---|
| Use the Playground | `use_playground` | yes | yes | yes | no | yes |
| Search queries, hashes only | `search_queries` | yes | yes | yes | yes | yes |
| See raw SQL | `see_raw_sql` | no | reason | reason | reason | no |
| Pause a caller | `pause_caller` | no | reason | no | no | reason |
| Accept suggestions, open PRs | `propose_changes` | yes | yes | yes | no | yes |
| Approve a policy change | `approve_change` | no | no | yes | no | no |
| Approve a PII exception | `approve_exception` | no | no | yes | no | no |
| Build evidence packs | `build_evidence` | no | yes | yes | yes | no |
| Restart verifiers | `restart_verifiers` | no | no | no | no | reason |
| Manage roles and integrations | `manage_access` | no | no | no | no | yes |
| Open and update cases | `write_cases` | no | yes | yes | no | yes |
| See the activity log | `view_activity` | no | yes | yes | yes | yes |

`yes` is allowed, `reason` is allowed with a reason (`x-haltsql-reason` header
or a `reason` body field; the reason is written to the activity log), `no` is
`403 FORBIDDEN`. The matrix is `Rbac.grant` in `bin/console/lib/rbac.ml`;
`test/console/test_rbac.ml` checks it against this table.

**Several roles.** A person whose groups map to several roles has every one of
them, and each permission is the best grant any of those roles has (`yes`
beats `reason` beats `no`). For example `owner` + `admin` can both approve a
policy change and restart verifiers, and `analyst` + `audit` can pause a
caller with a reason and write cases. Role precedence (`admin`, `owner`,
`audit`, `analyst`, `dev`) only picks the primary role shown in the UI
(`role` in `/me`); it never decides access.

Every role can read Overview, Signals, Agents, Fleet, Data classification and
Policies. The activity log needs `view_activity`. Cases are readable by
everyone and writable with `write_cases`.

## Endpoints

### Health

| | |
|---|---|
| `GET /healthz` | `200 {"status":"ok"}` while the process runs. No auth. |
| `GET /readyz` | `200 {"status":"ready"}` when `state_dir` was writable at the last probe (at startup, then every 30 s; the probe result is cached) and no background loop is in crash backoff; `503` with `reasons` and per-loop `loops` status otherwise. No auth. |

### `GET /api/v1/me`

```json
{
  "user": { "id": "dana.reyes@acme.com", "name": "Dana Reyes", "auth": "oidc:okta", "groups": ["haltsql-analysts"] },
  "roles": ["analyst"],
  "role": "analyst",
  "role_label": "Security analyst",
  "permissions": { "use_playground": "yes", "see_raw_sql": "reason", "restart_verifiers": "no", "...": "..." },
  "environment": { "org": "Acme Corp", "name": "Production", "region": "us-east-1" }
}
```

`roles` lists every role the user's groups map to; `permissions` is the union
of their grants (see [Roles](#roles)). `role` and `role_label` are the primary
role, for display only.

### Overview: `GET /api/v1/overview?range=24h`

```json
{
  "range": { "since": "...", "until": "...", "bucket_seconds": 3600 },
  "updated": "2026-11-07T14:21:00.000Z",
  "verifiers_reporting": 8,
  "totals": { "checked": 88904, "denied": 2868, "denied_by_opa": 46, "shadow_denied": 131, "p99_ms": 1.8 },
  "series": [ { "start": "...", "allowed": 2900, "denied": 110, "shadow_denied": 4 } ],
  "posture": [ { "id": "bundle_in_sync", "state": "ok|warning|error|unknown", "title": "...", "detail": "..." } ],
  "signals": { "open": 5, "high": 1, "medium": 3, "low": 1 }
}
```

`denied` counts every enforce denial (HaltSQL or OPA); `denied_by_opa` is the
subset whose codes include `E_EXTERNAL_POLICY`. `p99_ms` comes from the
records' `elapsed_us` (null when no record carries it). `series` never has more
than 2000 buckets: for a wide explicit range `bucket_seconds` grows to a
multiple of the usual bucket.

Posture checks: `bundle_in_sync` (every verifier serves the same signed bundle
version), `audit_chains` (last chain verification result), `pii_exposure` (no
tagged column allowed without an approved exception), `in_process_agents`
(agents configured as in-process are not centrally audited), `restart_pending`
(any verifier with `audit_restart_pending`).

### Signals

`GET /api/v1/signals?status=open|all&limit=&cursor=` returns
`{ "signals": [Signal], "next_cursor": "..." | null }`, most severe and newest
first (signals known only from their stored snapshot are included).

```json
{
  "id": "sig_cross_tenant_support-bot_20261107T1356",
  "kind": "cross_tenant | deny_spike | opa_errors | sink_buffering | shadow_ready | new_caller | bundle_drift | restart_pending | chain_broken",
  "severity": "high | medium | low",
  "status": "open | investigating | contained | resolved | acknowledged",
  "title": "support-bot is filtering on other tenants",
  "body": "37 queries in 6 minutes compared tenant_id to 9 values other than acme. All were denied ...",
  "first_seen": "...", "last_seen": "...",
  "caller": "mtls:spiffe://prod/ns/support/sa/bot",
  "policy": "support-copilot", "policy_version": "sha256:...",
  "verifier": "haltsql-5",
  "assignee": null,
  "case_id": null,
  "link": { "kind": "investigation | fleet | rollout | agent", "target": "..." },
  "facts": { "records": 37, "distinct_values": 9, "codes": { "E_TENANT_MISMATCH": 21 } }
}
```

`GET /api/v1/signals/{id}` returns the signal plus its investigation:

```json
{
  "signal": { "...": "..." },
  "timeline": { "bucket_seconds": 60, "series": [ { "start": "...", "allowed": 4, "denied": 3 } ] },
  "shapes": [ { "fingerprint": "6c1e0b7f3a2d9e41", "example_shape": "SELECT id, subject, status FROM tickets WHERE tenant_id = ?",
                "count": 21, "stopped_at": "tenancy", "codes": ["E_TENANT_MISMATCH"], "request_ids": ["..."] } ],
  "caller": { "id": "...", "agent": "support-bot", "policy": "support-copilot", "usual_per_minute": 4.0, "usual_deny_rate": 0.002 },
  "request_ids": ["..."]
}
```

`timeline.series` items also carry `shadow_denied`; the investigation covers at
most the 24 hours before the signal's `last_seen` (plus 15 minutes either side)
and its timeline at most 2000 buckets. `shapes` group the signal's records by
fingerprint; `example_shape` is the raw SQL with every literal (any quoting,
including `$$...$$`, `E'...'` and `U&'...'`, and numbers) replaced by `?` and
comments dropped, when the producer logged SQL and the shape can be derived
safely (the statement parses and the shape keeps its libpg_query fingerprint);
otherwise it is the fingerprint. Viewing a signal's investigation is written to
the activity log (`signal.view`). A signal no longer in memory (after a restart,
or a week after it cleared) is served from the snapshot stored with its
workflow, in the same shape.

`POST /api/v1/signals/{id}` with `{ "status": "investigating", "assignee": "dana.reyes@acme.com" }`
(either field; `assignee: null` clears it) updates workflow state. Needs
`write_cases` (checked before the body is read, so a caller without it gets
`403` even for a malformed body). `acknowledged` is for low signals (`400`
otherwise). Returns the signal.

A signal's id is its kind, subject and the start of the window bucket the
episode began in; re-detections update the same signal. A signal whose
condition has cleared for 30 minutes (`signals.resolve_after_minutes`) becomes
`resolved` unless someone set its status. If the condition comes back after
that, it is a new signal (a new id, suffixed `_2`, `_3`, ... when the bucket is
the same) and is notified again, even if the old one had an assignee or a case;
a signal whose status a person set (other than `resolved`) keeps absorbing
recurrences.

The `cross_tenant` signal needs the tenant values a query compared against.
Records only carry codes, so the detector counts `E_TENANT_MISMATCH` records
per caller in a sliding 10-minute window (threshold `signals.cross_tenant.min_records`, default 10);
when raw SQL is logged it also extracts the distinct values by re-verifying.

### Queries and records

`GET /api/v1/queries?q=&caller=&policy=&outcome=allowed|denied|shadow_denied&code=&table=&fingerprint=&verifier=&since=&until=&limit=&cursor=`

`q` matches a request id prefix, caller substring, fingerprint prefix, or table
name. Records never include `sql`. Without `since`, `until` or `range` the whole
retention window is searched (so an old request id can still be found); `range`
applies only when given. `table` matches `schema.table` or the bare table name.
Permission `search_queries`.

```json
{ "records": [ {
    "request_id": "01930c4e-7a2f-7c41-9d2e-5b8f0a63e1d4", "ts": "...",
    "verifier": "haltsql-2", "source": "server | proxy",
    "caller": "...", "caller_type": "mtls", "policy": "support-copilot", "policy_version": "sha256:...",
    "outcome": "denied", "codes": ["E_TENANT_MISMATCH"], "tables": ["app.tickets"],
    "fingerprint": "6c1e0b7f3a2d9e41", "sql_sha256": "...", "elapsed_us": 240,
    "has_raw_sql": true
  } ], "next_cursor": null, "total": 37 }
```

Newest first (equal timestamps: most recently ingested first). The cursor names the
last record returned (its timestamp and request id), and the next page is what sorts
after it, so records that arrive between pages never shift a later page. `total` is
counted on the first page only and is `null` on later pages.

`GET /api/v1/records/{request_id}`:

```json
{
  "record": { "...": "as above" },
  "trail": [ { "stage": "parse | tables | tenancy | limit | functions | opa | verdict",
               "state": "passed | denied | not_run | skipped", "detail": "..." } ],
  "trail_source": "reverified | codes",
  "reasons_detail": "codes | redacted | full",
  "reasons": [ { "code": "E_TENANT_MISMATCH", "rule": "tenancy.mismatch", "message": "...", "hint": "..." } ],
  "policy": { "name": "support-copilot", "version": "sha256:...", "bundle": "prod 1.4.0", "loaded_version": "sha256:..." },
  "custody": {
    "verifier": "haltsql-2", "seq": 8412096, "hash": "...", "prev_hash": "...",
    "neighbours": [ { "seq": 8412095, "request_id": "...", "hash": "...", "prev_hash": "...", "outcome": "allowed" } ],
    "location": "s3://acme-audit/haltsql/2026/11/07/13/haltsql-2-20261107T130000.000001Z.42-0000000412-<sha256>.jsonl#L412",
    "chain_state": "intact | gap | broken | unknown",
    "first_break": { "seq": 8412001, "request_id": "...", "location": "...", "message": "hash mismatch (record was modified)" },
    "last_verified": "...",
    "verify_command": "haltsql audit verify s3://acme-audit/haltsql/ --host haltsql-2 --region us-east-1"
  }
}
```

`GET /records/{id}` needs `search_queries` and never includes SQL. `reasons` has one
entry per recorded code; `rule` and `hint` are `null` when only the code is known.
Re-verification (`trail_source: reverified`) names the rule behind each code, but its
messages and hints can quote SQL literals (the other tenant's value in
`E_TENANT_MISMATCH`), so by default they are replaced by the generic description of the
code (`reasons_detail: redacted`). `GET /records/{id}?details=full` returns them
(`reasons_detail: full`); it needs `see_raw_sql` and its reason, and is written to the
activity log as `record.view_details`.
`policy.bundle` comes from the last fleet snapshot of the record's verifier and
`policy.loaded_version` is the version of the policy the console loaded (both `null`
when unknown); a re-derived trail uses the loaded policy, so compare the two versions.

**Custody.** `seq` is the record's position in its verifier's stream as ingested
(files in name order, objects in key order); `neighbours` are the records up to two
positions before and after. The chain is checked locally over the records in the
index, in `seq` order, following hash links: a record continues the segment whose last
`hash` is its `prev_hash`, so independent chains under one verifier name (several hosts
under one prefix) are checked separately. A record that links to no segment starts a
new one when its `prev_hash` is the genesis hash (a new chain, as after a restart
without a spool), when it is the first record read from its file or object-sink host
(its predecessor may have left the retention window), or right after an ingestion gap
(rotation or truncation that may have skipped records, or an object skipped after
repeated read failures); otherwise the link is broken. Every hash must verify.
`chain_state` is that of the record's segment: `broken` (with `first_break`) when any
record in it fails, `gap` when the segment starts after an ingestion gap, `unknown` when
the record has no `hash`. The check is incremental (only records added since the last
check are hashed); `POST /records/{id}/verify-chain` re-walks the verifier's whole
stream, yielding to other requests as it goes, shares one walk between concurrent
calls, and serves the incremental result within 30 seconds of the last walk. The
published chain status (`chains[]`) carries `state` (`intact`, `gap`, `broken`,
`unknown`), `records`, `segments`, `gaps`, `first_break` and `checked_at`.
`verify_command` re-verifies the original records with the CLI: `haltsql audit verify
<file>` for files, `haltsql audit verify s3://bucket/prefix/ --host <host>` (plus
`--region`/`--endpoint` when configured) for S3, and, because the CLI does not read
`gs://` directly, a `gcloud storage cp -r` of the prefix followed by `haltsql audit
verify <dir> --host <host>` for GCS. `<host>` is the host in the object name.

The trail is re-derived by re-verifying the SQL against the named policy when
raw SQL and the policy are available (`trail_source: "reverified"`, with the
record's `context` if it has one, else a placeholder context); otherwise from the
codes alone (`trail_source: "codes"`). Either way the record's own codes decide each
stage's state; re-verification only adds the detailed messages, rules, hints and
tables. Codes map to stages as follows: `parse` from `E_PARSE`, `E_EMPTY`, `E_LIMIT`,
`E_MULTI_STATEMENT`, `E_STATEMENT_KIND`, `E_DATA_MODIFYING_CTE`, `E_LOCKING_CLAUSE`,
`E_SELECT_INTO`, `E_UNSUPPORTED`, `E_INTERNAL`; `tables` from `E_TABLE_*`/`E_COLUMN_*`
and `E_WRITE_DENIED`; `tenancy` from `E_TENANT_*`, `E_CONTEXT_MISSING`,
`E_PARAM_UNBOUND`; `limit` from `E_LIMIT_REQUIRED`, `E_LIMIT_TOO_HIGH`,
`E_JOIN_BUDGET`; `functions` from `E_FUNCTION_DENIED`, `E_OPERATOR_DENIED`,
`E_CAST_DENIED`; `opa` from `E_EXTERNAL_POLICY`; unknown codes are named in the
`verdict` stage. After a hard parse failure (`E_PARSE`, `E_EMPTY`, `E_LIMIT`,
`E_MULTI_STATEMENT`, `E_UNSUPPORTED`, `E_INTERNAL`) the other analyzer stages are
`not_run`. OPA is `not_run` when HaltSQL denied, because OPA is only asked after an
allow. `tenancy` is `skipped` when the loaded policy has no tenancy keys. In shadow
mode a stage that would deny is `denied` (detail says "Shadow mode") and the verdict
is `passed`.

| | |
|---|---|
| `GET /api/v1/records/{id}/sql` | `see_raw_sql` with reason. `{ "sql": "...", "logged": true }`, `404` when the producer didn't log it. Logged as `record.view_sql` (the SQL itself is never logged). |
| `POST /api/v1/records/{id}/verify-chain` | `search_queries`. Re-verifies the record's verifier chain now; returns `custody` and updates the chain status Overview reads. Logged as `record.verify_chain`. |

The console also re-verifies every verifier's chain every 5 minutes; the result
(`{ "checked_at", "chains": [ { "verifier", "state": "intact | broken | unknown",
"records", "segments", "first_break", "checked_at" } ] }`) feeds the `audit_chains`
posture check and the `chain_broken` signal.

### Cases

| | |
|---|---|
| `GET /api/v1/cases?status=open\|all&assignee=me&limit=&cursor=` | `{ "cases": [Case], "next_cursor" }`, newest first |
| `POST /api/v1/cases` | `{ "title", "signal_id"?, "request_ids"?: [], "assignee"? }` → `201 Case` |
| `GET /api/v1/cases/{id}` | `Case` |
| `PATCH /api/v1/cases/{id}` | `{ "title"?, "status"?, "assignee"?, "note"? }` |
| `POST /api/v1/cases/{id}/records` | `{ "request_ids": [] }` adds records |
| `POST /api/v1/cases/{id}/steps/{n}` | `{ "done": true }` checks off a next step |

```json
{ "id": "CASE-1042", "title": "...", "status": "open | contained | resolved", "assignee": "...",
  "created": "...", "updated": "...", "created_by": "...", "signal_id": "...",
  "request_ids": ["..."], "notes": [ { "at": "...", "by": "...", "text": "..." } ],
  "steps": [ { "text": "Confirm nothing leaked", "done": false } ] }
```

Case ids are `CASE-<n>` from a counter in the store, starting at 1000.
`status=open` (the default) lists every case that is not resolved. A case
created with `signal_id` links both ways (the signal gets `case_id`), adds the
signal's request ids, and for `cross_tenant` signals starts with default steps;
an unknown signal is `400`, a signal already linked to a case `409`. `{n}` in
`/steps/{n}` is the step's 0-based index. A resolved case only accepts
`PATCH { "status": "open" }` (reopen); other changes are `409 CONFLICT`.
Limits (`400` when exceeded): 1000 request ids per request, 10000 per case,
200 bytes per request id, 500 bytes per title, 320 per assignee, 10000 per note
and 500 notes per case. Mutations check `write_cases` before reading the body.
When
`integrations.jira` is set the case also has `"jira": { "key", "url" }` (or
`null` if the issue could not be created).

### Pause a caller: `POST /api/v1/callers/{caller}/pause`

`{ "minutes": 60, "reason": "..." }`, `pause_caller` with reason. Verifiers do
not yet consume a signed deny list, so this returns `501 NOT_IMPLEMENTED` after
logging the attempt. Until then, revoke the caller's token or identity at the
identity provider.

### Agents

`GET /api/v1/agents?via=sidecar|proxy|mcp|in_process&sort=denied|queries|newest&range=7d`

```json
{ "counts": { "all": 14, "sidecar": 7, "proxy": 3, "mcp": 2, "in_process": 2 },
  "agents": [ {
    "name": "analytics-agent", "team": "Data platform",
    "via": "sidecar | proxy | mcp | in_process", "stack": "LangGraph, Python",
    "identity": "oidc:okta svc-analytics", "callers": ["oidc:okta"],
    "policy": "analytics", "policy_version": "v12", "mode": "enforce", "shadow": ["analytics-v13"],
    "queries": 41220, "denied": 1566, "deny_rate": 0.038, "first_seen": "...", "last_seen": "...",
    "audit": "central | in_app"
  } ] }
```

Agents come from `agents:` in the config (name, team, via, stack, which
callers belong to the agent) merged with every caller seen in the index;
a caller seen in records but not configured becomes its own agent with
`via` guessed from the record (`proxy` source → `proxy`, verifier kind `mcp`
→ `mcp`, else `sidecar`). In-process agents have `queries: null`.

Agents also carry `caller_types` and `configured` (listed in `agents:`), and
the response has the `range` it covers. `sort` defaults to `denied`.

`GET /api/v1/agents/{name}` adds `top_codes: [{code, count, top_object}]`
and `policies: { enforced: {name, version, mode, origin, loaded}, shadow: [...] }`.
`top_object` is the most frequent object denied with that code (column,
function, table, `LIMIT n`), named from detailed reasons re-derived from raw
SQL when it was logged, else the most frequent table of those records.

### Playground: `POST /api/v1/playground/check`

`use_playground`. Nothing touches a database.

```json
{ "sql": "SELECT ...", "context": { "tenant_id": "acme" },
  "caller": "analytics-agent",
  "targets": [ { "policy": "analytics" }, { "policy": "analytics", "draft": "<policy YAML>" } ],
  "opa": true }
```

`caller` (an agent name) picks the policy and context defaults when
`targets` is omitted (its enforced and shadow policies). Response:

```json
{ "results": [ {
    "label": "analytics (live)", "policy": "analytics", "version": "sha256:...", "where": "live | shadow | draft",
    "allowed": false,
    "stages": [ { "stage": "parse", "state": "passed", "detail": "One SELECT." } ],
    "verdict": { "...": "verdict JSON exactly as haltsql-server returns it" },
    "opa": { "asked": false, "allowed": null, "ms": null, "error": null, "outcome": "skipped", "reasons": [] }
  } ],
  "columns": [ { "column": "app.orders.region", "tags": [], "sources": ["dbt"], "allowed_by": ["analytics"] } ],
  "test_case": "- name: ...\n  # policy: analytics\n  context: {\"tenant_id\":\"acme\"}\n  sql: ...\n  expect: allow\n",
  "sql_sha256": "..." }
```

Stages are `parse`, `tables`, `tenancy`, `functions`, `limit`, `opa`, each
`passed | denied | not_run | skipped` with a detail (`not_run` after a parse
failure, and for OPA when HaltSQL denied). `allowed` is true when the final
verdict has neither reasons nor shadow reasons (a shadow policy that would deny
reports `false`). An invalid `draft` returns `400` with
`error.errors: ["<load error>", ...]`; an unknown live policy `404`.

OPA is consulted only when the HaltSQL verdict allows, `opa` is configured
in the console (same `opa:` block as the server) and the request does not set
`"opa": false`. The input document is the server's (`caller.type` is
`playground`); `timeout_ms` and `on_error` apply as on the server.

`test_case` is one case in the `haltsql test` suite format, from the first
result (`expect` and, for a denial, `codes`); suite cases have no per-case
policy, so the policy is a comment. The activity log entry
(`playground.check`) stores the SQL's SHA-256, never the SQL.

### Policies and rollouts

| | |
|---|---|
| `GET /api/v1/policies` | `{ "policies": [ { "name", "version", "mode": "enforce|shadow", "origin": "config|bundle|file", "file", "bundle", "verifiers": ["haltsql-1"], "owner", "shadow": ["<sibling>"], "loaded": true } ], "loaded": "<last successful load>", "errors": [], "notes": [] }` |
| `GET /api/v1/policies/{name}` | Policy detail: the list fields plus `description`, `format`, `yaml` (the source; normalized YAML for inline and bundle policies), `statements`, `require_limit`, `tenancy`, `tables` (`[{table, columns, tenant_columns, writes}]`), `functions`. |
| `GET /api/v1/policies/{name}/report?since=&compare=<shadow policy>` | Shadow comparison and suggestions. |
| `POST /api/v1/policies/{name}/pull-request` | `propose_changes`. `{ "suggestions": ["<id>"], "tests": ["<yaml>"], "title"? }` opens or updates a PR in `integrations.github.repo`. `503 NOT_CONFIGURED` without GitHub. |

Report response:

```json
{
  "policy": "analytics", "compare": "analytics-v13", "days_in_shadow": 6,
  "comparison": { "records": 248310, "denied_now_allowed": 1412, "allowed_now_denied": 0, "tenancy_relaxed": 0 },
  "suggestions": [ { "id": "analytics/column/app.orders.region", "kind": "column | function | table | limit",
                     "title": "...", "evidence": { "records": 1412, "distinct_queries": 37, "callers": 3 },
                     "yaml": "...", "review": null } ],
  "never": [ { "category": "sensitive_column | tenancy | external_policy | query_fix", "codes": ["E_COLUMN_DENIED"], "records": 88, "advice": "..." } ],
  "pull_request": { "number": 212, "url": "...", "state": "open", "checks": [ { "name", "state", "detail" } ],
                    "approvals": [ { "by", "at" } ], "required_approvals": 2 }
}
```

Suggestions come from `Report.Suggest.compute`, so tenancy, writes, OPA
denials and PII columns are never suggested.

Details of the report:

- Records are the index records of the policy since `since` (RFC 3339, a date
  or a duration such as `7d`; default the whole retention window). Records
  with raw SQL are re-verified to name the denied objects, like
  `haltsql report`. The response also has `version`, `since`, `records` and
  `missing_detail`.
- `compare` defaults to the first shadow sibling (`<name>-*`, `<name>_*`,
  `<name>.*` in shadow mode); `null` (and `comparison: null`) when there is
  none. `days_in_shadow` counts from the oldest record logged under the
  compare policy.
- `comparison` re-verifies the raw SQL of the policy's records under the
  compare policy (`compared` of `records` had SQL). Records do not carry
  context values, so the re-verification uses placeholder tenancy values: in
  `literal` tenancy mode, tenant literals then never match. `tenancy_relaxed`
  counts records denied with an `E_TENANT_*` code that the compare policy
  allows.
- Suggestions also carry `code`, `applicable`, `notes` and
  `evidence.denied`/`shadow_denied`; `review` is `{pull_request, url}` when the
  stored PR includes the suggestion, else `null`.
- `never` has one row per code that is never suggested, plus one per
  sensitive column (`target`) and unsafe function. `E_TENANT_*` and
  `E_CONTEXT_MISSING` are `tenancy`, `E_EXTERNAL_POLICY` is `external_policy`,
  everything else (query fixes, writes, statement kinds) `query_fix`.
- `pull_request` is `null` until a PR was opened from the console. Its live
  state (`open | closed | merged | missing | unknown`), check runs and
  approvals (each reviewer's latest decisive review) are read from GitHub and
  cached for 30 seconds; a failed read gives `state: "unknown"` and `error`.

`POST /api/v1/policies/{name}/pull-request` applies the chosen suggestions to
the policy file in the repository with `Report.Patch` (validated before
committing; `409` when the patched policy does not validate or nothing
applies), appends `tests` (each one case or a list of cases in the
`haltsql test` format; `400` when invalid) to `<tests_path>/<name>.yaml`,
commits both in one commit on `<branch_prefix><name>` and opens a PR, or
updates the open PR it opened before for this policy. Response `201` (opened)
or `200` (updated):

```json
{ "number": 212, "url": "...", "branch": "haltsql-console/analytics", "head_sha": "...", "state": "open",
  "created": true, "applied": ["analytics/column/app.orders.region"], "skipped": [ { "id", "reason" } ],
  "files": ["policies/analytics.yaml", "tests/analytics.yaml"] }
```

The PR is stored (`number`, `url`, `branch`, `head_sha`, suggestions) and the
action logged as `policy.pull_request`.

### Fleet

`GET /api/v1/fleet`:

```json
{
  "updated": "...", "config_generation": 14,
  "verifiers": [ {
    "name": "haltsql-1", "kind": "server | proxy | mcp", "location": "shared service, zone a", "url": "...",
    "state": "ready | buffering | restart_pending | not_ready | unreachable",
    "version": "0.1.0", "uptime_seconds": 345600,
    "policies": [ { "name", "version", "mode", "origin" } ],
    "bundle": { "source", "bundle", "version", "signed_by", "revision", "checks", "last_success", "last_error" },
    "bundles": [ { same fields as bundle, one per bundle source } ],
    "sinks": [ { "name", "type", "healthy" } ], "unhealthy_sinks": [],
    "opa": { "configured": true, "timeouts": 12 }, "restart_pending": false,
    "connections": null, "verifies_per_second": 310.2, "note": "...", "error": null } ],
  "bundles": [ { "source", "version", "signed_by", "revision", "verifiers": 8, "in_sync": true } ],
  "sinks": [ { "type": "kafka", "target": "...", "state": "healthy | buffering | failing", "verifiers": 7 } ],
  "opa": { "decision_path", "endpoint", "timeout_ms", "on_error", "in_sync": true,
           "configs": [ { "decision_path", "endpoint", "timeout_ms", "on_error", "verifiers": [names] } ],
           "decisions": { "allowed", "denied", "error_denied", "skipped" } }
}
```

`verifies_per_second` and OPA decisions come from `/metrics` when the verifier
exposes it (deltas between polls); `null` otherwise.

Before the first poll the document is empty: `updated` and `config_generation`
are `null` and the lists are empty. Details:

- `state`: `unreachable` (no HTTP answer, or for a proxy no TCP connection;
  `error` says why), `buffering` (an audit sink is unhealthy or has buffered
  records), `not_ready` (`/readyz` is 503 for another reason: no policy,
  draining), `restart_pending` (`audit_restart_pending`), else `ready`.
  `note` is a human sentence about the state. `error` reports a failed probe
  even when the state is known (e.g. a 403 on the admin status).
- `config_generation` (top level) is the highest generation reported; each
  verifier also carries its own `config_generation`.
- Extra fields: verifier `sinks[].buffered_records`, `buffered_records` (total),
  `opa.external_policy_denials`; bundle `versions: [ { version, revision,
  signed_by, verifiers: [names] } ]` (majority first; the top-level version is
  the majority's); sink `buffered_records`, `peak_buffered_records`,
  `unhealthy_verifiers`; `opa.configured`, `opa.decisions.error_allowed` and
  `opa.window_seconds`.
- `opa.timeouts` (per verifier) counts OPA errors (`error_allowed` +
  `error_denied`: timeouts and failures), and `opa.decisions` the decisions of
  every verifier, both over the in-memory history (the last 120 polls,
  `window_seconds`). Fields are `null` when the verifier has no `/metrics`.
- `bundle` is the verifier's first bundle source (kept for compatibility);
  `bundles` lists every source. Source ids and `last_error` have the query,
  fragment and userinfo of any URL replaced (`?<redacted>`), since every role
  can read this document.
- `opa`: the top-level settings are the majority's; `configs` groups the
  verifiers by OPA settings (majority first) and `in_sync` is false when they
  differ.
- `error` on an unreachable verifier that is backing off says when it is
  probed next (`fleet.max_concurrent_probes` in config.md).
- `kind: mcp`/`proxy` verifiers without admin status get their state from
  `/readyz` and `/metrics` (404s are not errors); a proxy with a non-HTTP `url`
  from a TCP connect.

`POST /api/v1/fleet/{name}/restart`: `restart_verifiers` and a reason (always
required for restarts, even for roles granted the permission outright).
Restarts the verifier's Kubernetes workload (`fleet.kubernetes`, a rollout
restart patch on its Deployment or StatefulSet) and returns
`{ "verifier", "workload": "deployment/haltsql-1", "restarted_at", "result": "ok | no_rollout" }`.
`no_rollout` (with a `warning`) means the patch was accepted but will not
restart pods: a paused Deployment or a StatefulSet with `updateStrategy:
OnDelete`. The intent is logged as `fleet.restart_requested` before the
Kubernetes call (the restart is refused if that write fails), and the outcome
as `fleet.restart`. `404` for an unknown verifier, `503 NOT_CONFIGURED`
without `fleet.kubernetes` or the verifier's `workload`, or when the console's
own setup fails at restart time (token file unreadable, bad CA), `502
UPSTREAM` when the Kubernetes API fails (the message carries the HTTP status
and Status `reason`, never the token).

### Data classification

`GET /api/v1/data/columns?show=allowed|all&q=`:

```json
{ "updated": "...", "loaded": "...", "shadow_denials_counted": "...",
  "sources": [ { "kind": "dbt", "label": "dbt", "detail": "manifest.json from acme/analytics", "as_of": "...", "authoritative": true, "error": null } ],
  "totals": { "tagged": 312, "tables": 41, "blocked": 309, "exception": 2, "needs_review": 1 },
  "columns": [ { "column": "billing.invoices.tax_id", "tags": ["PII", "government id"], "sources": ["datahub"],
                 "authoritative": true,
                 "allowed_by": ["finance-agent"], "status": "needs_review | exception | blocked",
                 "exception": { "column", "policy", "owner", "ticket", "expires", "expired": false }, "shadow_denials": 0 } ] }
```

`show` defaults to `allowed` (every status but `blocked`); `totals` always count every
tagged column. `q` matches a substring of the column or of a tag. `exception` is `null`
unless an exception matches; for `needs_review` it is the expired (or partial)
exception, with `expired`. Column `sources` are catalog labels (default: the kind);
`authoritative` is false when only live fetches tag the column. See
[config.md](config.md#catalogs-and-data) for how the status is derived.

A column allowed by a policy is `exception` when listed in
`data.exceptions` (owner, ticket, expiry), otherwise `needs_review`.
`shadow_denials` comes from a background scan of the record index every minute
(`shadow_denials_counted` is when it last finished, `null` before the first); `GET`
never scans the index.
`POST /api/v1/data/refresh` re-reads every catalog and recounts shadow denials (any role; rate-limited to
once a minute, `429 RATE_LIMITED` otherwise; logged as `data.refresh`) and returns
`{ "updated", "sources", "totals" }`. A live fetch (DataHub, OpenMetadata) only flags columns; it is
never loaded as a policy catalog.

### Evidence and controls

| | |
|---|---|
| `GET /api/v1/evidence/controls?framework=soc2\|iso27001\|gdpr\|hipaa` | Any role. Control mapping (default `soc2`): `{ framework, framework_name, disclaimer, controls: [ { id, name, what, evidence: [string] } ] }` |
| `POST /api/v1/evidence/packs` | `build_evidence`. `{ "framework", "since", "until"?, "include_sql"? }` (`until` defaults to now) → `202 { id: "pack_<n>", state: "building" }`. `include_sql: true` also needs `see_raw_sql` and its reason (`403 REASON_REQUIRED` without one). One build at a time per console: `409 BUILD_IN_PROGRESS` while another is building. A period holding more than 1,000,000 records is refused (`400`). Logged as `evidence.build` (detail `include_sql`; the reason when SQL is included). |
| `GET /api/v1/evidence/packs` | `build_evidence`. `{ "packs": [ { id, framework, since, until, built_by, created, state: "building\|ready\|failed", records, chains: {verified, total}, manifest_sha256, bytes, include_sql, sql_redacted, gaps: [ { kind, name, detail } ], error } ] }`, newest first. |
| `GET /api/v1/evidence/packs/{id}/download` | `build_evidence`. `application/gzip`, streamed from disk (with `content-length`): a `.tar.gz` with `manifest.json`, audit records, chain reports, policy versions, activity log extract and `README.md`. `409 CONFLICT` while building or after a failure. Logged as `evidence.download`. |
| `DELETE /api/v1/evidence/packs/{id}` | `build_evidence`. Deletes the pack's file and listing entry → `{ id, deleted: true }`. `409` while building, `404` when unknown. Logged as `evidence.delete`. |

Control ids: `soc2` CC6.1, CC6.3, CC7.2, CC8.1, A1.2; `iso27001` A.5.15, A.8.2, A.8.15,
A.8.16, A.8.32; `gdpr` Art. 5(1)(f), Art. 25, Art. 30, Art. 32; `hipaa`
164.308(a)(1)(ii)(D), 164.312(a)(1), 164.312(b), 164.312(c)(1). Wording follows
[security/compliance.md](../security/compliance.md).

The archive has one top-level directory `pack_<n>/` with `README.md` (scope,
disclaimer, gaps, file list), `manifest.json` (SHA-256 and size of every other file,
record counts per verifier, chain results, builder, period, generator),
`records/<verifier>.jsonl` (the audit lines in the period, as ingested except that
SQL text, `sql` and `statement`, is removed unless the pack was built with
`include_sql`; `sql_sha256` stays. A verifier name that is not a safe file name gets a
sanitised name plus a short hash, and each records file's `verifier` is in the manifest),
`chains.json` (per verifier, with the same rules as the chain-of-custody page:
`state` `intact | broken | unknown`, `verified` (chained records checked), `segments`
(a genesis `prev_hash` starts a new segment, e.g. after a restart without a spool),
`unchained` (records without a hash), and `first_break`
`{ line, problem, request_id, location }`, `line` being the line of the records file;
the first record of each segment may link to a record outside the period and is
accepted as is. Verification runs on the records as ingested, so a line whose SQL was
removed does not verify on its own from the pack; verify it against the audit store
with `haltsql audit verify`),
`policies.json` (`seen_in_records` versions and the `loaded` policies), `activity.jsonl`,
`exceptions.json` and `controls.json`. `manifest_sha256` in the listing is the SHA-256 of
`manifest.json`; `raw_sql` in the manifest is `{ included, reason, redacted_records }`.
The gzip stream uses uncompressed (stored) DEFLATE blocks; it is a
standard gzip file. Gap kinds: `in_process_agent` (agents with `via: in_process`),
`source_error` (audit sources whose ingestion reports an error) and `retention` (the
period starts before the index's retention window, `audit.retention_hours`, or records
of the period were evicted by `audit.max_records`; the detail names the first covered
time).

Packs are built in a worker thread and written to a temporary file (fsynced, then
renamed), so the console keeps serving requests during a build. The 20 most recent
finished packs are kept: after each successful build, older ones and their files are
deleted.

The pack states plainly that HaltSQL holds no certification and lists gaps
(in-process agents, sources that could not be read, periods outside retention).

### Activity log: `GET /api/v1/activity?actor=&action=&since=&limit=&cursor=`

Needs `view_activity` (see [Roles](#roles)). Newest first.

```json
{ "entries": [ { "seq": 48213, "at": "...", "actor": "dana.reyes@acme.com", "role": "analyst", "action": "record.view_sql",
                 "target": "01930c4e-...", "reason": "CASE-1042 triage", "detail": {} } ],
  "next_cursor": null, "total": 1, "window_oldest_seq": 1 }
```

`actor` matches exactly, `action` is a prefix, `since` is RFC 3339. Every
entry has a `seq`: a persisted integer that only grows (it resumes after a
restart). Paging is keyset on `seq`: the cursor is the last `seq` returned, so
entries logged between two requests never shift or repeat a page; they appear
on a fresh first page.

Queries cover the **in-memory window**: the most recent 50,000 entries, loaded
from the tail of the log at startup. `window_oldest_seq` is the oldest `seq`
in it (`null` when the log is empty); older entries are only in the files.
Evidence packs read every file, not the window.

Storage: each entry is one JSON line appended (and fsynced) to
`activity.jsonl` in `state_dir`. When that file reaches 64 MiB it is renamed
to `activity-<first seq>.jsonl` and a new file is started. Rotated files are
never deleted by the console: the log is an audit trail, so retention and
archival (for example moving old files to object storage) are an operator
concern.

### Access and integrations

| | |
|---|---|
| `GET /api/v1/access/roles` | Any role. `{ "roles": [ { "id", "label" } ], "permissions": [ { "id", "name", "grants": { "dev": "yes", ... } } ], "mapping": { "admin": ["okta:haltsql-admins"] }, "safeguards": [ { "id", "title", "detail", "verified" } ], "dev_mode" }` |
| `GET /api/v1/integrations` | `{ "groups": [ { "name": "Caller identity", "items": [ { "id", "name", "detail", "state": "configured | not_set_up | connected | error", "error" } ] } ] }` |

`mapping` (the group-to-role mapping from `auth.roles`) is included only when
the caller has `manage_access`; for everyone else the field is omitted. Roles,
the matrix and the safeguards are visible to every role.

Each safeguard says whether the console itself checks it (`verified`):

| id | detail | verified |
|---|---|---|
| `two_person_rule` | Policy changes need two owners, never the requester. Expected to be enforced by branch protection on the policy repository; the console cannot see that setting. | `false` |
| `sessions` | OIDC sign-ins older than `auth.session_hours` are rejected (from the token's `auth_time`, else `iat`). | `true` |

Integration `state` values:

| state | meaning |
|---|---|
| `configured` | Present in the console configuration; no live check has run (or none exists for it). |
| `not_set_up` | Not in the configuration. |
| `connected` | A live check succeeded. |
| `degraded` | A live check succeeded partially; `error` says what is wrong. |
| `error` | A live check failed; `error` says why. |

Live checks: OIDC providers (JWKS reachable, checked at most every 5 minutes:
`degraded` when the JWKS has no usable key, `error` when unreachable), bundle
sources (from the fleet snapshot; `degraded` when verifiers serve different
versions), catalogs (`connected` after a load, `error` when the last load failed,
`configured` before the first load), audit sources (`connected` once ingestion has
read them, `error` when it reports one, `configured` before it reports), audit sinks
(from the fleet snapshot; `degraded` unless healthy). OPA, Slack, PagerDuty, Jira and
GitHub are `configured` or `not_set_up`. Credentials are never returned; URLs are
shown without user info or query.
