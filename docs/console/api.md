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
| 400 | `BAD_REQUEST` | Malformed JSON, missing or invalid field or parameter. |
| 401 | `UNAUTHENTICATED` | No or invalid credentials. |
| 403 | `FORBIDDEN` | Authenticated, but the role lacks the permission. |
| 403 | `REASON_REQUIRED` | The permission is "with a reason" and none was given. |
| 404 | `NOT_FOUND` | Unknown route or object. |
| 409 | `CONFLICT` | State conflict (for example a case already resolved). |
| 501 | `NOT_IMPLEMENTED` | The action needs verifier support that does not exist yet. |
| 502 | `UPSTREAM` | A verifier, catalog, GitHub or Kubernetes call failed. Message has no secrets. |
| 503 | `NOT_CONFIGURED` | The feature needs configuration that is missing (for example no GitHub integration). |

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
   Only enable it when the console is reachable solely through that proxy.
3. **Service token**: `Authorization: Bearer <token>` matched (constant time)
   against `auth.tokens[].sha256`; the token carries a fixed role.
4. **Dev mode** (`auth.dev`, never in production): every request is the
   configured dev user and role.

Groups map to roles through `auth.roles` (`admin` wins over `owner`, then
`audit`, `analyst`, `dev`). A user with no mapped group gets `401`.

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
| Restart verifiers | `restart_verifiers` | no | no | no | no | yes |
| Manage roles and integrations | `manage_access` | no | no | no | no | yes |

Every role can read Overview, Signals, Agents, Fleet, Data classification,
Policies and the activity log. Cases are readable by everyone and writable by
`analyst`, `owner` and `admin`.

## Endpoints

### Health

| | |
|---|---|
| `GET /healthz` | `200 {"status":"ok"}` while the process runs. No auth. |
| `GET /readyz` | `200 {"status":"ready"}` once config is loaded and `state_dir` is writable; `503` otherwise. No auth. |

### `GET /api/v1/me`

```json
{
  "user": { "id": "dana.reyes@acme.com", "name": "Dana Reyes", "auth": "oidc:okta", "groups": ["haltsql-analysts"] },
  "role": "analyst",
  "permissions": { "use_playground": "yes", "see_raw_sql": "reason", "restart_verifiers": "no", "...": "..." },
  "environment": { "org": "Acme Corp", "name": "Production", "region": "us-east-1" }
}
```

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
records' `elapsed_us` (null when no record carries it).

Posture checks: `bundle_in_sync` (every verifier serves the same signed bundle
version), `audit_chains` (last chain verification result), `pii_exposure` (no
tagged column allowed without an approved exception), `in_process_agents`
(agents configured as in-process are not centrally audited), `restart_pending`
(any verifier with `audit_restart_pending`).

### Signals

`GET /api/v1/signals?status=open|all` returns `{ "signals": [Signal] }`, newest
and most severe first.

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

`POST /api/v1/signals/{id}` with `{ "status": "investigating", "assignee": "dana.reyes@acme.com" }`
(either field) updates workflow state. `acknowledged` is for low signals.

The `cross_tenant` signal needs the tenant values a query compared against.
Records only carry codes, so the detector counts `E_TENANT_MISMATCH` records
per caller in a sliding 10-minute window (threshold `signals.cross_tenant.min_records`, default 10);
when raw SQL is logged it also extracts the distinct values by re-verifying.

### Queries and records

`GET /api/v1/queries?q=&caller=&policy=&outcome=allowed|denied|shadow_denied&code=&table=&fingerprint=&verifier=&since=&until=&limit=&cursor=`

`q` matches a request id prefix, caller substring, fingerprint prefix, or table
name. Records never include `sql`.

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

`GET /api/v1/records/{request_id}`:

```json
{
  "record": { "...": "as above" },
  "trail": [ { "stage": "parse | tables | tenancy | limit | functions | opa | verdict",
               "state": "passed | denied | not_run | skipped", "detail": "..." } ],
  "reasons": [ { "code": "E_TENANT_MISMATCH", "rule": "tenancy.mismatch", "message": "...", "hint": "..." } ],
  "policy": { "name": "support-copilot", "version": "sha256:...", "bundle": "prod 1.4.0" },
  "custody": {
    "verifier": "haltsql-2", "seq": 8412096, "hash": "...", "prev_hash": "...",
    "neighbours": [ { "seq": 8412095, "hash": "...", "prev_hash": "...", "outcome": "allowed" } ],
    "location": "s3://acme-audit/haltsql/haltsql-2-20261107T1300Z-0412.jsonl#L412",
    "chain_state": "intact | broken | unknown", "last_verified": "...",
    "verify_command": "haltsql audit verify s3://acme-audit/haltsql/ --server haltsql-2"
  }
}
```

The trail is re-derived by re-verifying the SQL against the named policy when
raw SQL and the policy are available; otherwise from the codes alone
(`tenancy` stage from `E_TENANT_*`, `tables` from `E_TABLE_*`/`E_COLUMN_*`,
`opa` from `E_EXTERNAL_POLICY`; OPA is `not_run` when HaltSQL denied, because
OPA is only asked after an allow).

| | |
|---|---|
| `GET /api/v1/records/{id}/sql` | `see_raw_sql` with reason. `{ "sql": "...", "logged": true }`, `404` when the producer didn't log it. |
| `POST /api/v1/records/{id}/verify-chain` | Re-verifies the record's chain segment now; returns `custody`. |

### Cases

| | |
|---|---|
| `GET /api/v1/cases?status=open\|all&assignee=me` | `{ "cases": [Case] }` |
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
    "sinks": [ { "name", "type", "healthy" } ], "unhealthy_sinks": [],
    "opa": { "configured": true, "timeouts": 12 }, "restart_pending": false,
    "connections": null, "verifies_per_second": 310.2, "note": "...", "error": null } ],
  "bundles": [ { "source", "version", "signed_by", "revision", "verifiers": 8, "in_sync": true } ],
  "sinks": [ { "type": "kafka", "target": "...", "state": "healthy | buffering | failing", "verifiers": 7 } ],
  "opa": { "decision_path", "endpoint", "timeout_ms", "on_error", "decisions": { "allowed", "denied", "error_denied", "skipped" } }
}
```

`verifies_per_second` and OPA decisions come from `/metrics` when the verifier
exposes it (deltas between polls); `null` otherwise.

`POST /api/v1/fleet/{name}/restart`: `restart_verifiers` with a reason.
Restarts the verifier's Kubernetes workload (`fleet.kubernetes`, a rollout
restart patch on its Deployment or StatefulSet). `503 NOT_CONFIGURED`
outside Kubernetes.

### Data classification

`GET /api/v1/data/columns?show=allowed|all&q=`:

```json
{ "sources": [ { "kind": "dbt", "detail": "manifest.json from acme/analytics", "as_of": "...", "authoritative": true, "error": null } ],
  "totals": { "tagged": 312, "tables": 41, "blocked": 309, "exception": 2, "needs_review": 1 },
  "columns": [ { "column": "billing.invoices.tax_id", "tags": ["PII", "government id"], "sources": ["datahub"],
                 "allowed_by": ["finance-agent"], "status": "needs_review | exception | blocked",
                 "exception": { "owner", "ticket", "expires" }, "shadow_denials": 0 } ] }
```

A column allowed by a policy is `exception` when listed in
`data.exceptions` (owner, ticket, expiry), otherwise `needs_review`.
`POST /api/v1/data/refresh` re-reads every catalog (any role; rate-limited to
once a minute). A live fetch (DataHub, OpenMetadata) only flags columns; it is
never loaded as a policy catalog.

### Evidence and controls

| | |
|---|---|
| `GET /api/v1/evidence/controls?framework=soc2\|iso27001\|gdpr\|hipaa` | Control mapping: `[ { id, name, what, evidence } ]` |
| `POST /api/v1/evidence/packs` | `build_evidence`. `{ "framework", "since", "until" }` → `202 { id, state: "building" }` |
| `GET /api/v1/evidence/packs` | `[ { id, framework, since, until, built_by, created, state, records, chains: {verified, total}, manifest_sha256, gaps: [] } ]` |
| `GET /api/v1/evidence/packs/{id}/download` | `application/gzip`: a `.tar.gz` with `manifest.json`, audit records, chain reports, policy versions, activity log extract and `README.md`. |

The pack states plainly that HaltSQL holds no certification and lists gaps
(in-process agents, sources that could not be read).

### Activity log: `GET /api/v1/activity?actor=&action=&since=&limit=&cursor=`

```json
{ "entries": [ { "at": "...", "actor": "dana.reyes@acme.com", "role": "analyst", "action": "record.view_sql",
                 "target": "01930c4e-...", "reason": "CASE-1042 triage", "detail": {} } ], "next_cursor": null }
```

### Access and integrations

| | |
|---|---|
| `GET /api/v1/access/roles` | `{ "roles": [...], "permissions": [ { "id", "name", "grants": { "dev": "yes", ... } } ], "mapping": { "admin": ["okta:haltsql-admins"] }, "safeguards": [...] }` |
| `GET /api/v1/integrations` | `{ "groups": [ { "name": "Caller identity", "items": [ { "id", "name", "detail", "state": "connected | degraded | not_set_up | error", "error" } ] } ] }` |

Integrations are derived from configuration and live checks: OIDC providers
(JWKS reachable), bundle sources (from fleet), OPA, catalogs, secrets
providers, audit sinks (from fleet), Slack, PagerDuty, Jira, GitHub.
Credentials are never returned.
