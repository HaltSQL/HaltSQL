# HaltSQL Console: configuration

`haltsql-console --config console.yaml` (or `HALTSQL_CONSOLE_CONFIG`). YAML or
JSON. A complete example is
[deploy/console/console.example.yaml](../../deploy/console/console.example.yaml).
Unknown keys are errors.

**Secrets.** Any string can contain `${env:NAME}`, `${vault:...}`,
`${aws-sm:...}` or `${gcp-sm:...}`. Provider placeholders need a `secrets:`
section with the same shape as the server's ([secrets.md](../secrets.md)).
`$${` writes a literal `${`. Resolved values are never logged or returned by
the API.

When placeholders are resolved depends on the section:

- **At load:** the sections the console reads at startup (`listen`,
  `environment`, `state_dir`, `frontend_dir`, `auth`, `verifiers`, `fleet`,
  `audit`, `policies`, `catalogs`, `data`, `agents`). A placeholder that cannot
  be resolved is a startup error.
- **On demand:** `opa`, `integrations` and `signals`. At load each placeholder
  is only checked: valid syntax, a known scheme, the provider configured in
  `secrets:`, and for `${env:...}` the variable set. Errors stop startup. The
  value is fetched only when a feature needs it (for example when it posts to
  Slack). Provider values are cached for at most 5 minutes, so a rotated secret
  is picked up without a restart, and the console does not keep these secrets
  in memory between uses.

The configuration document the console keeps for feature-specific keys is the
file as written, with its placeholders unresolved.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8090` | `host:port` to serve on. `--listen`, then `HALTSQL_CONSOLE_LISTEN`, override it (the container image sets `HALTSQL_CONSOLE_LISTEN=0.0.0.0:8090`). |
| `public_url` | none | The URL browsers use to reach the console, for example `https://console.example.com`: `http` or `https`, a host, an optional port, no path. Its origin is added to `allowed_origins`. |
| `allowed_origins` | `[]` | More browser origins (`scheme://host[:port]`) allowed to send state-changing requests, for example a frontend dev server. See [Origins](#origins). |
| `environment.org`, `.name`, `.region` | `HaltSQL`, `Default`, none | Shown in the environment switcher. |
| `state_dir` | `./console-state` | Durable state (cases, activity log, signal workflow, evidence packs). Must be writable; `/readyz` is 503 otherwise. Put it on a persistent volume. |
| `frontend_dir` | none | Directory with the built web frontend, served at `/`. |

## `auth`

At least one of `oidc`, `proxy`, `tokens`, `dev`. `dev` cannot be combined
with the others.

| Key | Meaning |
|---|---|
| `oidc[]` | `name`, `issuer`, `audience` (or `audiences`), optional `jwks_uri`, `groups_claim` (default `groups`), `group_prefix` (default `<name>:`), `leeway_seconds`, `allow_insecure_http` (tests only). Tokens are verified like the server verifies callers (JWKS, `iss`, `aud`, expiry; RS256, ES256, PS256, EdDSA), and the sign-in must be recent enough for `session_hours`. |
| `proxy` | Trusts identity headers set by an identity-aware proxy. See [`auth.proxy`](#authproxy). |
| `tokens[]` | `name`, `sha256` (hex SHA-256 of the token), `role`. For automation. |
| `dev` | `true`, or `{ user, role }`. The role defaults to `dev`. Every request without credentials is that user. Development only: see [Dev mode](#dev-mode). `--dev ROLE` does the same. |
| `roles` | `{ admin: [groups], owner: [...], analyst: [...], audit: [...], dev: [...] }`. A user gets every role one of their groups maps to, and their permissions are the union of those roles. The most privileged role (`admin`, then `owner`, `audit`, `analyst`, `dev`) is shown as their primary role. A user whose groups map to no role is refused. |
| `session_hours` | 1 to 720, default 8. An OIDC token is refused with `session expired; sign in again` when its `auth_time` claim (or `iat` when there is no `auth_time`) is more than `session_hours` old. A token with neither claim is accepted until it expires, unless `require_auth_time` is set. Not applied to proxy headers or service tokens: set the session length on the proxy. |
| `require_auth_time` | Default `false`. When `true`, an OIDC token without an `auth_time` claim is refused (`session expired; sign in again`), so `session_hours` is measured from the actual sign-in. Check that your provider sets `auth_time` (some only do when the client asks for it, for example with `max_age`). The Access page shows the *Sessions* safeguard as verified only when OIDC is the only auth method and this is `true`. |

### `auth.proxy`

| Key | Meaning |
|---|---|
| `user_header` | Required. Header with the user's id (for example `X-Auth-Request-Email`). |
| `name_header` | Optional display-name header. |
| `groups_header` | Optional header with comma-separated groups. |
| `group_prefix` | Prepended to each proxy group before role mapping. Default `""`. Set it (for example `proxy:`) when OIDC is also configured, so a proxy group can't collide with an OIDC group. |
| `label` | Shown as the auth method, `proxy:<label>`. Default `proxy`. |
| `trusted_proxies` | IPs or CIDRs (IPv4 or IPv6) of the proxy, for example `[10.0.0.0/8, "fd00::/8"]`. The TCP peer of the request must be in one of them. |
| `secret_header`, `secret_sha256` | A header the proxy adds with a shared secret, and the hex SHA-256 of that secret. The header must hash to `secret_sha256`. The comparison is constant-time. |

You must set `trusted_proxies`, the shared secret, or both. When both are
set, both checks must pass. A request that carries `user_header` but fails a
check gets `401` (`proxy identity headers from an untrusted source`). It is
not treated as anonymous. Still make sure the console can only be reached
through the proxy, and that the proxy strips these headers from client
requests.

### Dev mode

`auth.dev` is refused at startup unless:

- it is the only auth method: no `oidc`, `proxy` or `tokens`, and
- `listen` is a loopback address: `127.0.0.0/8`, `::1` (`[::1]:port`) or
  `localhost`. An empty host or `*` means `0.0.0.0`, which is not loopback.

These rules also apply after `--listen` and `--dev` overrides (either one
alone or both), and the server checks them again before it binds. When dev
mode is not configured, a request without credentials is always `401`.

In dev mode, every `/api/` request must also be addressed to a loopback host:
its `Host` header must be `localhost`, an address in `127.0.0.0/8` or `[::1]`
(any port), else `403 HOST_NOT_ALLOWED`. This blocks DNS rebinding, where a
web page on another site resolves its own name to `127.0.0.1` and calls the
console from the browser.

## Origins

State-changing `/api/` requests (anything but `GET`, `HEAD`, `OPTIONS`) are
checked against cross-site request forgery. A request without an `Origin`
header (curl, scripts) passes. A request with one passes when:

- `public_url` or `allowed_origins` is set: the Origin's scheme, host and port
  are one of the configured origins (a missing port is the scheme's default).
  The `Host` header is not used, so this works behind a reverse proxy or load
  balancer that rewrites `Host`.
- neither is set: the Origin names the same host and port as the `Host`
  header. A proxy in front must then pass `Host` through unchanged.

`Sec-Fetch-Site: cross-site` is refused in both cases.

## `verifiers[]`

| Key | Meaning |
|---|---|
| `name` | Unique; matches the `verifier` of audit sources. |
| `url` | Base URL of the verifier's HTTP API (for `kind: proxy`, its PostgreSQL address; see [`fleet`](#fleet)). |
| `kind` | `server` (default), `proxy`, `mcp`. |
| `location` | Free text shown in Fleet. |
| `token` | Admin bearer token; the verifier must list it in `server.admin.callers`. |
| `metrics_url` | Default `<url>/metrics`. |
| `workload` | Kubernetes workload to restart, e.g. `deployment/haltsql-1`. |

## `fleet`

```yaml
fleet:
  poll_seconds: 30
  kubernetes:                     # optional: enables POST /api/v1/fleet/{name}/restart
    namespace: haltsql
    # api: https://kubernetes.default.svc
    # token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    # ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

| Key | Default | Meaning |
|---|---|---|
| `poll_seconds` | `30` | How often every verifier is polled. Each poll reads `<url>/v1/admin/status` (with `token`), `<url>/readyz` and `metrics_url`, concurrently, with a 5 second timeout each. |
| `kubernetes.namespace` | required | Namespace of the verifier workloads. |
| `kubernetes.api` | `https://kubernetes.default.svc` | API server URL. `http://` is accepted (tests, `kubectl proxy`); with `https://` the server is verified against `ca_file`. |
| `kubernetes.token_file` | in-cluster service-account token | Re-read on every restart, so projected tokens rotate. |
| `kubernetes.ca_file` | in-cluster CA | Cluster CA bundle (PEM). |

What each verifier kind exposes:

- `server`: everything. `/v1/admin/status` needs `server.admin` enabled with the
  console's token in `server.admin.callers`; without it (404) the state comes from
  `/readyz` and `/metrics` only. A 401/403 is shown as the verifier's `error`.
- `mcp`: polled the same way; a 404 on any endpoint is not an error.
- `proxy`: `haltsql-proxy` has no HTTP endpoints. Give its PostgreSQL address as `url`
  (`postgres://host:6432` or `tcp://host:6432`) and the console checks that it accepts
  TCP connections. An `http(s)://` url is polled like a server.

The admin `token` is sent to `metrics_url` only when it has the same scheme, host and
port as `url`.

Rates (`verifies_per_second`), OPA decision counts, OPA errors (`timeouts`) and
buffered-record peaks are computed from the last 120 polls kept in memory, so they
restart from zero when the console restarts.

### RBAC for restarts

A restart is the patch `kubectl rollout restart` sends (a new
`kubectl.kubernetes.io/restartedAt` pod-template annotation) on the verifier's
`workload` (`deployment/<name>` or `statefulset/<name>`). The console's service account
needs only `patch` on those workloads in that namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: haltsql-console-restart, namespace: haltsql }
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    # optionally pin resourceNames: ["haltsql-1", "haltsql-2"]
    verbs: ["patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: haltsql-console-restart, namespace: haltsql }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: haltsql-console-restart }
subjects:
  - { kind: ServiceAccount, name: haltsql-console, namespace: haltsql }
```

Restarts need the `restart_verifiers` permission (admin) **and** a reason, and are
written to the activity log as `fleet.restart` (also when the Kubernetes call fails).

## `audit`

Where the console reads audit records. The console only reads; the verifiers keep
writing their sinks as configured.

```yaml
audit:
  sources:
    - { verifier: haltsql-1, file: /var/log/haltsql/audit.jsonl }
    - { verifier: auto, file: /var/log/haltsql/ }            # every *.jsonl / *.log inside
    - { verifier: auto, file: "/var/log/haltsql/audit-*.jsonl" }
    - { verifier: auto, s3: "s3://acme-audit/haltsql/", region: us-east-1 }
    - { verifier: auto, gcs: "gs://acme-audit/haltsql/" }
  retention_hours: 168
  max_records: 2000000
  poll_seconds: 5
```

| Key | Default | Meaning |
|---|---|---|
| `sources[]` | none | Exactly one of `file` (alias `path`), `s3` or `gcs`, plus `verifier`. |
| `sources[].verifier` | `auto` | Verifier name the records belong to (matches `verifiers[].name`). With `auto`, the name comes from the object name (object sinks write `<host>-<run>-<seq>-<sha256>.jsonl`, so the host), else the file's basename without extension. |
| `sources[].file` | | A file, a directory (every `*.jsonl` and `*.log` directly inside, in name order) or a glob with `*`/`?` in the last path segment. Files are tailed by byte offset; only complete lines are read. A file that shrinks or is replaced (new inode, as with rotation) is read again from the start. |
| `sources[].s3` | | `s3://bucket/prefix`. Every `.jsonl` object under the prefix is read once, in key order. Credentials: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (optional `AWS_SESSION_TOKEN`), web identity (IRSA), ECS/EKS Pod Identity or the instance profile. Needs `s3:ListBucket` and `s3:GetObject` only. |
| `sources[].region` | `AWS_REGION`, else `us-east-1` | S3 signing region. |
| `sources[].endpoint` | AWS | S3-compatible endpoint (path-style; https, or http on loopback). |
| `sources[].gcs` | | `gs://bucket/prefix`, read like S3 through the JSON API. Credentials: `GOOGLE_APPLICATION_CREDENTIALS` (service-account key file), else the metadata server (Workload Identity). Needs `storage.objects.list` and `storage.objects.get`. `STORAGE_EMULATOR_HOST` overrides the API base. |
| `retention_hours` | `168` | Records older than this are dropped from the in-memory index. |
| `max_records` | `2000000` | Index size cap; the oldest records are evicted first. |
| `poll_seconds` | `5` | How often every source is polled. |

Each verifier's records are numbered (`seq`) in the order they are read; the chain of
custody check walks that order. Per-source state (records read, last successful read,
last error) is kept as the console's ingest status for the other views. Objects are listed in full on every poll, so
prefer a prefix that holds only HaltSQL audit objects.

## `policies` and `opa`

The console loads the same policies as the verifiers, for the Playground, policy
detail, shadow reports and suggestions. Loading runs at startup and every 60
seconds; a load that fails anywhere keeps the last good set (like the server's
hot reload), and the errors are shown in `GET /api/v1/policies` (`errors`, file
basenames only). A policy file is read and parsed once per change: a reload
reuses the parsed policy while the file's modification time and size are
unchanged.

| Key | Meaning |
|---|---|
| `policies.server_config` | A haltsql-server config file. Only its `policies` section is decoded, with the server's loader: the console never resolves the server's other secrets (database, admin tokens, OPA headers), so its identity needs no access to them. A secret provider placeholder inside `policies` (for example a bundle key) is resolved through the file's own `secrets:` section, with one resolver kept for an hour across reloads. Supported: `policies[].path`, `policies[].inline`, and local signed bundles (`policies[].bundle` with `public_keys` and `name_prefix`; the signature is verified). **Not** fetched: remote `bundle_source` entries; their policies appear only through fleet status (`loaded: false`). |
| `policies.files` | Policy files, or directories whose `*.yaml`/`*.yml`/`*.json` documents with `kind: Policy` are loaded (other documents, such as test suites, are skipped). They replace server-config policies of the same name, like the server's `--policy` flags. |

Relative paths are resolved against the console config file's directory. A
policy's `version` is the same `sha256:` the verifiers log as
`policy_version`. A *shadow sibling* of policy `P` is a loaded shadow-mode
policy named `P-*`, `P_*` or `P.*`; it is the default `compare` of
`GET /api/v1/policies/P/report` and an agent's default shadow policy.

`opa` has exactly the shape of the server's `opa` block (`url`,
`decision_path`, `timeout_ms`, `on_error`, `headers`, `tls.ca_file`). When set,
the Playground asks OPA after a HaltSQL allow, with the same input document as
the server (`caller.type` is `playground`), honouring `timeout_ms` and
`on_error`.

```yaml
policies:
  server_config: /etc/haltsql/server.yaml
  files: [/etc/haltsql/policies/drafts]
opa:
  url: https://opa.internal:8181
  decision_path: haltsql/allow
  timeout_ms: 500
  on_error: deny
```

## `signals`

Detectors run every 30 seconds over the record index, the fleet snapshot and the
last audit-chain verification. Every key is optional; numbers may be integers or
decimals.

```yaml
signals:
  cross_tenant: { window_minutes: 10, min_records: 10 }
  deny_spike:   { window_minutes: 15, factor: 3.0, min_records: 50, min_baseline_rate: 0.01 }
  opa_errors:   { window_minutes: 15, min_records: 10 }
  shadow_ready: { min_records: 1 }
  new_caller:   { hours: 24 }
```

| Key | Default | Meaning |
|---|---|---|
| `cross_tenant.window_minutes` | `10` | Sliding window for `E_TENANT_MISMATCH` records per caller. |
| `cross_tenant.min_records` | `10` | Records in the window that open a high `cross_tenant` signal. |
| `deny_spike.window_minutes` | `15` | Window whose deny rate is compared with the caller's previous 24 hours. |
| `deny_spike.factor` | `3.0` | The window's deny rate must be at least this many times the baseline. |
| `deny_spike.min_records` | `50` | Minimum records from the caller in the window. |
| `deny_spike.min_baseline_rate` | `0.01` | Baseline deny rate used when the real one is lower, so one denial after a quiet day is not a spike. |
| `opa_errors.window_minutes` | `15` | Window for `E_EXTERNAL_POLICY` denials and for the fleet's OPA error counter delta. |
| `opa_errors.min_records` | `10` | `E_EXTERNAL_POLICY` denials in the window that open a signal (any increase of the fleet's OPA error counter also does). |
| `shadow_ready.min_records` | `1` | Shadow-denied records in 24 hours that open a `shadow_ready` signal for a policy. |
| `new_caller.hours` | `24` | A caller first seen this recently and not listed under `agents` opens a low signal. Only checked once the index holds older records, so a fresh console does not flag every caller. |

`sink_buffering`, `restart_pending` and `bundle_drift` come from the fleet
snapshot and `chain_broken` from the last chain verification; they have no
settings. A signal whose condition has cleared for 30 minutes is resolved
automatically unless someone set its status. Detector output is kept in memory
and rebuilt after a restart; status, assignee and linked case are stored in
`state_dir` (`signals.json`).

## `agents`

Agents shown in `GET /api/v1/agents`. Every caller seen in audit records that
no agent claims becomes its own agent (`via` guessed: proxy records → `proxy`,
a verifier of kind `mcp` → `mcp`, else `sidecar`).

| Key | Meaning |
|---|---|
| `name` | Required, unique. |
| `team`, `stack`, `identity` | Free text shown on the agent. |
| `via` | `sidecar` (default), `proxy`, `mcp` or `in_process`. In-process agents verify inside the app, so the console has no records for them (`queries: null`, `audit: in_app`). |
| `callers` | Audit `caller` values that belong to this agent (exact match). |
| `policy` | Its enforced policy; default the most frequent policy of its records. |

```yaml
agents:
  - name: analytics-agent
    team: Data platform
    stack: LangGraph, Python
    callers: ["oidc:okta:svc-analytics"]
    policy: analytics
```

## `catalogs` and `data`

Catalogs are read at startup, every 15 minutes, and on `POST /api/v1/data/refresh`.
A catalog that cannot be read is reported (in `GET /api/v1/data/columns` `sources[].error`
and as `error` under Integrations); the others still load.

```yaml
catalogs:
  - { kind: dbt, manifest: /etc/haltsql/catalogs/manifest.json }
  - { kind: unity, file: /etc/haltsql/catalogs/unity-column-tags.json }
  - { kind: datahub, file: /etc/haltsql/catalogs/datahub-export.json }
  - { kind: openmetadata, url: https://om.acme.internal/api, token: "${vault:secret/om#token}", service: prod_pg, database: app }
  - { kind: file, file: /etc/haltsql/policies/pii.json, label: reviewed }
data:
  exceptions:
    - { column: app.customers.email, policy: support-copilot, owner: Lee Park, ticket: SEC-88, expires: "2027-02-01" }
```

| `catalogs[]` key | Meaning |
|---|---|
| `kind` | `dbt`, `datahub`, `openmetadata`, `unity` or `file`. |
| `label` | Name shown in column `sources` and Integrations. Default: the kind. |
| `manifest` | `dbt`: the `manifest.json` (column `tags`, `meta`, `config.tags`, `config.meta`, `policy_tags`, nested `meta.pii`). |
| `catalog` | `dbt`, optional: `catalog.json` (column comments). |
| `file` | `datahub`: a file-sink export or GraphQL response. `unity`: `information_schema.column_tags` rows or table JSON. `file`: a HaltSQL PII manifest (the `haltsql schema import` format). |
| `url` | `datahub`, `openmetadata`, `unity`: read the catalog's API live through `Haltsql_catalog_fetch` (same providers as `haltsql schema fetch`). `https://`, or `http://` on loopback. |
| `token` | Bearer token for `url`. Use a secret placeholder; never returned or logged. |
| `service`, `database`, `schemas` | Live fetch scope, as `haltsql schema fetch --service/--database/--schema`. |
| `ca_file`, `timeout_seconds` | Live fetch: trust only this CA bundle; per-request timeout (default 30). |
| `tags`, `terms` | Labels that mark a column as sensitive (default: `pii`, `sensitive`, `confidential`, `restricted`, `gdpr`, `phi`, `pci`, `personal`, `email`, `phone`, `ssn`, `secret`), as `--pii-tag`/`--pii-term`. |
| `detail` | Free text shown as the source's detail. |

The importers are the ones `haltsql schema import` and `haltsql report --pii` use
(see [schema-and-pii.md](../schema-and-pii.md)). Columns are merged per
`schema.table.column` (lower-cased): tags and sources are the union.

**Live fetches are non-authoritative.** A catalog's view of table structure can lag
behind the database, so a live-fetched source is reported with `authoritative: false`
and only flags columns. The console never loads it as a policy catalog.

**Status of a tagged column.** `allowed_by` lists the loaded policies whose allowlist
lets a `SELECT` read the column (the table is listed and the column is listed, or the
table allows `"*"`). With no such policy the column is `blocked`. Otherwise it is
`exception` when every allowing policy is covered by an unexpired `data.exceptions`
entry for the column (an entry without `policy` covers every policy), and
`needs_review` otherwise, including when the matching exception has expired.
`shadow_denials` counts shadow-denied records that read the column (from the record, or
re-derived from raw SQL when it was logged).

| `data.exceptions[]` key | Meaning |
|---|---|
| `column` | `schema.table.column`. |
| `policy` | Optional: only this policy is covered. |
| `owner` | Required. Who approved it. |
| `ticket` | Optional reference. |
| `expires` | Optional date (`2027-02-01`, valid through that day UTC) or RFC 3339 time. An unparsable value counts as expired. |

## `integrations`

<!-- Documented by the PRs that use each integration. -->

### `integrations.github`

Used by `POST /api/v1/policies/{name}/pull-request` (and the PR state in
policy reports). Without it that endpoint returns `503 NOT_CONFIGURED`.

| Key | Default | Meaning |
|---|---|---|
| `repo` | required | `owner/name` of the policy repository. |
| `token` | required | Token with `contents: write` and `pull_requests: write` (and `checks: read`). Use a secret placeholder, e.g. `${env:GITHUB_TOKEN}`. Never returned or logged. |
| `base` | `main` | Branch PRs target. |
| `path` | `policies` | Directory of policy files in the repo. The file patched is `<path>/<basename of the loaded file>` (`<name>.yaml` for inline and bundle policies); when that is missing, the only file under `<path>` (any depth) with that basename, else the only one (of the first 25 policy documents) whose `metadata.name` is the policy's name. Several matches are `409`; no match is `409` unless the request sets `create_file: true` (the loaded source is then added at the default path). |
| `policy_paths` | none | Mapping of policy name to its file in the repo (for example `analytics: teams/data/analytics.yaml`), used instead of the lookup above. |
| `tests_path` | `tests` | Directory of test suites; tests are appended to `<tests_path>/<policy>.yaml` (created, pointing at the policy file, when absent). |
| `branch_prefix` | `haltsql-console/` | PR branch is `<branch_prefix><policy>`; an open PR for the policy (the one the console stored, else any open PR GitHub has for that branch) is updated instead of opening another. A leftover branch with no open PR is reset to `base` only when its head is a commit the console made; otherwise the request is `409`. |
| `required_approvals` | `1` | Shown next to the approvals in the PR state. |
| `api` | `https://api.github.com` | API base URL (GitHub Enterprise: `https://ghe.example.com/api/v3`). https, or http for loopback only. |

Reads (GETs) are retried up to three times on a network error, a 5xx, a 429
or a rate-limit 403, honouring `Retry-After` and `x-ratelimit-reset` (a wait
over 5 seconds is not taken: the call fails instead). Writes are never
retried. Reviews and check runs are read 100 per page, following `Link:
rel="next"` for up to 10 pages.

```yaml
integrations:
  github:
    repo: acme/haltsql-policies
    token: ${env:GITHUB_TOKEN}
    path: policies
    required_approvals: 2
```

### `integrations.slack`, `integrations.pagerduty`

```yaml
integrations:
  slack: { webhook: "${vault:secret/slack#webhook}" }
  pagerduty: { routing_key: "${vault:secret/pagerduty#key}" }
```

| Key | Meaning |
|---|---|
| `slack.webhook` | Slack incoming-webhook URL. |
| `pagerduty.routing_key` | PagerDuty Events API v2 integration (routing) key. |
| `pagerduty.events_url` | Default `https://events.pagerduty.com/v2/enqueue`; override for a proxy or EU endpoint. |

Each new **high** signal is posted once to every configured channel (PagerDuty:
`event_action: trigger`, `dedup_key` = the signal id, severity `critical`).
Delivery is best effort: failures are logged with the HTTP status only, never the
URL or key. URLs must be `https` (plain `http` only on a loopback host).

### `integrations.jira`

```yaml
integrations:
  jira: { url: https://acme.atlassian.net, project: SEC, email: haltsql-bot@acme.com, token: "${vault:secret/jira#token}" }
```

| Key | Meaning |
|---|---|
| `url` | Jira base URL. |
| `project` | Project key for new issues. |
| `token` | API token. With `email`, sent as Basic auth (Jira Cloud); without, as a Bearer token (Jira Data Center personal access token). |
| `email` | Optional; the account the API token belongs to. |
| `issue_type` | Default `Task`. |

Creating a case also creates a Jira issue and stores its key on the case
(`jira: { key, url }`). If Jira is unreachable the case is still created, with
`jira: null`.
