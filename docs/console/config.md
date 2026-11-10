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

## Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8090` | `host:port` to serve on. `--listen` overrides. |
| `environment.org`, `.name`, `.region` | `HaltSQL`, `Default`, none | Shown in the environment switcher. |
| `state_dir` | `./console-state` | Durable state (cases, activity log, signal workflow, evidence packs). Must be writable; `/readyz` is 503 otherwise. Put it on a persistent volume. |
| `frontend_dir` | none | Directory with the built web frontend, served at `/`. |

## `auth`

At least one of `oidc`, `proxy`, `tokens`, `dev`.

| Key | Meaning |
|---|---|
| `oidc[]` | `name`, `issuer`, `audience` (or `audiences`), optional `jwks_uri`, `groups_claim` (default `groups`), `group_prefix` (default `<name>:`), `leeway_seconds`, `allow_insecure_http` (tests only). Tokens are verified like the server verifies callers (JWKS, `iss`, `aud`, expiry; RS256, ES256, PS256, EdDSA). |
| `proxy` | `user_header`, optional `name_header`, `groups_header` (comma-separated), `label`. Trusts headers set by an identity-aware proxy. **Only** enable when the console is reachable solely through that proxy. |
| `tokens[]` | `name`, `sha256` (hex SHA-256 of the token), `role`. For automation. |
| `dev` | `true` (admin), or `{ user, role }`. Every request is that user. Development only; `--dev ROLE` does the same. |
| `roles` | `{ admin: [groups], owner: [...], analyst: [...], audit: [...], dev: [...] }`. A user in several groups gets the most privileged role; a user in none is refused. |
| `session_hours` | Shown under Safeguards; enforce it at the identity provider. Default 8. |

## `verifiers[]`

| Key | Meaning |
|---|---|
| `name` | Unique; matches the `verifier` of audit sources. |
| `url` | Base URL of the verifier's HTTP API. |
| `kind` | `server` (default), `proxy`, `mcp`. |
| `location` | Free text shown in Fleet. |
| `token` | Admin bearer token; the verifier must list it in `server.admin.callers`. |
| `metrics_url` | Default `<url>/metrics`. |
| `workload` | Kubernetes workload to restart, e.g. `deployment/haltsql-1`. |

## `fleet`

<!-- Documented by the fleet PR (console/03-fleet). -->

## `audit`

<!-- Documented by the records PR (console/02-records). -->

## `policies` and `opa`

<!-- Documented by the build PR (console/05-build). -->

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

<!-- Documented by the build PR (console/05-build). -->

## `catalogs` and `data`

<!-- Documented by the comply PR (console/06-comply). -->

## `integrations`

<!-- Documented by the PRs that use each integration. -->

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
