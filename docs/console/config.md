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

<!-- Documented by the records PR (console/02-records). -->

## `policies` and `opa`

<!-- Documented by the build PR (console/05-build). -->

## `signals`

<!-- Documented by the signals PR (console/04-signals). -->

## `agents`

<!-- Documented by the build PR (console/05-build). -->

## `catalogs` and `data`

<!-- Documented by the comply PR (console/06-comply). -->

## `integrations`

<!-- Documented by the PRs that use each integration. -->
