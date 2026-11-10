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

The console loads the same policies as the verifiers, for the Playground, policy
detail, shadow reports and suggestions. Loading runs at startup and every 60
seconds; a load that fails anywhere keeps the last good set (like the server's
hot reload), and the errors are shown in `GET /api/v1/policies` (`errors`, file
basenames only).

| Key | Meaning |
|---|---|
| `policies.server_config` | A haltsql-server config file, loaded with the server's loader (secret placeholders resolved through its own `secrets:` section). Supported: `policies[].path`, `policies[].inline`, and local signed bundles (`policies[].bundle` with `public_keys` and `name_prefix`; the signature is verified). **Not** fetched: remote `bundle_source` entries; their policies appear only through fleet status (`loaded: false`). |
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

<!-- Documented by the signals PR (console/04-signals). -->

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

<!-- Documented by the comply PR (console/06-comply). -->

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
| `path` | `policies` | Directory of policy files in the repo. The file patched is `<path>/<basename of the loaded file>` (`<name>.yaml` for inline and bundle policies); when it is missing from the repo, the loaded source is used. |
| `tests_path` | `tests` | Directory of test suites; tests are appended to `<tests_path>/<policy>.yaml` (created, pointing at the policy file, when absent). |
| `branch_prefix` | `haltsql-console/` | PR branch is `<branch_prefix><policy>`; an open PR for the policy is updated instead of opening another. |
| `required_approvals` | `1` | Shown next to the approvals in the PR state. |
| `api` | `https://api.github.com` | API base URL (GitHub Enterprise: `https://ghe.example.com/api/v3`). https, or http for loopback only. |

```yaml
integrations:
  github:
    repo: acme/haltsql-policies
    token: ${env:GITHUB_TOKEN}
    path: policies
    required_approvals: 2
```
