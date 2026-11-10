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

<!-- Documented by the signals PR (console/04-signals). -->

## `agents`

<!-- Documented by the build PR (console/05-build). -->

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
