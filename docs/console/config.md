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

<!-- Documented by the build PR (console/05-build). -->

## `signals`

<!-- Documented by the signals PR (console/04-signals). -->

## `agents`

<!-- Documented by the build PR (console/05-build). -->

## `catalogs` and `data`

<!-- Documented by the comply PR (console/06-comply). -->

## `integrations`

<!-- Documented by the PRs that use each integration. -->
