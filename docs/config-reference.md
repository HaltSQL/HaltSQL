# Config reference

A config controls how the CLI and `haltsql-server` run: where to listen, who
may call, which policies to load, audit logging, and metrics. It is a YAML
or JSON document with `kind: Config`, loaded with the same rules as a policy
(see [policy-reference.md](policy-reference.md#loading-rules)): unknown and
duplicate keys are errors, and errors are located by file, line, and key path.

A config does not change what SQL is allowed. That is the policy's job.

## Example

```yaml
apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:8080                 # pod-local; TLS is terminated in front (see below)
  auth:
    allow_unauthenticated: false
    tokens:
      - name: analytics-agent
        token_sha256: ${env:HALTSQL_ANALYTICS_TOKEN_HASH}
        policy: analytics-agent          # each token is pinned to one policy
      - name: support-bot
        token_sha256: ${file:/run/secrets/support-bot.sha256}
        policy: support-bot
policies:
  - path: ./policies/analytics-agent.yaml
  - path: ./policies/support-bot.json    # formats can be mixed
default_policy: null
reload:
  watch: true
audit:
  sinks:
    - type: file
      path: /var/log/haltsql/audit.jsonl
  log_raw_sql: false
telemetry:
  metrics:
    prometheus: true
logging:
  level: info
  format: json
limits:
  max_request_bytes: 1048576
```

Top-level keys: `apiVersion` (`haltsql.dev/v1`), `kind` (`Config`), `server`,
`policies`, `default_policy`, `reload`, `audit`, `telemetry`, `logging`,
`limits`. Any other key is an error.

## Keys

### server

| Key | Type | Default | Meaning |
|---|---|---|---|
| `server.listen` | string `host:port` | `127.0.0.1:8080` | Address the HTTP server binds to. |
| `server.tls.cert`, `server.tls.key` | path | none | Reserved. **`haltsql-server` 0.1.0 has no built-in TLS** and refuses to start if `server.tls` is set, so that nobody believes traffic is encrypted when it is not. Terminate TLS in front of the server (Envoy, nginx, or a service mesh such as Istio or Linkerd) and bind the server to `127.0.0.1` or a pod-local address. |
| `server.auth.tokens` | list | `[]` | Bearer tokens (see below). |
| `server.auth.allow_unauthenticated` | boolean | `false` | Accept requests without a token. For local development only. |

Each token entry:

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Label used in logs and audit events. Never the secret. Must be unique. |
| `token_sha256` | hex string | SHA-256 of the bearer token as 64 lower-case hex characters. The token itself is never stored. Must be unique. |
| `policy` | string | Name (`metadata.name`) of the one policy this token may use. |

A token can only use its pinned policy, so a compromised agent cannot pick a
looser one. Generate a token and its hash with, for example:

```sh
token="$(openssl rand -hex 32)"
printf '%s' "$token" | sha256sum | cut -d' ' -f1    # goes in token_sha256
```

### policies

A list of policies to load. Each entry is one of:

| Form | Meaning |
|---|---|
| `{ path: FILE }` | Load a policy file (YAML or JSON). Relative paths are resolved against the config file's directory. |
| `{ inline: { ...policy document... } }` | Embed a whole policy document, so a small deployment can be one file. |

Policy names (`metadata.name`) must be unique. Every token's `policy` must
name a loaded policy. If any policy fails to load, the whole config fails to
load (at startup) or the reload is rejected and the last good set stays active
(at runtime).

### default_policy

Name of the policy used for unauthenticated requests when
`allow_unauthenticated` is `true`, and for requests that name no policy.
Must name a loaded policy. Default: none.

### reload

| Key | Type | Default | Meaning |
|---|---|---|---|
| `reload.watch` | boolean | `false` | Watch the config and policy files (polled every 2 seconds) and reload on change. The server also reloads on `SIGHUP`. A reload is atomic: either all policies are swapped in, or none are. |

### audit

| Key | Type | Default | Meaning |
|---|---|---|---|
| `audit.sinks` | list | `[{type: stdout}]` | Where audit events go: `{type: stdout}` or `{type: file, path: FILE}` (relative paths are resolved against the config file's directory). If a sink cannot be written, the request is refused with HTTP 503 (fail closed). |
| `audit.log_raw_sql` | boolean | `false` | Include the raw SQL in audit events. Off by default because SQL can contain sensitive literals; events always include `sql_sha256` and the fingerprint. |

### telemetry

| Key | Type | Default | Meaning |
|---|---|---|---|
| `telemetry.metrics.prometheus` | boolean | `true` | Serve Prometheus metrics at `GET /metrics`. |
| `telemetry.otlp_endpoint` | string | none | Reserved for OpenTelemetry export; accepted but not used in 0.1.0. |

### logging

| Key | Type | Default | Meaning |
|---|---|---|---|
| `logging.level` | `debug`, `info`, `warn`, `error` | `info` | Minimum log level. |
| `logging.format` | `json`, `text` | `json` | Log line format. Logs go to stderr. |

### limits

| Key | Type | Default | Meaning |
|---|---|---|---|
| `limits.max_request_bytes` | integer (1024 to 67108864) | `1048576` | Largest accepted HTTP request body. Larger requests get HTTP 413. |

## Secrets: `${env:NAME}` and `${file:/path}`

Config values can load secrets without writing them into the file:

| Placeholder | Replaced by |
|---|---|
| `${env:NAME}` | The value of environment variable `NAME`. |
| `${file:/path}` | The contents of the file (at most 1 MiB), with one trailing newline (`\n` or `\r\n`) removed. Relative paths are resolved against the config file's directory. |
| `$${` | A literal `${`. |

Rules:

- A placeholder that cannot be resolved (unset variable, unreadable file) is a
  load error. HaltSQL never substitutes an empty string.
- Placeholders are allowed only in `Config` documents. They are rejected in
  policies, which may only use `${ctx.*}`.
- Resolved secrets are never printed. `haltsql config show` replaces them with
  `"<redacted>"`.

## Precedence

Runtime settings come from four places. Higher rows win:

| Priority | Source | Example |
|---|---|---|
| 1 (highest) | Command-line flags | `haltsql-server --listen 0.0.0.0:9000` |
| 2 | `HALTSQL_*` environment variables | `HALTSQL_LISTEN=0.0.0.0:9000` |
| 3 | Config file | `server.listen: 0.0.0.0:8443` |
| 4 (lowest) | Built-in defaults | `127.0.0.1:8080` |

Environment variables recognized in 0.1.0:

| Variable | Overrides |
|---|---|
| `HALTSQL_LISTEN` | `server.listen` |
| `HALTSQL_LOG_LEVEL` | `logging.level` |
| `HALTSQL_LOG_FORMAT` | `logging.format` |
| `HALTSQL_ALLOW_UNAUTHENTICATED` | `server.auth.allow_unauthenticated` (`true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`) |
| `HALTSQL_DEFAULT_POLICY` | `default_policy` |

An invalid value in one of these variables is a load error, not ignored.

Use `haltsql config show --config FILE` to print the effective, merged config
with secrets redacted. Run it after every change; it is the fastest way to see
what the server will actually do.

## Quick start without a config file

For local experiments, the server accepts a policy directly:

```sh
haltsql-server --policy policy.yaml --listen 127.0.0.1:8080 --allow-unauthenticated
```

`--policy` is repeatable and adds to (or, by name, replaces) the config's
policies. See [cli.md](cli.md#haltsql-server) for all server flags. Use a config file with tokens
for anything shared or deployed.
