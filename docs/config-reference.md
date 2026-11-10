# Config reference

A config controls how the CLI and `haltsql-server` run: where to listen, TLS,
who may call (static tokens, OIDC, mTLS), which policies to load (files,
inline, signed bundles, or signed bundles pulled from a registry, S3 or HTTPS),
audit logging (stdout, files, S3, GCS, Elasticsearch/OpenSearch, Kafka), an
optional Open Policy Agent check, the admin API, metrics and OpenTelemetry, and
where secrets come from. It is a YAML
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
`limits`, `secrets`, `opa`. Any other key is an error.

A larger example using the enterprise features:

```yaml
apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 0.0.0.0:8443
  tls:
    cert: /etc/haltsql/tls/server.crt
    key: /etc/haltsql/tls/server.key
    client_ca: /etc/haltsql/tls/clients-ca.pem
    client_auth: optional            # mTLS identities below, OIDC for everyone else
    min_version: "1.3"
  auth:
    oidc:
      - name: corp-okta
        issuer: https://corp.okta.com/oauth2/default
        audiences: [haltsql]
        policy_claim: haltsql_policy
        allowed_policies: [saas-analytics, support-bot]
        context_claims:
          tenant_id: https://corp.example/tenant
          user_id: sub
        required_claims:
          scope: sql.verify
    mtls:
      identities:
        - spiffe_id: spiffe://corp.example/ns/agents/sa/analytics
          policy: saas-analytics
          context: { tenant_id: acme }
policies:
  - path: ./policies/support-bot.yaml
  - bundle: ./bundles/prod.haltsqlbundle
    public_keys: [./keys/release.pub]
audit:
  sinks:
    - type: s3
      bucket: corp-haltsql-audit
      region: eu-west-1
      object_lock: { mode: COMPLIANCE, retain_days: 365 }
      credentials: { source: web_identity }
telemetry:
  otlp:
    endpoint: http://otel-collector:4318
    headers:
      authorization: "Bearer ${vault:secret/data/haltsql/otel#token}"
secrets:
  vault:
    address: https://vault.corp.example:8200
    auth: { method: kubernetes, role: haltsql }
```

## Keys

### server

| Key | Type | Default | Meaning |
|---|---|---|---|
| `server.listen` | string `host:port` | `127.0.0.1:8080` | Address the HTTP server binds to. |
| `server.tls` | mapping | none | Built-in TLS (see [server.tls](#servertls)). Without it, terminate TLS in front of the server (Envoy, nginx, or a service mesh) and bind to `127.0.0.1` or a pod-local address. See [authentication.md](authentication.md). |
| `server.auth.tokens` | list | `[]` | Bearer tokens (see below). |
| `server.auth.oidc` | list | `[]` | OpenID Connect providers whose JWTs are accepted (see [server.auth.oidc](#serverauthoidc)). |
| `server.auth.mtls` | mapping | none | Client-certificate identities (see [server.auth.mtls](#serverauthmtls)). |
| `server.auth.allow_unauthenticated` | boolean | `false` | Accept requests without a token. For local development only. |
| `server.admin` | mapping | disabled | Admin API (see [server.admin](#serveradmin)). |

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

### server.tls

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cert` | path or PEM | none | Server certificate chain. Required together with `key`. |
| `key` | path or PEM | none | Private key. Required together with `cert`. Always shown as `<redacted>` by `config show`. |
| `client_ca` | path or PEM | none | CA bundle used to verify client certificates (enables mTLS). |
| `client_auth` | `none`, `optional`, `required` | `none` | Whether client certificates are requested. `optional` and `required` need `client_ca`. |
| `min_version` | `"1.2"`, `"1.3"` | `"1.2"` | Minimum TLS version. |

Relative paths are resolved against the config file's directory. A value
that starts with `-----BEGIN` (for example from `${file:...}` or a secret
provider) is used as inline PEM. Setting `client_ca`, `client_auth` or
`min_version` without `cert` and `key` is an error.

### server.auth.oidc

Each entry describes one OpenID Connect provider. A request whose bearer
token is a JWT signed by the provider is authenticated by it.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | Unique provider name, used in logs and audit events. |
| `issuer` | URL | required | Must equal the token's `iss`. `https` only (no credentials, query or fragment); `http` only with `allow_insecure_http: true`. |
| `audiences` | list | required | Non-empty; the token's `aud` must contain one of them. |
| `jwks_uri` | URL | discovered | Default: `jwks_uri` from `<issuer>/.well-known/openid-configuration`. |
| `algorithms` | list | `[RS256, ES256]` | Subset of `RS256 RS384 RS512 PS256 ES256 ES384 EdDSA`. `none` and `HS*` are rejected. |
| `leeway_seconds` | integer 0-300 | `60` | Clock skew allowed for `exp`, `nbf`, `iat`. |
| `jwks_cache_seconds` | integer 10-86400 | `300` | How long fetched keys are cached. |
| `policy` | string | none | Pin every token from this provider to one policy. |
| `policy_claim` | claim path | none | Instead of `policy`: the claim whose value names the policy. Needs `allowed_policies`. |
| `allowed_policies` | list | none | The only policies `policy_claim` may select (non-empty). |
| `policy_from_groups` | mapping | none | Instead of `policy` / `policy_claim`: pick the policy from the token's groups (see [policy_from_groups](#policy_from_groups)). |
| `context_claims` | map | `{}` | Context field -> claim path. The path is first tried as one claim name (so `https://corp.example/tenant` works), then as a dot path (`org.id`). |
| `required_claims` | map | `{}` | Claim -> string or list. A string must equal the claim, or be contained in it when the claim is an array or a space-separated string such as `scope`. A list requires every value. |
| `request_context_fields` | list | `[]` | Context fields the request body may still supply. They must not also appear in `context_claims`. |
| `allow_insecure_http` | boolean | `false` | Allow `http` issuer and JWKS URLs. For tests only. |

Exactly one of `policy`, `policy_claim` or `policy_from_groups` is required.
Every referenced policy must be loaded (see [policies](#policies) for bundles).

#### policy_from_groups

Maps IdP groups (or roles) to policies, so one provider can serve several
kinds of caller without a custom claim:

```yaml
server:
  auth:
    oidc:
      - name: corp-keycloak
        issuer: https://sso.corp.example/realms/corp
        audiences: [haltsql]
        policy_from_groups:
          claim: groups                    # default; dotted paths like realm_access.roles work
          map:                             # ordered: the first entry the token matches wins
            - { group: data-platform-admins, policy: admin-readonly }
            - { group: analysts, policy: saas-analytics }
            - { group: support, policy: support-bot }
          default: null                    # no match: the token is rejected (401)
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `claim` | claim path | `groups` | Claim holding the groups. Looked up like `context_claims` paths: first as one claim name, then as a dot path (`realm_access.roles`). |
| `map` | list | required | Non-empty, ordered list of `{group, policy}`. Groups are compared exactly (case-sensitive) and must be unique. |
| `default` | string | none | Policy for a token that matches no entry. Without it such a token is rejected. |

The claim may be a string (one group; it is never split on spaces) or an
array of strings. A missing claim, or a claim of any other shape (a number,
an object, an array containing a non-string), rejects the token. The map is
walked in order and the first entry whose `group` the token has wins, so
put the most privileged or most specific groups first.

`policy_from_groups` cannot be combined with `policy`, `policy_claim` or
`allowed_policies`. Every policy in `map` and `default` must resolve, with
the same rule as other references (bundles with `name_prefix`, see
[policies](#policies)).

### server.auth.mtls

```yaml
server:
  auth:
    mtls:
      identities:
        - spiffe_id: spiffe://corp.example/ns/agents/sa/analytics   # exact URI SAN
          policy: saas-analytics
          context: { tenant_id: acme, region: [eu-1, eu-2] }
          request_context_fields: [user_id]
        - subject_cn: support-bot                                  # exact subject CN
          policy: support-bot
```

Each identity has exactly one of `spiffe_id` (a valid `spiffe://` URI with a
lower-case trust domain) or `subject_cn`, a `policy`, an optional static
`context` (strings, integers or non-empty lists of those) and
`request_context_fields` (default `[]`, must not repeat a static context
field). Identities must be unique. Non-empty `identities` require
`server.tls.client_ca` and `server.tls.client_auth` set to `optional` or
`required`.

### policies

A list of policies to load. Each entry is one of:

| Form | Meaning |
|---|---|
| `{ path: FILE }` | Load a policy file (YAML or JSON). Relative paths are resolved against the config file's directory. |
| `{ inline: { ...policy document... } }` | Embed a whole policy document, so a small deployment can be one file. |
| `{ bundle: FILE, public_keys: [...], name_prefix: STR }` | A signed `.haltsqlbundle`. `public_keys` (non-empty) lists trusted ed25519 keys, each a file path, inline PEM (`-----BEGIN PUBLIC KEY-----`) or the base64 of the 32 raw key bytes. `name_prefix` (optional) is prepended to the names of the bundle's policies. |
| `{ bundle_source: {...}, public_keys: [...], ... }` | A signed bundle fetched from an OCI registry, S3 (or an S3-compatible store) or HTTPS, and polled for updates. See [bundle_source](#bundle_source). |

Policy names (`metadata.name`) must be unique. Every token's `policy` must
name a loaded policy.

#### bundle_source

```yaml
policies:
  - bundle_source:
      oci: ghcr.io/corp/haltsql-policies:prod      # or registry/repo@sha256:<digest>
    public_keys: [./keys/release.pub]               # mandatory
    name_prefix: prod.
    poll_interval_s: 60
    cache_dir: /var/cache/haltsql/bundles
    auth: { username: robot$haltsql, password: "${vault:secret/data/haltsql/registry#password}" }
  - bundle_source:
      s3:
        bucket: corp-haltsql-bundles
        key: prod/policies.haltsqlbundle
        region: us-east-1
        endpoint: http://127.0.0.1:9000             # S3-compatible store such as MinIO
        credentials: { source: static, access_key_id: "${env:BUNDLE_AK}", secret_access_key: "${env:BUNDLE_SK}" }
    public_keys: [./keys/release.pub]
  - bundle_source:
      https: https://bundles.corp.example/prod.haltsqlbundle
    public_keys: [./keys/release.pub]
    auth: { token: "${env:BUNDLE_TOKEN}" }
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bundle_source` | mapping | required | Exactly one of `oci`, `s3` or `https` (below). |
| `public_keys` | list | required | Trusted ed25519 keys, as for `bundle`. Signature verification is mandatory: a source without keys is a config error. |
| `name_prefix` | string | none | Prepended to the names of the bundle's policies (1-64 of letters, digits, `.`, `_`, `-`, starting with a letter or digit). |
| `poll_interval_s` | integer 10-86400 | `60` | Seconds between update checks. |
| `cache_dir` | path | none | Directory holding the last verified bundle (relative to the config file). |
| `auth` | mapping | none | `oci` and `https` only: `{token}` (bearer token) or `{username, password}`. Not allowed for `s3`, which uses `s3.credentials`. |

`bundle_source` forms:

| Form | Meaning |
|---|---|
| `oci: REF` | An OCI artifact. `REF` is `registry[:port]/repository:tag`, `registry[:port]/repository@sha256:<64 hex>` (or `sha512:<128 hex>`), or both (`:tag@digest`). The registry host is mandatory (there is no implicit Docker Hub): it must contain a `.` or a `:` or be `localhost`. Repository components are lower-case letters, digits, `.`, `_` and `-`. Pin a digest for immutable deployments. |
| `plain_http: true` | With `oci` only: talk plain HTTP to the registry. Allowed only for loopback registries (`localhost`, `127.x`, `[::1]`), for local tests. Default `false`. |
| `s3: {bucket, key, region, endpoint, credentials}` | An S3 object. `bucket`, `key` and `region` are required; `key` must not start with `/`. `endpoint` is an S3-compatible URL (MinIO). `credentials` has the same shape as for [S3 audit sinks](#audit) (`env` by default). |
| `https: URL` | An `https` URL (plain `http` only for loopback addresses). No credentials, query or fragment in the URL; use `auth`. |

Two entries with the same source are an error. `poll_interval_s`,
`cache_dir` and `auth` are only allowed with `bundle_source`; `public_keys`
and `name_prefix` only with `bundle` or `bundle_source`.

Bundles and bundle sources are parsed and checked when the config loads, but
they are fetched, verified and loaded by the server afterwards. So when a
config lists bundles (of either form), a policy
name used by a token, OIDC provider (including `policy_from_groups` map entries
and `default`), mTLS identity or `default_policy` that is
not one of the plain policies is accepted at config load time. If every bundle
and bundle source has a `name_prefix`, such a name must start with one of them. The server
re-validates every reference after loading the bundles and refuses to start
(or rejects the reload) if one is still missing. If any policy fails to load, the whole config fails to
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

What a reload (file change, `SIGHUP`, or a new bundle from a bundle source)
applies, and what needs a restart:

| Applied on reload | Restart only |
|---|---|
| `policies` (paths, inline policies, local `bundle` files and their signatures) and `default_policy` | `server.listen`, the health listener |
| `server.auth.tokens`, `allow_unauthenticated` | enabling or disabling `server.tls` (certificates and keys themselves reload) |
| `server.auth.oidc` (including `policy_from_groups`; key caches of unchanged providers are kept) and `server.auth.mtls` | `audit` (all sinks, `log_raw_sql`): two writers on one chain would fork it. A reload that changes `audit.sinks` keeps the running sinks, logs a warning and sets `audit_restart_pending` in `GET /v1/admin/status` |
| `server.tls` certificate, key and client CA files | the list of `bundle_source` entries: adding, removing or changing an entry needs a restart (the running pollers keep their settings; new bundles they fetch are applied as reloads) |
| `opa` (url, decision path, timeout, `on_error`, headers) | `limits`, `logging`, `telemetry.metrics.prometheus` |
| `server.admin` (enabling, callers, `report_window`, `max_tracked_queries`; disabling it drops the report window) | |
| `telemetry.otlp` | |

A reload that fails (any load, validation, reference or TLS error) changes
nothing: the last good configuration stays active and the failure is logged
and counted in `haltsql_policy_reload_total{result="error"}`.

### audit

| Key | Type | Default | Meaning |
|---|---|---|---|
| `audit.sinks` | list | `[{type: stdout}]` | Where audit events go: `stdout`, `file`, `s3`, `gcs`, `elasticsearch` or `kafka` (below). |
| `audit.log_raw_sql` | boolean | `false` | Include the raw SQL in audit events. Off by default because SQL can contain sensitive literals; events always include `sql_sha256` and the fingerprint. |

Every sink accepts `on_error`: `fail_closed` (default; if the sink cannot be
written, requests are refused with HTTP 503) or `buffer` (records are kept in
memory and retried).

| Sink | Keys |
|---|---|
| `stdout` | `type`, `on_error` |
| `file` | `type`, `path` (relative to the config file), `on_error` |
| `s3` | `type`, `bucket`, `region` (required); `prefix` (default `haltsql/audit/`), `endpoint` (S3-compatible URL, e.g. MinIO), `object_lock: {mode: GOVERNANCE\|COMPLIANCE, retain_days: 1-36500}`, `batch`, `credentials`, `spool_dir`, `on_error` |
| `gcs` | `type`, `bucket` (required); `prefix` (default `haltsql/audit/`), `batch`, `credentials`, `spool_dir`, `on_error` |

`batch`: `max_records` (1-100000, default 500) and `max_seconds` (1-3600,
default 10).

`spool_dir` (s3/gcs, optional, relative to the config file; one directory per
sink, on persistent storage): records are spooled there before upload, and
the hash-chain head and object sequence number are persisted, so after a
restart or crash the chain continues instead of starting again at genesis,
and a batch uploaded just before a crash is not stored twice. Without it,
each process starts a new chain (see
[Audit sinks](audit-sinks.md#restarts-and-chain-continuity)).

S3 `credentials.source`: `env` (default; the standard `AWS_*` variables),
`static` (needs `access_key_id` and `secret_access_key`, optional
`session_token`; use secret placeholders and never write keys in the file),
`web_identity` (IRSA / OIDC federation) or `instance` (instance profile).
The static keys are only allowed with `source: static`.

GCS `credentials.source`: `metadata` (default) or `service_account_file`
(needs `file`, relative to the config file).

Bucket names are validated (3-63 characters; S3: lower-case letters, digits,
`.` and `-`; GCS also `_`). A `prefix` must not start with `/` or contain `..`.

#### Streaming sinks: elasticsearch and kafka

The `elasticsearch` and `kafka` sinks stream records as they are written
instead of uploading objects. They accept a third `on_error` value and their
own `batch` shape:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `on_error` | `fail_closed`, `buffer`, `drop` | `fail_closed` | `fail_closed` refuses requests (HTTP 503) when records cannot be delivered. `buffer` keeps up to `max_buffer_records` in memory and retries; when the buffer is full the sink fails closed. `drop` discards records that cannot be delivered (they are counted and logged); requests keep being served without an audit trail in this sink, so use it only next to another fail-closed sink. |
| `max_buffer_records` | integer 1-1000000 | `10000` (or `batch.max_records` if larger) | Only with `on_error: buffer`. Must be at least `batch.max_records`. |
| `batch.max_records` | integer 1-100000 | `500` | Records per request at most. |
| `batch.max_bytes` | integer 1024-104857600 | `5242880` (5 MiB) | Request body size at most. |
| `batch.flush_interval_ms` | integer 10-60000 | `1000` | Milliseconds before a partial batch is sent. |

`elasticsearch` (Elasticsearch or OpenSearch, bulk API):

```yaml
audit:
  sinks:
    - type: elasticsearch
      urls: [https://es-1.corp.example:9200, https://es-2.corp.example:9200]
      data_stream: logs-haltsql-prod       # or index: haltsql-audit
      auth: { api_key: "${vault:secret/data/haltsql/es#api_key}" }
      pipeline: haltsql-enrich
      tls: { ca_file: ./certs/es-ca.pem }
      timeout_ms: 10000
      batch: { max_records: 500, max_bytes: 5242880, flush_interval_ms: 1000 }
      on_error: buffer
      max_buffer_records: 20000
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` / `urls` | URL / list | required | Exactly one of them. Node URLs: `https`, or plain `http` only for loopback addresses. No credentials, query or fragment (a path prefix is allowed). `urls` must be non-empty and unique. |
| `index` / `data_stream` | string | required | Exactly one of them. Lower-case letters, digits, `.`, `-`, `_`, `+`; at most 255 characters; not starting with `-`, `_` or `+`; not `.` or `..`. |
| `auth` | mapping | none | `{api_key}` (the encoded key, sent as `Authorization: ApiKey <value>`) or `{username, password}` (basic auth; the user name must not contain `:`). Use secret placeholders. |
| `pipeline` | string | none | Ingest pipeline run on every record (letters, digits, `.`, `_`, `-`). |
| `tls.ca_file` | path or PEM | system roots | CA bundle for the cluster certificate. Only allowed when a URL is `https`. |
| `timeout_ms` | integer 100-120000 | `10000` | Request timeout. |

`kafka` (one message per audit record):

```yaml
audit:
  sinks:
    - type: kafka
      brokers: [kafka-1.corp.example:9093, kafka-2.corp.example:9093]
      topic: haltsql.audit
      client_id: haltsql-prod
      acks: all
      tls: { ca_file: /etc/haltsql/kafka/ca.pem }
      sasl: { mechanism: scram-sha-512, username: haltsql, password: "${env:KAFKA_PASSWORD}" }
      on_error: fail_closed
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `brokers` | list | required | Non-empty, unique `host:port` bootstrap brokers (DNS name, IPv4, or `[IPv6]`). |
| `topic` | string | required | 1-249 of letters, digits, `.`, `_`, `-`; not `.` or `..`. |
| `client_id` | string | `haltsql` | Kafka client id (1-255 of letters, digits, `.`, `_`, `-`). |
| `acks` | `all`, `1` | `all` | Acknowledgements required per batch. `0` (fire and forget) is rejected: audit records must be acknowledged. |
| `tls` | mapping | none (plain text) | `enabled` (default `true` when `tls` is given), `ca_file`, and a client certificate as `cert_file` + `key_file` (both or neither). The other keys are only allowed when `enabled` is `true`. Values are paths (relative to the config file) or inline PEM. |
| `sasl` | mapping | none | `mechanism` (`plain`, `scram-sha-256`, `scram-sha-512`), `username` and `password` (all required). `plain` without `tls` is rejected unless every broker is a loopback address, because it sends the password in clear text. |

The streaming sinks sit in the same `audit.sinks` list as the others and can
be mixed with them; listing only streaming sinks means no stdout sink.

### opa

An optional [Open Policy Agent](https://www.openpolicyagent.org/) check that
runs after HaltSQL has allowed a query:

```yaml
opa:
  url: https://opa.corp.example:8181
  decision_path: haltsql/allow
  timeout_ms: 500
  on_error: deny
  headers:
    Authorization: "Bearer ${vault:secret/data/haltsql/opa#token}"
  tls: { ca_file: ./certs/opa-ca.pem }
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | URL | required | OPA base URL. `https`, or plain `http` only for loopback addresses (an OPA sidecar on `127.0.0.1`). No credentials, query or fragment. |
| `decision_path` | string | required | The decision below `/v1/data`, as Rego identifiers separated by `/`, without a leading `/`: `haltsql/allow` queries `POST <url>/v1/data/haltsql/allow`. |
| `timeout_ms` | integer 10-5000 | `500` | Decision request timeout. |
| `on_error` | `deny`, `allow_haltsql_verdict` | `deny` | What happens when OPA cannot be reached, times out, or answers with an error or an undefined/non-boolean decision. `deny` refuses the query; `allow_haltsql_verdict` keeps HaltSQL's verdict. |
| `headers` | map | `{}` | Extra HTTP headers (for example a bearer token). Values may use secret placeholders, must not contain CR/LF, and are redacted by `config show`. |
| `tls.ca_file` | path or PEM | system roots | CA bundle for the OPA certificate. Only allowed with an `https` url. |

Semantics: OPA can only further deny. A query HaltSQL denies is denied
without asking OPA, and OPA's answer can never turn a HaltSQL denial into an
allow. A query HaltSQL allows is allowed only if OPA's decision is `true`
(or, with `on_error: allow_haltsql_verdict`, if OPA could not give a
decision). An OPA denial is reported with its own reason code so it can be
told apart from HaltSQL's own reasons.

### server.admin

The admin API serves `GET /v1/admin/report` (shadow-mode analytics: which
queries would have been denied, by reason and policy, over the report window)
and `GET /v1/admin/status`. It is off by default.

```yaml
server:
  admin:
    enabled: true
    callers:
      - token:ops-dashboard                              # a server.auth.tokens name
      - oidc:corp-okta                                   # any token verified by this provider
      - mtls:spiffe://corp.example/ns/ops/sa/console     # a configured mTLS spiffe_id
      - mtls:ops-console                                 # a configured mTLS subject_cn
    report_window: 24h
    max_tracked_queries: 10000
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `false` | Serve the admin endpoints. |
| `callers` | list | `[]` | Who may call them. Required and non-empty when `enabled` is `true`. Each entry is `token:<name>`, `oidc:<provider>` or `mtls:<spiffe-id or subject CN>` and must name a configured token, OIDC provider or mTLS identity. Unauthenticated callers can never use the admin API. |
| `report_window` | duration | `24h` | How far back the report looks: a whole number followed by `s`, `m`, `h` or `d`, between `1m` and `30d`. |
| `max_tracked_queries` | integer 1-1000000 | `10000` | Distinct query fingerprints tracked for the report; the least recently seen are evicted first. |

### telemetry

| Key | Type | Default | Meaning |
|---|---|---|---|
| `telemetry.metrics.prometheus` | boolean | `true` | Serve Prometheus metrics at `GET /metrics`. |
| `telemetry.otlp` | mapping | none | OpenTelemetry (OTLP/HTTP) export, below. |
| `telemetry.otlp_endpoint` | URL | none | Legacy shorthand for `telemetry.otlp.endpoint` with all other defaults. Cannot be combined with `telemetry.otlp`. Must be an `http(s)` URL. |

`telemetry.otlp`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | URL | required | Collector base URL, e.g. `http://collector:4318`. |
| `headers` | map | `{}` | Extra HTTP headers. Values may use secret placeholders, must not contain CR/LF, and are redacted by `config show`. |
| `service_name` | string | `haltsql` | `service.name` resource attribute. |
| `traces` | boolean | `true` | Export traces. |
| `metrics` | boolean | `true` | Export metrics. |
| `export_interval_seconds` | integer 1-3600 | `15` | Metric export interval. |
| `timeout_seconds` | integer 1-300 | `5` | Export request timeout. |

### logging

| Key | Type | Default | Meaning |
|---|---|---|---|
| `logging.level` | `debug`, `info`, `warn`, `error` | `info` | Minimum log level. |
| `logging.format` | `json`, `text` | `json` | Log line format. Logs go to stderr. |

### limits

| Key | Type | Default | Meaning |
|---|---|---|---|
| `limits.max_request_bytes` | integer (1024 to 67108864) | `1048576` | Largest accepted HTTP request body. Larger requests get HTTP 413. |

### secrets

Configures the secret providers used by the `${vault:...}`, `${aws-sm:...}`
and `${gcp-sm:...}` placeholders. Values in this section may only use
`${env:...}` and `${file:...}` (a provider cannot configure itself).

| Key | Meaning |
|---|---|
| `secrets.vault.address` | Vault URL. `https`, or `http` for loopback addresses only. |
| `secrets.vault.namespace` | Vault Enterprise namespace (optional). |
| `secrets.vault.auth.method` | `token` (needs `token`), `kubernetes` (needs `role`; `jwt_path` defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`, `mount` to `kubernetes`) or `approle` (needs `role_id` and `secret_id`; `mount` defaults to `approle`). Fields of other methods are errors. |
| `secrets.vault.ca_file` | CA bundle for the Vault server certificate (optional). |
| `secrets.aws.region`, `secrets.aws.endpoint` | AWS Secrets Manager region (required) and optional endpoint (tests). |
| `secrets.gcp.project`, `secrets.gcp.endpoint` | Default project for short secret names, and optional endpoint (tests). |

Vault tokens, AppRole role and secret ids are redacted by `config show`.

`config show` also redacts: Elasticsearch API keys and passwords, the Kafka
SASL password and TLS client key, bundle source passwords and tokens, static
S3 credentials (sinks and bundle sources), OPA and OTLP header values, the
server TLS key and token hashes. Inline PEM values are shown as
`<inline PEM>`.

## Secrets: placeholders

Config values can load secrets without writing them into the file:

| Placeholder | Replaced by |
|---|---|
| `${env:NAME}` | The value of environment variable `NAME`. |
| `${file:/path}` | The contents of the file (at most 1 MiB), with one trailing newline (`\n` or `\r\n`) removed. Relative paths are resolved against the config file's directory. |
| `${vault:<path>#<field>}` | Field `<field>` of the Vault secret at `<path>` (e.g. `secret/data/haltsql/otel#token`). |
| `${aws-sm:<secret-id>[#<json-key>]}` | An AWS Secrets Manager secret, or one key of its JSON value. |
| `${gcp-sm:<name>[#<json-key>]}` | A Google Secret Manager secret (`projects/P/secrets/S/versions/V` or a short name in `secrets.gcp.project`), or one key of its JSON value. |
| `$${` | A literal `${`. |

The provider placeholders are resolved by the program loading the config
(the server and CLI build a resolver from the `secrets` section first, then
load the rest). A provider placeholder in a program or context with no
resolver is a load error ("secret provider not configured"). Each distinct
reference is fetched once per load.

Rules:

- A placeholder that cannot be resolved (unset variable, unreadable file,
  missing secret) is a load error. HaltSQL never substitutes an empty string.
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

Environment variables recognized in 0.0.1:

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
