# haltsql-proxy

`haltsql-proxy` is a PostgreSQL wire-protocol (v3) firewall. Clients (an LLM
agent, a BI tool, any libpq/JDBC/psycopg/pgx driver) connect to the proxy as if
it were Postgres. The proxy authenticates them, connects to the real database
with its own service credentials, and runs **every statement** through
`Haltsql.verify` under the policy and context bound to the client's identity
before forwarding it. Denied statements never reach the database.

The library and the HTTP sidecar ask "is this SQL allowed?" and trust the
caller to act on the answer. The proxy enforces the answer itself: a client
cannot skip verification, choose a looser policy, or pick its tenant.

```
 agent / driver ──TLS──▶ haltsql-proxy ──TLS──▶ PostgreSQL
                         │ auth: SCRAM or client cert -> (policy, context)
                         │ every Query/Parse: Haltsql.verify
                         │ every Bind: tenancy params overwritten
```

## Quick start

```bash
# 1. A verifier for each proxy user (the password never appears in the config)
printf '%s\n' "$AGENT_PASSWORD" | haltsql-proxy scram-verifier
# SCRAM-SHA-256$4096:...$...:...

# 2. A config (see below), then validate and run it
haltsql-proxy validate --config proxy.yaml
UPSTREAM_PASSWORD=... haltsql-proxy run --config proxy.yaml

# 3. Connect with any driver
psql "host=127.0.0.1 port=6432 dbname=app user=analytics-agent sslmode=require"
```

## Example config

```yaml
apiVersion: haltsql.dev/v1
kind: ProxyConfig
listen: 0.0.0.0:6432
tls:                                   # client side TLS (optional)
  cert: /etc/haltsql/tls.crt
  key: ${file:/run/secrets/tls.key}
  client_ca: /etc/haltsql/clients-ca.pem
  client_auth: optional                # none | optional | require
  required: true                       # refuse plaintext clients (default true)
upstream:
  host: db.internal
  port: 5432
  database: app
  user: haltsql_service                # a read-only role is strongly recommended
  password: ${env:UPSTREAM_PASSWORD}
  tls: { mode: verify-full, ca: /etc/haltsql/db-ca.pem }
policies:
  - path: ./policies/analytics-agent.yaml
auth:
  method: scram
  users:
    - name: analytics-agent
      scram_verifier: "SCRAM-SHA-256$4096:...$...:..."
      policy: analytics-agent          # metadata.name of a loaded policy
      context: { tenant_id: acme }
limits:
  max_connections: 200
  max_message_bytes: 1048576
  idle_timeout_seconds: 300
deny_sqlstate: "42501"
audit: { type: file, path: /var/log/haltsql/proxy-audit.jsonl }
logging: { level: info }
```

## Config reference

`kind: ProxyConfig`, `apiVersion: haltsql.dev/v1`. Loaded with the same rules
as every HaltSQL document (YAML 1.2 core schema or JSON, duplicate keys and
unknown keys are errors). Strings may use `${env:NAME}` and `${file:/path}`
(relative paths resolve against the config's directory; one trailing newline
is trimmed; `$${` is a literal `${`). Placeholders are not allowed inside inline
policies.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:6432` | `host:port` to accept clients on. `--listen` overrides it. |
| `tls.cert`, `tls.key` | none | PEM server certificate chain and key. Enables `SSLRequest` upgrades. |
| `tls.client_ca` | none | PEM CA bundle for client certificates. Required when `client_auth` is not `none`. |
| `tls.client_auth` | `none` | `none`, `optional` (verify if presented) or `require`. |
| `tls.required` | `true` | Refuse clients that do not upgrade to TLS (FATAL 28000). |
| `upstream.host`, `upstream.port` | -, `5432` | The real server. Every resolved address is tried in order. |
| `upstream.database`, `upstream.user` | required | Service credentials. Clients must ask for exactly this database name. |
| `upstream.password` | none | For SCRAM-SHA-256, MD5 or cleartext (cleartext only over TLS). Omit for `trust`. |
| `upstream.tls.mode` | `disable` | `disable`, `require` (encrypt, no verification) or `verify-full` (chain + host name). |
| `upstream.tls.ca` | none | PEM CA bundle; required for `verify-full`. |
| `upstream.connect_timeout_seconds` | `10` | TCP connect timeout (authentication gets three times this). |
| `policies` | required | List of `{path: file}` or `{inline: {...policy...}}`. Each is referenced by its `metadata.name`. |
| `auth.method` | required | `scram` or `cert`. |
| `auth.users[]` | | `scram`: `name`, `scram_verifier` (PostgreSQL's stored format), `policy`, `context`. |
| `auth.identities[]` | | `cert`: exactly one of `subject_cn` or `spiffe_id` (URI SAN), plus `policy`, `context`. |
| `limits.max_connections` | `100` | Extra clients get FATAL 53300. |
| `limits.max_message_bytes` | `1048576` | Largest client message; larger is FATAL 08P01. |
| `limits.idle_timeout_seconds` | `0` (off) | Close sessions idle this long with nothing in flight (FATAL 57P05). |
| `limits.auth_timeout_seconds` | `30` | Startup + authentication must finish within this (FATAL 08006). |
| `deny_sqlstate` | `42501` | SQLSTATE of policy denials. |
| `allow_transaction_control` | `true` | Let plain `BEGIN`/`START TRANSACTION [modes]`, `COMMIT`, `END`, `ROLLBACK`, `ABORT` through without a policy check, so drivers work outside autocommit. Matching is exact, token by token: comments, quotes, savepoints, `AND CHAIN` and `PREPARE TRANSACTION` are not matched and go to the policy. |
| `audit.type` | `stdout` | `stdout`, `file` (with `path`; created 0600, append) or `none`. |
| `audit.log_raw_sql` | `false` | Include the SQL text in audit records (otherwise only its SHA-256). |
| `logging.level` | `info` | `debug`, `info`, `warn`, `error`. Logs are JSON lines on stderr. |
| `shutdown_grace_seconds` | `10` | On SIGTERM/SIGINT, how long to let sessions finish before closing them. |

Validation also checks that every user's/identity's `context` provides every
value its policy's tenancy needs, that TLS files parse, that `cert` auth has
`tls.client_auth: require`, and that names are unique.

## Authentication

**SCRAM-SHA-256** (`auth.method: scram`). The proxy implements the server side
of RFC 5802/7677 exactly as PostgreSQL does (mechanism `SCRAM-SHA-256`, no
channel binding). Verifiers use PostgreSQL's stored format, so you can also copy
one from `pg_authid.rolpassword`. Unknown users go through a full fake exchange
with a deterministic per-process salt, so user names cannot be probed. Failures
are always `FATAL 28P01 password authentication failed for user "..."`.
Passwords should be ASCII (SASLprep is the identity for ASCII).

**Client certificates** (`auth.method: cert`). The TLS handshake verifies the
chain against `tls.client_ca`; the proxy then matches the leaf's subject CN or a
`spiffe://` URI SAN against `auth.identities`. The startup user name is not used
for authorization. Certificate revocation lists are not checked.

**Upstream.** The proxy authenticates to PostgreSQL with `trust`, cleartext
(only over TLS), MD5 or SCRAM-SHA-256, and verifies the server's SCRAM
signature (mutual authentication). It always sends `client_encoding=UTF8`, and
terminates the session if the server ever reports a different
`client_encoding` or `standard_conforming_strings` other than `on`, because the
verified bytes must mean the same thing to the server as to the parser.

## Protocol handling

| Message | Behaviour |
|---|---|
| `SSLRequest` | `S` + TLS handshake when `tls` is configured, else `N`. Bytes pipelined after the request are a protocol violation (CVE-2021-23214). |
| `GSSENCRequest` | Always refused with `N`. |
| `StartupMessage` | Protocol 3.x only; a newer minor version or `_pq_.*` options get `NegotiateProtocolVersion` (3.0). Needs `user`; `database` must equal `upstream.database`; any `replication` parameter is refused; only `application_name` is forwarded. `options` and every other parameter are ignored, so clients cannot set GUCs such as `search_path`. |
| `CancelRequest` | Proxy-issued (pid, key) pairs are random and map to the upstream backend; the key is compared in constant time; the request is forwarded over a fresh upstream connection (TLS if configured). |
| `Query` (simple) | Verified as a whole. Denied if the verdict denies, or if it needs bound tenancy parameters (they cannot be bound in the simple protocol: use prepared statements). |
| `Parse` | Verified; the verdict is remembered per statement name. A named statement that already exists is refused (42P05). |
| `Bind` | The statement's verdict is looked up. Every `$n` in `verdict.bind_params` is **replaced** with the session's context value (text format), whatever the client sent; binary format for those parameters is refused. Unknown statements are refused (26000). |
| `Describe`, `Execute`, `Close`, `Flush`, `Sync`, `Terminate` | Validated and relayed. |
| `FunctionCall` | Refused in-band (`deny_sqlstate`, `PROXY_FUNCTION_CALL`). |
| `CopyData`/`CopyDone`/`CopyFail`, unknown types, malformed or oversized messages | FATAL 08P01 and the connection is closed. `COPY` statements are already denied by the policy (`E_STATEMENT_KIND`); a server that enters COPY mode anyway ends the session. |

The SQL forwarded upstream is always byte-for-byte the SQL that was verified;
only Bind parameter values are rewritten.

### Denials

A denial looks exactly like a PostgreSQL error, so every driver surfaces it
normally, and the connection stays usable:

| Field | Value |
|---|---|
| `S`, `V` | `ERROR` |
| `C` | `deny_sqlstate` (default `42501`, `insufficient_privilege`) |
| `M` | `haltsql: query denied by policy "<name>": <first reason>` |
| `D` | `HaltSQL reasons: E_COLUMN_DENIED, ...` (reason codes, see [reason-codes.md](reason-codes.md)) |
| `H` | the first reason's hint, when it has one |

Denials raised by the proxy itself use these pseudo-codes in `D`:
`E_PARAM_UNBOUND` (bound tenancy over the simple protocol, binary or missing
tenancy parameter), `PROXY_STATEMENT_EXISTS` (42P05),
`PROXY_STATEMENT_UNKNOWN` (26000), `PROXY_FUNCTION_CALL`.

Inside a transaction a denial aborts the transaction, exactly like a real
permission error. In the extended protocol, messages after a denied one are
discarded until `Sync`, as PostgreSQL does.

**How ordering is preserved.** Clients pipeline. Instead of writing the error
directly (which could overtake responses to earlier messages), the proxy
replaces the denied message with a statement that cannot parse
(`haltsql_deny_<random>`), so the server's own error handling produces an error
at exactly the right position and skips to `Sync`. The proxy swaps that error
for the denial. The random token is per denial and never reaches the client.

**Statement bookkeeping.** A `Parse` takes effect only when the server answers
`ParseComplete`; after an error the server ignores later messages until `Sync`.
The proxy therefore commits a statement's verdict only on `ParseComplete`,
drops pending ones on `ErrorResponse`, and makes a `Bind` that depends on an
unresolved `Parse` from an earlier `Sync` segment wait for it. A missing entry
always denies, so bookkeeping can only err towards denial; a client cannot make
the proxy apply one statement's tenancy positions to another statement.

## Audit and logs

One JSON object per verified statement:

```json
{"ts":"2026-11-07T22:45:17.297Z","event":"statement","session":"49fd05aacd53",
 "user":"agent","policy":"proxy-test","policy_version":"sha256:...",
 "protocol":"extended","statement":"","allowed":false,
 "reasons":["E_COLUMN_DENIED"],"shadow_reasons":[],"sql_sha256":"...",
 "fingerprint":"...","tables":["app.users"],"bind_params":[1]}
```

`bind_params` lists parameter numbers only, never values. Proxy-level denials
(`bind`, `parse`, `function_call` events) carry `reasons` and `message`.
Operational logs (stderr, JSON lines) record connections, authentication
results, denials and errors. Neither ever contains passwords, verifiers, SCRAM
messages, keys or bind values, and SQL text only with `log_raw_sql: true`.

## Operations

- `haltsql-proxy run -c FILE [--listen HOST:PORT] [--log-level L]`
- `haltsql-proxy validate -c FILE [--json]` prints the effective config with
  secrets redacted. Exit 0 valid, 1 invalid, 2 unreadable.
- `haltsql-proxy scram-verifier [--iterations N]` reads a password from stdin.
- SIGTERM/SIGINT: stop accepting, drain for `shutdown_grace_seconds`, close the
  rest, exit 0.
- Give the upstream user the least privilege that works (for a read-only
  agent: `SELECT` on the policy's tables only, `default_transaction_read_only`),
  and keep row-level security on as a second layer (see
  [defense-in-depth.md](defense-in-depth.md)).

## Limitations

- No SCRAM channel binding (`SCRAM-SHA-256-PLUS`), no GSSAPI, no CRL/OCSP for
  client certificates.
- `COPY`, the fastpath function-call protocol, replication connections,
  `LISTEN`-style asynchronous workflows that need non-SELECT statements, and
  savepoints (unless the policy allows them, which v1 policies cannot) are not
  available through the proxy.
- No metrics endpoint yet; use the audit stream.
- Client `options`/GUC startup parameters are ignored, not forwarded.

## Testing

```bash
make -C lab up      # Postgres 17 on localhost:5417
dune test test/proxy
```

`test/proxy/test_pgwire_unit.ml` covers the codecs, SCRAM (RFC 7677 vector),
config validation, enforcement decisions and statement bookkeeping.
`test/proxy/test_proxy_integration.ml` starts the real binary four times
(SCRAM + optional TLS, client-cert auth, tight limits, unavailable upstream TLS)
against database `haltsql_proxy_test` and drives it with psycopg 3 from
`lab/.venv` and a raw protocol client: allowed and denied queries, tenancy
overwrite (the client asks for another tenant and gets only its own rows),
pipelining, transactions, cancel (plain and TLS), COPY, auth failures, protocol
violations, limits, audit content, log hygiene and graceful shutdown. It skips
when Postgres or the venv is unavailable.

`lab/proxy` runs a haltlab scenario through the proxy and checks parity with
the CLI, row-for-row equality with directly bound execution (while the client
always sends another tenant's id), and honeytokens:

```bash
cd lab && .venv/bin/python -m proxy run proxy/scenarios/proxy-smoke.yaml
```
