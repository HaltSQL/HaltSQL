# Troubleshooting

This page is for operators and on-call engineers. It is organised by symptom:
for each one it says what the symptom means, how to confirm the cause with a
command, endpoint, log line or metric that HaltSQL actually produces, and how
to fix it.

## Before you start

Most diagnosis uses four tools. The examples assume a server on
`127.0.0.1:8080` and a token in `$HALTSQL_TOKEN`.

| Tool | Command |
|---|---|
| Readiness and loaded policies | `curl -sS http://127.0.0.1:8080/readyz` and `curl -sS -H "Authorization: Bearer $HALTSQL_TOKEN" http://127.0.0.1:8080/v1/policies` |
| Metrics | `curl -sS http://127.0.0.1:8080/metrics \| grep '^haltsql_'` |
| Logs | JSON lines on stderr, with `ts`, `level` and `msg` fields. For example `kubectl logs deploy/haltsql \| jq -c 'select(.msg == "reload failed; keeping the last good configuration")'` |
| Reproduce a verdict offline | `haltsql explain --policy policy.yaml --context '{"tenant_id":"acme"}' --sql '...'` with the same policy file and context the server uses |

If `server.admin` is enabled, `GET /v1/admin/status` (as an admin caller)
shows the loaded policies with their versions and origins, bundle sources with
`last_error`, audit sink health and `audit_restart_pending`. See
[http-api.md](../http-api.md#get-v1adminstatus).

Every response carries `X-Request-Id`. Send your own to find a request in the
server logs and audit records (`request_id`).

**A denial is not an error.** A denied query returns `200` with
`"allowed": false` and reason codes. Any non-200 status means the check did
not happen. Start by telling these apart.

## Quick index

| Symptom | Section |
|---|---|
| Every query is denied | [Every query is denied](#every-query-is-denied) |
| `E_TENANT_MISSING` on a query that has a tenant filter | [E_TENANT_MISSING on queries that look scoped](#e_tenant_missing-on-queries-that-look-scoped) |
| `401`, `403` from `/v1/verify` | [401 and 403 from the server](#401-and-403-from-the-server) |
| `503` from `/v1/verify`, or `/readyz` not ready | [503 responses and not ready](#503-responses-and-not-ready) |
| A policy change did not take effect | [Policy reload failed or did not happen](#policy-reload-failed-or-did-not-happen) |
| The server or proxy exits at startup | [The process will not start](#the-process-will-not-start) |
| A bundle is refused | [Bundle signature or bundle source failures](#bundle-signature-or-bundle-source-failures) |
| Audit errors, `AUDIT_UNAVAILABLE`, SQLSTATE `58030` | [Audit sink errors](#audit-sink-errors) |
| `haltsql audit verify` reports problems | [Audit chain verification fails](#audit-chain-verification-fails) |
| OIDC tokens rejected, `groups_overage` | [OIDC rejections and groups overage](#oidc-rejections-and-groups-overage) |
| Clients cannot connect to `haltsql-proxy` | [Proxy connection errors](#proxy-connection-errors) |
| Slow verifies | [High latency](#high-latency) |

## Every query is denied

**What it means.** The server is answering (`200`), but every verdict has
`"allowed": false`. The cause is almost always the same for every query:
missing context, a name that does not resolve, or a policy rule the agent
never satisfies.

**How to confirm.**

1. Look at the codes: `curl -sS http://127.0.0.1:8080/metrics | grep haltsql_reasons_total`.
   One code dominating points to the cause.
2. Take one denied query and run `haltsql explain` with the same policy file
   and context.
3. Check that the server runs the policy you think it does: compare
   `policy.version` in a verdict (or `GET /v1/policies`) with the `policy.version`
   from `haltsql verify --json` on your local file. For a bundle with a
   `name_prefix`, the version reflects the prefixed name; use
   `haltsql bundle inspect BUNDLE` to see the versions inside it.

| Dominant code | Usual cause | Fix |
|---|---|---|
| `E_CONTEXT_MISSING` | The request does not carry the context field the policy's tenancy needs. The field name is the one after `ctx.` in `tenancy.keys`, for example `tenant_id` in `"${ctx.tenant_id}"`. For OIDC callers, the context comes from `context_claims`; for mTLS callers, from the identity's `context`. | Send the field from the authenticated session, or fix `context_claims`. See [reason-codes.md](../reason-codes.md#e_context_missing). |
| `E_TABLE_DENIED` | Unqualified table names resolve through the policy's `search_path`; if it does not match the agent's schema, every table is "not in the allowlist". | Fix `search_path`, or have the agent qualify names. See [policy-reference.md](../policy-reference.md#search_path). |
| `E_LIMIT_REQUIRED`, `E_LIMIT_TOO_HIGH` | `require_limit` is set and the agent omits `LIMIT` or uses a parameter. | Teach the agent (tool description) to add a constant `LIMIT n` within `max`. |
| `E_PARAM_UNBOUND` | The agent uses `$n` for values other than the tenant, or reuses the tenant placeholder outside its predicate. Also returned by `haltsql-proxy` for bound tenancy over the simple query protocol. | Literals for non-tenant values; prepared statements through the proxy. See [reason-codes.md](../reason-codes.md#e_param_unbound). |
| `E_TENANT_MISSING` | See the next section. | |
| `E_COLUMN_UNRESOLVED` | Unqualified or ambiguous columns in joins. | Qualify every column with its alias. |
| `E_EXTERNAL_POLICY` | OPA denies, or OPA is unreachable and `opa.on_error` is `deny`. | Check `haltsql_opa_decisions_total{outcome}` (`error_denied` means OPA failed) and the `opa check failed` log line. See [opa.md](../opa.md). |
| `E_INTERNAL` | An analyzer bug. | File a bug with the SQL, policy and version. If it looks like a bypass attempt, report it privately ([SECURITY.md](../../SECURITY.md)). |

If the verdicts are `"allowed": true` but carry `shadow_reasons`, the policy
is in shadow mode and nothing is being enforced.

## E_TENANT_MISSING on queries that look scoped

**What it means.** HaltSQL needs to prove, for every occurrence of every
tenant-scoped table in every scope, that a tenant predicate filters it. The
proof only accepts simple, auditable shapes, so some safe-looking queries are
denied on purpose.

**How to confirm.** `haltsql explain` prints each reason with its position in
the SQL and a caret under the table occurrence that lacks a predicate, plus a
hint naming the alias. Then compare the query with this table:

| Query shape | Why it is denied | Fix |
|---|---|---|
| `WHERE tenant_id = $1 OR status = 'open'` | Only top-level `AND` conjuncts count. `OR`, `NOT`, `CASE`, `COALESCE` and function arguments prove nothing. | Make the tenant predicate a top-level `AND`. |
| Filter only in the outer query of a subquery or CTE | Each scope must prove its own occurrences. | Add the predicate inside the subquery or CTE body. |
| A `UNION` with a filter in one branch | Each branch is a scope. | Filter every branch. |
| `JOIN customers c ON c.tenant_id = o.tenant_id` with `WHERE o.tenant_id = $1` | Equality is not propagated through joins. | Add `AND c.tenant_id = $1`. |
| Filter in the `ON` of a `LEFT JOIN` for the preserved side | The preserved side's rows are not filtered by `ON`. | Move it to `WHERE`. |
| Filter in `HAVING` | Rows are already grouped. Only `WHERE` and `ON` count. | Move it to `WHERE`. |
| A composite tenancy (`org_id` and `workspace_id`) with one predicate | Every tenant column needs its own predicate. Row-value comparisons such as `(a, b) = ($1, $2)` are not recognized. | One conjunct per tenant column. |
| `tenant_id <> $1`, `IS DISTINCT FROM`, `LIKE` | Only `=` (and `= ANY` / `IN` for sets) count. | Use `=`. |
| A view or table listed with a tenant column but queried without a predicate | Views are opaque relations; they need predicates like tables. | Add the predicate, or review the policy entry. |

Reference: [tenancy.md](../tenancy.md#what-breaks-the-proof),
[tenancy.md](../tenancy.md#equality-propagation),
[tenancy.md](../tenancy.md#composite-keys),
[reason-codes.md](../reason-codes.md#e_tenant_missing).

`E_TENANT_MISMATCH` is different: in literal mode the literal differs from the
context value, or in bound mode a literal was used instead of `$1`.

## 401 and 403 from the server

**What it means.** The request was refused before verification. The body says
why: `{"error": {"code": "...", "message": "..."}}`.

**How to confirm.** `haltsql_auth_total{method,result}` shows which
authentication method is failing (`method` is `token`, `oidc`, `mtls`,
`anonymous` or `none`; `result` is `ok`, `rejected` or `unavailable`). OIDC
rejections are logged at `info` as `oidc token rejected` with a `reason` field.

| Response | Message or log | Cause | Fix |
|---|---|---|---|
| `401 UNAUTHORIZED` | `missing bearer token` | No `Authorization: Bearer` header, and no matching client certificate. | Configure the client's token. |
| `401 UNAUTHORIZED` | `invalid bearer token` | No `token_sha256` matches. A common cause is hashing the token with a trailing newline (`echo` instead of `printf '%s'`). | Recompute: `printf '%s' "$token" \| sha256sum \| cut -d' ' -f1`, update the hash and reload. See [config-reference.md](../config-reference.md#server). |
| `401 UNAUTHORIZED` | `client certificate does not match any configured identity` | The certificate verified against `client_ca` but matches no `spiffe_id` or `subject_cn`, and there is no bearer token to fall back to. | Fix the identity entry. A CN in a TeletexString or with control characters never matches. |
| `401 UNAUTHORIZED` | OIDC `reason`: `expired`, `not_yet_valid`, `issued_in_future`, `wrong_audience`, `wrong_issuer`, `bad_signature`, `unknown_kid`, `missing_kid`, `alg_not_allowed`, `malformed`, `claim_mismatch`, `policy_not_allowed`, `missing_claim`, `bad_claim`, `no_group_policy`, `groups_overage` | The JWT failed its provider's checks. | See [OIDC rejections](#oidc-rejections-and-groups-overage). |
| `403 FORBIDDEN` | | The request names a `policy` other than the caller's pinned one. On `/v1/admin/*`: the caller is not in `server.admin.callers`. | Omit `policy` in the request, or fix the pinning. |
| `403 CONTEXT_NOT_ALLOWED` | | An OIDC or mTLS caller sent a context field that is not in its `request_context_fields`. Repeating an identity-provided field with the same value is accepted. | Stop sending the field, or add it to `request_context_fields` if the caller may set it. |
| `404 POLICY_NOT_FOUND` | | The request names an unknown policy, or names none and there is no default. | Check `GET /v1/policies`. |

Reference: [http-api.md](../http-api.md#post-v1verify),
[authentication.md](../authentication.md).

## 503 responses and not ready

| Response | Meaning | How to confirm | Fix |
|---|---|---|---|
| `503 NOT_READY`; `/readyz` `{"status":"not_ready","policies":0}` | No policy is loaded. | `haltsql_policies_loaded` is 0. | Check the startup logs; see [The process will not start](#the-process-will-not-start). |
| `503 POLICY_UNAVAILABLE` | The caller's pinned policy is not currently loaded. | `GET /v1/policies` and, with the admin API, `GET /v1/admin/status`. | Restore the policy (or its bundle) and reload. |
| `503 AUDIT_UNAVAILABLE`; `/readyz` lists `unhealthy_audit_sinks` | A `fail_closed` audit sink cannot be written. | See [Audit sink errors](#audit-sink-errors). | |
| `503 AUTH_UNAVAILABLE` with `Retry-After` | The OIDC provider's keys cannot be fetched and the cache has run out. | Log `oidc signing keys unavailable` (with `request_id`); `haltsql_auth_total{method="oidc",result="unavailable"}`. | Restore egress to the IdP (in Kubernetes, check the NetworkPolicy egress rules; the Helm chart opens TCP 443 only when `oidc` is set). |
| `/readyz` `"draining": true` | The process received `SIGTERM` and is shutting down. | Log `shutting down`, `draining connections`. | Expected during rollouts. |
| `413 PAYLOAD_TOO_LARGE` | The body is larger than `limits.max_request_bytes` (default 1 MiB). | | Raise the limit or send smaller requests. The SQL itself is limited separately by the policy's `limits.max_bytes` (`E_LIMIT`). |

## Policy reload failed or did not happen

**What it means.** Either the server tried to reload and rejected the new
configuration (the last good one stays active), or it never saw a change.

**How to confirm.**

- A failed reload logs `reload failed; keeping the last good configuration`
  with an `errors` list, and increments
  `haltsql_policy_reload_total{result="error"}`.
- A successful reload logs `policies reloaded` with every policy as
  `name@version`, and increments `{result="success"}`.
- Neither line means no reload happened.

| Cause | Fix |
|---|---|
| The new policy or config does not load (unknown key, bad YAML, invalid value). | Run `haltsql validate FILE` and `haltsql config show --config FILE` with the same files. Errors carry file, line, column and key path. |
| A token, OIDC provider, mTLS identity or `default_policy` references a policy that is no longer loaded. | Restore the policy or fix the reference. The whole reload is refused, not just the reference. |
| A secret placeholder cannot be resolved. | The error is located (`file:line:col: ${vault:...}: ...`). Fix access to the provider. |
| The change turns `server.tls` on or off. | Restart; this cannot be done by reload. |
| New TLS material is broken or the key does not match. | `haltsql_tls_reload_total{result="error"}`; the previous material stays. Fix the files. |
| No reload happened: the ConfigMap is mounted with `subPath`. | Such mounts are not updated in running pods. Mount the directory, or roll the deployment. |
| No reload happened: `reload.watch` is off. | Send `SIGHUP` (`systemctl reload haltsql`) or roll. The operator turns watching off on purpose and rolls instead. |
| No reload happened: the change was in a file referenced only through `${file:...}` (a token hash, for example). | Those files are not watched. Send `SIGHUP`. |
| The reload succeeded but audit sinks did not change. | Audit sinks need a restart. The reload logs `audit sink changes need a restart; keeping the current audit sinks` and `GET /v1/admin/status` shows `audit_restart_pending: true`. |
| A bundle source entry was added, removed or changed but nothing happened. | The list of bundle sources needs a restart. |

After a failed reload, the server does not retry the same broken files on
every poll; it tries again when they change. For `haltsql-proxy`, the log line
is `config reload failed; keeping the current configuration`, and a reload
applies only to new connections. Reference:
[config-reference.md](../config-reference.md#reload),
[proxy.md](../proxy.md#hot-reload).

## The process will not start

**What it means.** `haltsql-server` exits with code `2` when the
configuration cannot be loaded or the listener cannot start. Load errors are
logged as `failed to load configuration` with an `error` field; other startup
problems are logged at `error` level with the reason as the message (or as
`startup failed` for operating-system errors).

| Cause | How to confirm | Fix |
|---|---|---|
| Config or policy does not load. | `haltsql config show --config FILE`; `haltsql validate FILE`. | Fix the reported location. |
| An unknown `--default-policy` (or `default_policy`). | Startup error. | Name a loaded policy. |
| A secret placeholder cannot be resolved. | Located load error naming the placeholder (never its value). | Fix the provider, the env var or the file. |
| A bundle signature does not verify, or the bundle is malformed. | `haltsql bundle verify BUNDLE --public-key KEY` exits 1. | See [Bundle failures](#bundle-signature-or-bundle-source-failures). |
| A bundle source is unreachable and `cache_dir` holds no usable bundle. | Startup fails closed. | Restore access to the source, or provide a cache directory that survived. |
| The audit file's last line is not a sealed record (a crash during a write). | An `error` log line at startup; the file sink refuses to continue a chain from a line it cannot read as an audit record. | Move the file aside (rotate it) and start; keep the old file for verification. |
| The listen address is in use or invalid. | An `error` log line at startup. | Fix `server.listen` / `--listen` / `HALTSQL_LISTEN`. |
| An invalid `HALTSQL_*` environment value. | Load error naming the variable. | Fix or unset it. |

In Kubernetes, a pod in this state never becomes ready. With
`maxUnavailable: 0` the old pods keep serving. The operator reports
`Progressing=False` with reason `RolloutFailed` after 180 seconds.

`haltsql-proxy validate -c FILE` checks a proxy config (exit 0 valid, 1
invalid, 2 unreadable). Its command-line errors exit `2`.

## Bundle signature or bundle source failures

**What it means.** A bundle failed one of the verification steps (size,
signature, canonical form, digest, structure, policies), or a bundle source
could not fetch or accept a new version. The last good bundle stays active.

**How to confirm.**

- Local file: `haltsql bundle verify BUNDLE --public-key KEY` (exit 1 on
  failure; add `--json` for details). `haltsql bundle inspect BUNDLE` lists the
  signer key ids; without `--public-key` it says `UNVERIFIED`.
- Bundle source: the log line `bundle source poll failed; keeping the last good bundle`
  carries `source`, `code` and `error`; `haltsql_bundle_source_healthy{source}`
  is 0; `GET /v1/admin/status` shows `last_error` and the `current` bundle
  (`version`, `signed_by`).

| `code` | Usual cause | Fix |
|---|---|---|
| `bundle_source_signature` | Signed with a key that is not in `public_keys`, or a malformed `.sig`. | Add the new public key to `public_keys` (and reload), or re-sign. During key rotation, dual-sign with `haltsql bundle sign --append`. |
| `bundle_source_rollback` | The new bundle's `metadata.version` is not strictly greater than the current one, or it has another `metadata.name`. Commit SHAs as versions trigger this. | Publish with a monotonic version, for example `1.0.<run number>`. |
| `bundle_source_rejected` | The server refused the verified bundle, for example because a token references a policy the bundle no longer has. | Restore the policy in the bundle, or change the reference first. |
| `bundle_source_invalid` | Too large, not canonical, wrong digest, or a policy or catalog that does not load. | Rebuild with `haltsql bundle build`; check with `haltsql bundle verify`. |
| `bundle_source_integrity` | A manifest or blob does not match its digest or size. | Re-push; check for a proxy or mirror rewriting content. |
| `bundle_source_denied` | HTTP 401/403 or rejected credentials. | Fix the `auth` credentials. Changing a bundle source entry needs a restart. |
| `bundle_source_not_found` | No such tag, digest, object or URL. | Fix the reference. |
| `bundle_source_unavailable` | Connection failure, timeout, TLS failure, 429 or 5xx. | Restore network access; the poller retries at the next interval. |
| `bundle_source_protocol` | Another unexpected response. | Check the registry or server. |
| `bundle_source_cache` | `cache_dir` cannot be read or written. Never fatal. | Fix permissions or the volume. |

If the bundle was refused at startup but a cached last good bundle exists,
the server starts from it and logs
`bundle refused at startup; starting from the cached last good bundle`.

Reference: [policy-bundles.md](../policy-bundles.md#what-the-poller-does),
[policy-bundles.md](../policy-bundles.md#verification-order-fail-closed).

## Audit sink errors

**What it means.** A sink could not write a record. What happens next depends
on the sink's `on_error`:

| `on_error` | `haltsql-server` | `haltsql-proxy` |
|---|---|---|
| `fail_closed` (default) | `/v1/verify` returns `503 AUDIT_UNAVAILABLE`. For S3/GCS, Elasticsearch and Kafka the sink turns unhealthy after a batch fails all its attempts, and `/readyz` is 503 until a retry succeeds. For `file`/`stdout`, each request retries the write. | The statement is refused: `ERROR`, SQLSTATE `58030`, detail `HaltSQL reasons: PROXY_AUDIT_UNAVAILABLE`. The connection stays usable. |
| `buffer` | Records wait in memory and requests continue, up to a bound; then requests are refused as above. | Records wait in memory up to `max_buffer_records`; then `58030`. |
| `drop` (streaming sinks, and the proxy) | Records are dropped, counted and logged; requests continue. | Records are dropped and logged (`audit sink write failed; record dropped (on_error: drop)`). |

**How to confirm.**

| Signal | Where |
|---|---|
| `audit sink write failed; failing request closed` (with `sink`, `error`, `request_id`) | server log |
| `audit sink write failed; record buffered` | server log, `buffer` mode |
| `audit sink write failed; refusing the statement` | proxy log |
| `haltsql_audit_errors_total` | server metrics |
| `haltsql_audit_sink_healthy{sink}`, `_pending_objects`, `_upload_failures_total`, `_rejected_writes_total` | server metrics, S3/GCS |
| `haltsql_audit_stream_sink_healthy`, `_delivering`, `_delivery_failures_total`, `_records_dropped_total{reason}` | server metrics, Elasticsearch/Kafka |
| `unhealthy_audit_sinks` in `/readyz`; `audit_sinks[].healthy` in `/v1/admin/status` | server endpoints |

| Cause | Fix |
|---|---|
| S3 `AccessDenied`, expired credentials | Check the identity has `s3:PutObject` (and `s3:PutObjectRetention` with Object Lock). Temporary credentials are refreshed automatically. |
| S3 refuses Object Lock headers | The bucket must have Object Lock enabled. |
| Kafka `UNKNOWN_TOPIC_OR_PARTITION` | Topics are never created automatically. Create it. |
| Kafka broker name with `_`, or `PLAIN` to a non-loopback leader without TLS | Refused on purpose. Use valid DNS names and TLS. |
| Elasticsearch `mapping` drops | A field changed type. Fix the index template; see `records_dropped_total{reason="mapping"}`. |
| Disk full or unwritable path for a `file` sink | Free space or fix permissions; the next write recovers. |

Changing `on_error` or any sink setting needs a restart. A streaming sink
drops records only in `drop` mode or when the destination rejects a record for
good (`mapping`, `too_large`); both are counted and logged, and a dropped
record that was already sealed shows as a gap in chain verification. Records
still queued in memory are lost if the process dies. Reference:
[audit-sinks.md](../audit-sinks.md#failure-policy-on_error),
[proxy.md](../proxy.md#failure-policy-on_error).

## Audit chain verification fails

Run `haltsql audit verify` on the sink's output. Exit `0` means every chain
verifies, `1` a chain is broken, `2` a usage error or unreadable input.

| Problem `kind` | Usual benign cause | When to worry |
|---|---|---|
| `chain_restart` (warning) | A `stdout` sink after a process restart, or several replicas in one log. | Never on its own; an error with `--strict`. |
| `mid_chain_start` | You verified a time range or one day of objects. | Pass `--any-start` or `--initial-prev HASH` for partial exports. |
| `duplicate_record` | Kafka at-least-once re-delivery. | Pass `--allow-redelivery` for Kafka exports; otherwise investigate. |
| `truncated` | The process died during a write. | Expected only at the end of a file after a crash. |
| `broken_link`, `bad_hash`, `seq_gap`, `body_mismatch`, `fork`, `head_mismatch`, `spool_head_mismatch` | None. | Records were edited, deleted, inserted or reordered. Treat as a security incident. |

For Elasticsearch and Kafka exports, use `test/siem/verify_chain.py` as shown
in [audit-sinks.md](../audit-sinks.md#verifying-from-kafka). Full list of
problem kinds: [audit-verify.md](../audit-verify.md).

## OIDC rejections and groups overage

**How to confirm.** `jq -c 'select(.msg == "oidc token rejected")'` over the
server log; the `reason` field is a stable code. The `401` body's message also
says why.

| `reason` | Cause | Fix |
|---|---|---|
| `groups_overage` | Entra ID (Azure AD) left the `groups` claim out because the user is in too many groups (`_claim_names` / `_claim_sources`, or `hasgroups`). HaltSQL never calls Microsoft Graph, so it rejects the token. | Set *groupMembershipClaims* to `ApplicationGroup` and assign only the relevant groups to the enterprise application, or map app roles with `claim: roles`. |
| `missing_claim` | The groups (or another required) claim is absent. Keycloak omits the groups claim for a user in no group. | Add the claim mapper, or give `policy_from_groups` a `default`. |
| `bad_claim` | The groups claim is not a string or an array of strings. | Fix the mapper. |
| `no_group_policy` | No group in the token is in `map` and there is no `default`. | Add the mapping or a `default`. Groups are compared exactly and are case-sensitive; Keycloak's *Full group path* adds a leading `/`. |
| `wrong_audience` | `aud` contains none of `audiences`. | Request the token for the right audience. |
| `expired`, `not_yet_valid`, `issued_in_future` | Clock skew beyond `leeway_seconds` (default 60), or a stale token. | Fix time sync; refresh tokens. |
| `unknown_kid` | The IdP rotated keys. The server refreshes once per unknown `kid`, at most every 30 seconds per provider. | Usually resolves itself; if not, check `jwks_uri` reachability. |
| `claim_mismatch` | A `required_claims` entry did not match. | Fix the token's claims or the requirement. |
| `policy_not_allowed` | `policy_claim` names a policy outside `allowed_policies`. | Fix the claim or the allowlist. |

Reference: [authentication.md](../authentication.md#policies-from-idp-groups),
[authentication.md](../authentication.md#key-fetching-and-caching).

## Proxy connection errors

`haltsql-proxy` reports problems as PostgreSQL errors, so drivers show the
SQLSTATE. Session and audit events go to its stderr log.

| SQLSTATE and message | Cause | Fix |
|---|---|---|
| `28000` `haltsql-proxy requires an SSL/TLS connection` | `tls.required` is `true` (the default) and the client did not upgrade. | Use `sslmode=require` or stricter. |
| `28000` `a TLS client certificate is required` / `certificate identity is not authorized` | `auth.method: cert` and the certificate is missing or matches no identity. | Fix the client certificate or `auth.identities`. |
| `28P01` `password authentication failed for user "..."` | Wrong password, unknown user, or a bad `scram_verifier`. Unknown users get the same message on purpose. | Regenerate with `haltsql-proxy scram-verifier`. |
| `3D000` `database "..." does not exist` | The client asked for a database other than `upstream.database`. | Use exactly that database name. |
| `28000` `replication connections are not allowed through haltsql-proxy` | A replication connection. | Not supported through the proxy. |
| `53300` `sorry, too many clients already (haltsql-proxy limits.max_connections)` | `limits.max_connections` (default 100) reached. | Raise it, pool connections, or add replicas. |
| `08006` `haltsql-proxy could not connect to the upstream database` / `did not respond` / `the upstream database rejected the session` | Upstream down, unreachable, TLS or credential failure (log: `upstream rejected the session`). | Check `upstream.*`, credentials and `upstream.tls`. With `verify-full`, the host must be in a DNS SubjectAltName of the server certificate. |
| `08006` `authentication timed out` | Startup and authentication took longer than `limits.auth_timeout_seconds` (default 30). | Check the client and network. |
| `08P01` `message exceeds the haltsql-proxy size limit` | A message larger than `limits.max_message_bytes` (default 1 MiB). | Raise the limit or send smaller statements. |
| `08P01` `COPY sub-protocol is not allowed through haltsql-proxy` | `COPY`. | Not available through the proxy. |
| `57P05` `terminating connection due to idle timeout ...` | `limits.idle_timeout_seconds` is set and the session was idle. | Raise it, or let the pool reconnect. |
| `42501` `haltsql: query denied by policy "<name>": ...` | A policy denial (`deny_sqlstate`). The detail lists the reason codes. | Fix the query; see [Every query is denied](#every-query-is-denied). |
| `58030` `haltsql: the audit log could not be written; statement refused` | A `fail_closed` audit sink failed. | See [Audit sink errors](#audit-sink-errors). The client may retry. |
| `42P05`, `26000` | A named prepared statement already exists, or is unknown. | Driver statement handling; see [proxy.md](../proxy.md#denials). |

Reference: [proxy.md](../proxy.md).

## High latency

**What it means.** Verify calls take longer than expected. Separate the time
spent verifying from the time spent waiting.

**How to confirm.**

- `haltsql_verify_duration_seconds` measures verification only.
  `histogram_quantile(0.99, rate(haltsql_verify_duration_seconds_bucket[5m]))`
  above 0.05 is the alert threshold in
  [observability.md](../observability.md#recommended-alerts).
- `elapsed_us` in each verdict and audit record is the same per request.
- If verification is fast but clients see slow responses, the server is
  queueing. Check `haltsql_http_open_connections`, CPU on the instance, and the
  log line `connection limit reached; new connections wait in the listen backlog`.

| Cause | Fix |
|---|---|
| The instance is saturated. One server instance verifies on one event loop; in the published benchmark throughput levels off at about 4.5k requests/s and latency then grows with queue depth. | Add replicas. See [high-availability.md](high-availability.md#sizing). |
| CPU throttling from a container CPU limit. | The Helm chart sets no CPU limit by default for this reason. |
| Heavy queries. Cost grows with query complexity (joins, CTEs, window functions); pathological inputs take low milliseconds and are denied by the policy limits. | Tighten `limits` (`max_bytes`, `max_depth`, `max_nodes`, `max_joins`). |
| OPA is slow. Every allowed query waits for the decision. | `haltsql_opa_duration_seconds`; run OPA on `127.0.0.1` and keep `timeout_ms` small. |
| OIDC key refreshes. | An unknown `kid` triggers at most one refresh per 30 s per provider. |
| Client-side retries. | The SDKs retry timeouts and 503s with backoff; a slow first attempt can triple the latency the agent sees. |
| Per-invocation CLI use. One `haltsql verify --sql ...` process costs about 10 ms to start. | Use `--batch`, the server, or the in-process library. |
| Through the proxy: large result sets. | The proxy relays each row message (about 5 µs per row in the benchmark). |

Reference: [performance.md](../performance.md).

## Related

- [Runbooks](runbooks.md)
- [Production checklist](production-checklist.md)
- [Reason codes](../reason-codes.md)
- [HTTP API](../http-api.md)
- [Observability](../observability.md)
- [Audit chain verification](../audit-verify.md)
