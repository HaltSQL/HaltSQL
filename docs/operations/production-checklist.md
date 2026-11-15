# Production checklist

This page is for platform and SRE teams taking `haltsql-server` or
`haltsql-proxy` to production. Work through it before go-live and again after
each upgrade. Every item says why it matters, how to check it, and which page
covers it in detail.

> **Note:** HaltSQL is pre-1.0. The 0.0.3 release notes in
> [CHANGELOG.md](../../CHANGELOG.md) say it is not yet recommended as the only
> control in front of production data. Several features on this page (built-in
> TLS, OIDC, mTLS, cloud and SIEM audit sinks, signed bundles and bundle
> sources, `haltsql-proxy`, the operator) are listed under **Unreleased** in the
> changelog at the time of writing. Check the release notes of the exact version
> you deploy.

## How to use this page

Each section is a table. The **Check** column is something you can run or
look at, not a promise. Items marked **Required** close a gap that HaltSQL
cannot close for you; the others are strongly recommended.

## Release and supply chain

| Item | Why | Check | Reference |
|---|---|---|---|
| **Required.** Pin the image by digest, not by tag. | Tags such as `0.0` move. A digest is what you tested. | The pod spec or Helm `image.digest` holds `sha256:...`. | [deployment.md](../deployment.md#docker), [Helm chart README](../../deploy/helm/haltsql/README.md#supply-chain-pin-and-verify-the-image) |
| Verify release signatures and provenance before promoting a version. | Release artifacts are signed keylessly by the release workflow. A signature that does not verify means the artifact did not come from it. | `cosign verify-blob ...`, `cosign verify ...` and `gh attestation verify ...` as shown in the reference. | [deployment.md](../deployment.md#verifying-release-artifacts) |
| Run the same HaltSQL version in policy CI and on the servers. | The CLI that validates and tests policies in CI should load documents exactly as the server will. | `haltsql version` in CI and `haltsql_build_info{version}` on `/metrics` match. | [upgrades.md](upgrades.md) |

## Identity and TLS

| Item | Why | Check | Reference |
|---|---|---|---|
| **Required.** Unauthenticated access is off. | With it on, any caller can use `default_policy` or name a policy. | `haltsql config show --config FILE` shows `allow_unauthenticated: false`; `HALTSQL_ALLOW_UNAUTHENTICATED` is unset; no `--allow-unauthenticated` flag. | [config-reference.md](../config-reference.md#server), [authentication.md](../authentication.md) |
| **Required.** Every caller is pinned to one policy. | A compromised agent cannot pick a looser policy. | Each `server.auth.tokens` entry has `policy`; each OIDC provider has exactly one of `policy`, `policy_claim` + `allowed_policies`, or `policy_from_groups`; each mTLS identity has `policy`. The config loader enforces this. | [authentication.md](../authentication.md#choosing-the-policy) |
| Tenant and user context comes from an authenticated identity where possible. | With static tokens the request body supplies the whole context, so the calling service must be trusted to send the right tenant. With OIDC `context_claims` or mTLS identity `context`, the body cannot override it (`403 CONTEXT_NOT_ALLOWED`). | Review which callers use static tokens. | [authentication.md](../authentication.md#context-rules) |
| Token hashes are never written inline. | Config files end up in ConfigMaps, repositories and support tickets. | `token_sha256` uses `${env:...}`, `${file:...}` or a secret provider placeholder. | [config-reference.md](../config-reference.md#secrets-placeholders) |
| TLS on every listener that is not loopback inside the agent's pod. | Bearer tokens and SQL cross the network. | `server.tls` is set (consider `min_version: "1.3"`), or a mesh or proxy terminates TLS in front and the server binds to `127.0.0.1`. | [authentication.md](../authentication.md#built-in-tls), [deployment.md](../deployment.md) |
| With `client_auth: required`, probes use `--health-listen`. | Kubelet probes cannot present a client certificate. The health listener serves only `/healthz` and `/readyz`. | The Helm chart does this when `tls.enabled` is true (`tls.healthPort`, default 8081). | [cli.md](../cli.md#haltsql-server), [Helm chart README](../../deploy/helm/haltsql/README.md) |
| `/metrics` is reachable only by your monitoring. | `/healthz`, `/readyz` and `/metrics` need no token. | NetworkPolicy (`networkPolicy.metricsFrom` in the chart) or firewall rules. | [http-api.md](../http-api.md#authentication) |
| The admin API is off, or limited to named callers. | `/v1/admin/status` and `/v1/admin/report` reveal policies, sinks and query patterns. | `server.admin.enabled` is `false`, or `server.admin.callers` lists only operator identities. | [config-reference.md](../config-reference.md#serveradmin) |
| Proxy: TLS required, least-privilege upstream user. | The proxy holds the database credentials. | `tls.required: true` (the default), `upstream.tls.mode: verify-full`, and the upstream role has only what the policy needs. | [proxy.md](../proxy.md#config-reference), [proxy.md](../proxy.md#operations) |

## Policies

| Item | Why | Check | Reference |
|---|---|---|---|
| **Required.** Production policies run in `mode: enforce`. | A shadow policy enforces nothing. | `GET /v1/policies` shows `"mode": "enforce"`; `haltsql lint-policy FILE` warns about shadow mode. | [policy-reference.md](../policy-reference.md#mode), [cli.md](../cli.md#haltsql-lint-policy) |
| Tenancy uses bound mode. | The tenant value is bound by your code from `bind_params`, never written by the model. | `tenancy.mode: bound`. | [tenancy.md](../tenancy.md#bound-mode-and-literal-mode) |
| `require_limit` and `limits` are set deliberately. | They bound result size and analysis cost. | `haltsql lint-policy` reports a missing `require_limit`. | [policy-reference.md](../policy-reference.md#limits) |
| **Required.** Policies are validated and tested in CI. | A broken policy is refused at load or reload; you want to find out before that. | `haltsql validate` and `haltsql test` run on every change (GitHub Action, GitLab template or pre-commit). | [policy-ci.md](../policy-ci.md), [testing.md](../testing.md#policy-test-suites) |
| Policies are delivered as signed bundles. | The server verifies the Ed25519 signature before it parses anything, so the delivery channel need not be trusted. | `policies` entries use `bundle` or `bundle_source` with `public_keys`. | [policy-bundles.md](../policy-bundles.md) |
| The signing private key lives only in a CI secret store. | Anyone with the key can publish policies your servers accept. | The key is a protected CI secret (for example a GitHub environment with required reviewers); only `.pub` files are distributed. | [policy-bundles.md](../policy-bundles.md#key-management-and-rotation), [policy-ci.md](../policy-ci.md#signing-in-ci-safely) |
| Polled bundles have a monotonic `metadata.version`. | Bundle sources refuse a version that is not strictly greater than the current one (`bundle_source_rollback`). The GitHub Action's default `bundle-version` is a commit SHA, which has no order. | `bundle-version` is set explicitly, for example `1.0.${{ github.run_number }}`. | [policy-ci.md](../policy-ci.md#publishing-to-an-oci-registry) |
| Bundle sources have a `cache_dir` on storage that survives restarts. | With no cache and an unreachable source, startup fails closed. | `cache_dir` is set (the Helm chart sets `<cache.mountPath>/bundles`; use a PVC to survive rescheduling). | [policy-bundles.md](../policy-bundles.md#what-the-poller-does) |
| Policy rollouts go through shadow mode first. | A stricter policy can deny legitimate agent queries. | See [Shadow before enforce](#shadow-before-enforce). | [shadow-reports.md](../shadow-reports.md#a-rollout-loop) |

## Clients fail closed

| Item | Why | Check | Reference |
|---|---|---|---|
| **Required.** Every non-200 response, timeout or connection error is a denial. | A client that runs the query when the verifier is unreachable turns an outage into a bypass. | Use the official SDKs, which fail closed. In custom clients, review the error path. | [http-api.md](../http-api.md#post-v1verify), [integrations.md](../integrations.md#official-clients) |
| **Required.** The client runs exactly the verified string and binds `bind_params`. | HaltSQL verified that string, not a reformatted one. | The SDK guarded-execute helpers do this and check `sql_sha256`. | [verdict.md](../verdict.md#how-to-use-a-verdict) |
| **Required.** Context comes from the authenticated session, never from the model. | Attacks that control the context are out of scope for HaltSQL. | Code review of every integration. | [threat-model.md](../threat-model.md), [SECURITY.md](../../SECURITY.md) |
| Client timeouts and retries are known. | They decide how long an agent waits during an outage. | The SDK defaults are 2 s (Python) or 5 s per attempt, 2 retries. | [integrations.md](../integrations.md#official-clients) |
| Unknown reason codes are treated as denials. | New codes may be added in minor releases. | Clients branch on `allowed`, never on a list of known codes. | [reason-codes.md](../reason-codes.md) |

## Database role and RLS (defense in depth)

| Item | Why | Check | Reference |
|---|---|---|---|
| **Required.** Agent queries run as a dedicated read-only role, `NOSUPERUSER NOBYPASSRLS`, with column grants that match the policy. | If HaltSQL has a bug or a caller skips it, the database still holds. | [defense-in-depth.md](../defense-in-depth.md#checklist) | [defense-in-depth.md](../defense-in-depth.md) |
| **Required.** RLS is enabled and forced on every tenant-scoped table, keyed on a per-transaction setting. | Same reason. | `haltsql rls check` reports drift between the database and the policy (exit 1 on drift). | [rls-generation.md](../rls-generation.md) |
| The role's `search_path` equals the policy's `search_path`. | Otherwise a name can resolve to a different table in HaltSQL than in PostgreSQL. | Compare the role setting with the policy. | [policy-reference.md](../policy-reference.md#search_path) |
| `statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout` are set on the role. | A query within every policy limit can still be expensive. | `SHOW statement_timeout` as the role. | [threat-model.md](../threat-model.md#known-limitations-and-non-goals) |

## Audit sinks and chain verification

| Item | Why | Check | Reference |
|---|---|---|---|
| At least one durable sink runs with `on_error: fail_closed`. | `fail_closed` (the default) guarantees that no request is served without its audit record. | `haltsql config show` lists each sink's `on_error`. | [audit-sinks.md](../audit-sinks.md#failure-policy-on_error) |
| `drop` is used only next to another `fail_closed` sink. | `drop` serves requests without an audit trail in that sink. | Review `audit.sinks`. | [config-reference.md](../config-reference.md#streaming-sinks-elasticsearch-and-kafka) |
| S3/GCS sinks have a `spool_dir` on persistent storage, one per sink. | Without it, records accepted but not yet uploaded are lost on a crash, and each restart starts a new chain, so deleting an earlier run's objects is not detected. | `spool_dir` is set and backed by a persistent volume. The operator does not provision one. | [audit-sinks.md](../audit-sinks.md#restarts-and-chain-continuity), [kubernetes-operator.md](../kubernetes-operator.md#limitations) |
| Archive storage is write-once. | A hash chain alone cannot detect someone rewriting the whole log. | S3 `object_lock`, a GCS retention policy, an Elasticsearch key with only `create_doc`, Kafka `cleanup.policy=delete` (never compaction). | [audit-verify.md](../audit-verify.md#what-a-chain-does-not-prove) |
| Chains are verified on a schedule, anchored on the previous head. | Missing records at the end are only visible against a head recorded elsewhere. | A scheduled `haltsql audit verify --json --expect-head "$(cat last-head)" ...` exits 0. | [audit-verify.md](../audit-verify.md) |
| No two processes write the same audit file or spool directory. | Each process seals its own chain; two writers on one file fork it. | One file sink path per replica (no shared volume path). | [high-availability.md](high-availability.md#what-state-a-server-holds) |
| `log_raw_sql` is a deliberate decision. | Raw SQL can contain sensitive literals; without it, shadow reports cannot name the denied objects. | `audit.log_raw_sql` is `false` unless your data allows it. | [shadow-reports.md](../shadow-reports.md#raw-sql-and-detail) |

## Metrics and alerts

Scrape `/metrics` (`telemetry.metrics.prometheus`, on by default) or export
over OTLP (`telemetry.otlp`). These alerts use metrics that `haltsql-server`
exposes today:

| Alert on | Meaning |
|---|---|
| any increase of `haltsql_reasons_total{code="E_INTERNAL"}` | An analyzer bug. The query was denied. File a bug. |
| `rate(haltsql_audit_errors_total[5m]) > 0` | An audit sink is failing. With `fail_closed`, requests are being refused. |
| `haltsql_audit_sink_healthy == 0` or `haltsql_audit_stream_sink_healthy == 0` | A cloud or streaming audit sink refuses writes; `/readyz` is 503. |
| `rate(haltsql_audit_stream_sink_records_dropped_total[5m]) > 0` | Records were dropped (mapping error, too large, or `on_error: drop`). |
| any increase of `haltsql_policy_reload_total{result="error"}` | A reload was rejected; the last good configuration is still active. |
| `haltsql_bundle_source_healthy == 0` | The last poll of a bundle source failed; the last good bundle is still active. |
| any increase of `haltsql_tls_reload_total{result="error"}` | New certificate material was refused; the previous material is still in use. |
| any increase of `haltsql_auth_total{result="unavailable"}` | OIDC signing keys could not be fetched; callers get `503 AUTH_UNAVAILABLE`. |
| any increase of `haltsql_opa_decisions_total{outcome="error_denied"}` | OPA could not answer and `on_error: deny` denied the query. |
| `haltsql_policies_loaded` lower than expected | A policy is missing; its callers get `503 POLICY_UNAVAILABLE`. |
| `histogram_quantile(0.99, rate(haltsql_verify_duration_seconds_bucket[5m])) > 0.05` | Verification is slower than expected (threshold from [observability.md](../observability.md#recommended-alerts)). |

`haltsql-proxy` has no metrics endpoint. Alert on its stderr log lines
(`audit sink write failed; refusing the statement`,
`config reload failed; keeping the current configuration`) and on SQLSTATE
`58030` errors seen by clients. See [proxy.md](../proxy.md#limitations).

## Resource limits and timeouts

| Item | Default | Reference |
|---|---|---|
| Request body cap: `limits.max_request_bytes` or `--max-request-bytes` | 1 MiB | [config-reference.md](../config-reference.md#limits) |
| Open connections: `--max-connections` | 1024 (health listener: its own 64) | [cli.md](../cli.md#haltsql-server) |
| Request head and body: `--request-timeout` | 30 s | [cli.md](../cli.md#haltsql-server) |
| Idle keep-alive and stalled writes: `--idle-timeout` | 60 s | [cli.md](../cli.md#haltsql-server) |
| In-flight requests on `SIGTERM`: `--shutdown-timeout` | 15 s | [cli.md](../cli.md#haltsql-server) |
| SQL size and parse-tree limits per policy: `limits.max_bytes`, `max_depth`, `max_nodes`, `max_joins` | 16384, 64, 20000, 8 | [policy-reference.md](../policy-reference.md#limits) |
| OPA decision timeout: `opa.timeout_ms` | 500 ms | [opa.md](../opa.md#deployment-notes) |
| Proxy: `limits.max_connections`, `max_message_bytes`, `idle_timeout_seconds`, `auth_timeout_seconds`, `upstream.connect_timeout_seconds`, `shutdown_grace_seconds` | 100, 1 MiB, off, 30 s, 10 s, 10 s | [proxy.md](../proxy.md#config-reference) |

Also check:

- The orchestrator's grace period is longer than `--shutdown-timeout` (or the
  proxy's `shutdown_grace_seconds`), so in-flight requests can finish. The
  Helm chart's default `terminationGracePeriodSeconds` is 20.
- Container memory and CPU are set from your own load test. The documented
  benchmarks measure latency and throughput, not memory. See
  [high-availability.md](high-availability.md#sizing).

## Secrets

| Item | Check | Reference |
|---|---|---|
| No secret is written literally in a Config document. | Every credential uses `${env:...}`, `${file:...}`, `${vault:...}`, `${aws-sm:...}` or `${gcp-sm:...}`. | [secrets.md](../secrets.md) |
| `haltsql config show` output is clean. | Run it after every change; secrets show as `"<redacted>"`. | [config-reference.md](../config-reference.md#secrets) |
| Secret files are readable only by the service. | The image runs as uid 65532; the systemd example uses an env file with mode `0640`. | [deployment.md](../deployment.md#systemd) |
| You know which secret changes need a restart. | Rotated provider and file secrets are read on the next reload, but audit sinks, the bundle-source list and `${env:...}` values are fixed for the life of the process. | [runbooks.md](runbooks.md#token-and-credential-rotation) |

## Shadow before enforce

| Item | Check | Reference |
|---|---|---|
| New or stricter policies start in `mode: shadow`. | `haltsql_verify_total{result="shadow_denied"}` and `shadow_reasons` in the audit log show what would be denied. | [deployment.md](../deployment.md#rolling-out-a-policy-change) |
| Shadow results are reviewed before switching. | `haltsql report ... --suggest` or `GET /v1/admin/report`. | [shadow-reports.md](../shadow-reports.md) |
| Shadow is never the only control. | Database role and RLS are in place (see above). | [policy-reference.md](../policy-reference.md#mode) |

## Backups of policies and audit

| What | Where it should live | Notes |
|---|---|---|
| Policy source files and test suites | Version control | The source of truth. `policy.version` in every verdict ties a decision to exact content. |
| Signed bundles and signatures | Your OCI registry, bucket or artifact store, kept by digest or version | Keep old versions: rolling back a bundle source means republishing old content under a higher version. |
| Public signing keys | Version control and server images or ConfigMaps | Safe to commit. |
| Signing private key | Your secret store, with its own backup and access controls | Losing it means rotating to a new key on every server. |
| Audit records | A durable, write-once sink | Retention is set on the destination (Object Lock `retain_days`, bucket retention, ILM, topic retention), not in HaltSQL. |
| Chain heads | Somewhere separate from the audit store | Used with `--expect-head` to detect truncation. |
| Spool directories, bundle `cache_dir` | Persistent volumes | These are working state, not backups. Do not restore an old spool into a running chain. |

## Availability

| Item | Reference |
|---|---|
| At least two replicas of a shared server, with a PodDisruptionBudget. | [high-availability.md](high-availability.md) |
| Readiness on `/readyz`, liveness on `/healthz`. | [http-api.md](../http-api.md#get-readyz) |
| A runbook for "verifier down" exists and has been rehearsed. | [runbooks.md](runbooks.md#verifier-down) |

## Related

- [High availability and scaling](high-availability.md)
- [Upgrades and versioning](upgrades.md)
- [Troubleshooting](troubleshooting.md)
- [Runbooks](runbooks.md)
- [Deployment](../deployment.md)
- [Defense in depth](../defense-in-depth.md)
