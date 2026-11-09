# High availability and scaling

This page is for teams running `haltsql-server` or `haltsql-proxy` where an
outage stops agents from querying. It explains what state each process holds,
how to run replicas behind probes and a load balancer, how to size them from
the published benchmarks, and what clients see when the verifier is down.

## The short version

- Verification is a pure function of the policy, the context and the SQL
  string. `haltsql-server` never connects to the database, and replicas do not
  talk to each other. You can run as many as you need.
- Each process does hold some local state: audit chains, spool and cache
  directories, an in-memory report window. Give each replica its own.
- Clients fail closed. When no verifier answers, queries are not run. Plan
  capacity and probes so that this is rare, and keep it that way: HaltSQL has
  no fail-open switch.

## What state a server holds

| State | Where | Shared between replicas? | What to do |
|---|---|---|---|
| Loaded policies, tokens, OIDC and mTLS settings | Memory, rebuilt from the config on start and reload | No. Each replica loads the same config independently. | Deliver the same config to every replica (ConfigMap, bundle source). |
| Policy bundles from a `bundle_source` | Memory, plus the last accepted bundle in `cache_dir` | No. Each replica polls on its own (`poll_interval_s` ± 10%). | Give each server its own `cache_dir`; do not let two processes poll one source into the same directory. Replicas can briefly run different bundle versions between polls. |
| Audit hash chain, `file` sink | The file. Appending continues the chain from its last record. | Must not be. Two writers on one file fork the chain. | One file per process. A file whose last line is not a sealed record stops the process from starting; rotate it first. |
| Audit hash chain, `stdout` sink | Memory | No | Each process start begins a new chain at genesis (`chain_restart` warning in `haltsql audit verify`). |
| Audit hash chain, `s3`/`gcs` sink | Memory, plus `spool_dir` when set | Must not be. One spool directory per sink. | Object names carry the host and a per-process run id, so replicas never collide in the bucket. Without `spool_dir`, each restart starts a new chain. |
| Audit hash chain, `elasticsearch`/`kafka` sink | Memory only (no spool) | No | Each process starts a new chain; records still queued when the process dies are lost. Pair with a spooled object sink if that matters. |
| OIDC signing keys | Memory cache (`jwks_cache_seconds`) | No | Each replica fetches keys from the IdP. |
| Shadow report window (`GET /v1/admin/report`) | Memory | No | Behind a load balancer each call sees only one replica's verdicts, and the window is lost on restart. Use `haltsql report` over the audit records for a fleet-wide view. |
| Metrics counters | Memory | No | Aggregate across replicas in Prometheus. Counters reset on restart. |

Details: [audit-sinks.md](../audit-sinks.md#restarts-and-chain-continuity),
[policy-bundles.md](../policy-bundles.md#cache),
[shadow-reports.md](../shadow-reports.md#server-endpoint-get-v1adminreport).

`haltsql-proxy` adds per-connection session state: each client session keeps
the configuration snapshot it was accepted under, its prepared statements and
their verdicts, and a mapping from the proxy-issued cancel key to the upstream
backend. That mapping lives in the process that owns the session.

## Health and readiness endpoints

`haltsql-server`:

| Endpoint | Returns | Use for |
|---|---|---|
| `GET /healthz` (also `HEAD`) | `200 {"status":"ok"}` while the process runs. | Liveness. |
| `GET /readyz` (also `HEAD`) | `200 {"status":"ready","policies":N}` when at least one policy is loaded and every audit sink accepts writes. `503` with `"policies":0` when nothing is loaded, with `unhealthy_audit_sinks` when an S3/GCS, Elasticsearch/OpenSearch or Kafka sink refuses writes, and with `"draining": true` during shutdown. | Readiness and load-balancer health checks. |

- A failed hot reload does not make the server unready: the last good
  policies stay active.
- A `file` or `stdout` sink that fails in `fail_closed` mode does not turn
  `/readyz` to 503. Each request retries the write and gets
  `503 AUDIT_UNAVAILABLE` while it fails. Watch `haltsql_audit_errors_total`.
- With `server.tls.client_auth: required`, serve probes on a separate plain
  port with `--health-listen HOST:PORT`. It has its own connection budget (64),
  so probes keep working while the main listener is saturated.
- The image has no `HEALTHCHECK` (no shell or curl). Use orchestrator probes.

`haltsql-proxy` has no HTTP health or metrics endpoint. Use a TCP check on the
listen port, and its logs. See [proxy.md](../proxy.md#limitations).

Reference: [http-api.md](../http-api.md#get-healthz),
[deployment.md](../deployment.md#what-is-in-the-image).

## Sidecar or shared service

| | Sidecar (one server per agent pod, on `127.0.0.1`) | Shared service (replicas behind a load balancer) |
|---|---|---|
| Failure domain | One agent pod. A crash affects only that pod's queries. | Every agent that uses it. Needs replicas, a PDB and spread across zones. |
| Network | Loopback. No TLS needed inside the pod (tokens still required). | Crosses the network. Needs TLS (`server.tls` or a mesh) and an internal load balancer. |
| Scaling | Scales with the agent's replicas automatically. | Scale replicas (or an HPA) to total traffic. |
| Policy rollout | Every agent pod must be rolled or reloaded. | Fewer processes to update. |
| Audit | One chain per agent pod. | One chain per server replica. |
| Overhead | One process per agent pod. | Shared. |

[deployment.md](../deployment.md) recommends the sidecar for most cases and
the shared service when many agents need central policy management.
`haltsql-proxy` is a third option when the agent's driver cannot be changed
([proxy.md](../proxy.md)).

## Running replicas of a shared server

The Helm chart (`deploy/helm/haltsql`) already sets most of this up:

| Concern | What the chart does | Value |
|---|---|---|
| Replicas | 2 by default | `replicaCount` |
| Spread | Soft zone spread and soft node anti-affinity | `topologySpread`, `podAntiAffinityPreset` |
| Disruptions | PodDisruptionBudget (`minAvailable: 1`) when at least 2 replicas run | `podDisruptionBudget.*` |
| Rolling update | `maxUnavailable: 0`, so a ready pod is not removed before its replacement is ready | built in |
| Autoscaling | Optional HPA on CPU (target 70%) | `autoscaling.*` |
| Probes | startup and liveness on `/healthz`, readiness on `/readyz` | `startupProbe`, `livenessProbe`, `readinessProbe` |
| Shutdown | `terminationGracePeriodSeconds: 20`; optional `preStop` sleep | `terminationGracePeriodSeconds`, `preStopSleepSeconds` |
| Priority | Unset | `priorityClassName`. The chart README recommends a high class, because callers fail closed while HaltSQL is unavailable. |
| CPU limit | None by default, to avoid throttling on the verify path | `resources` |

The [Kubernetes operator](../kubernetes-operator.md) creates a Deployment with
`maxUnavailable: 0` and `maxSurge: 1`, and an optional PodDisruptionBudget.
It turns `reload.watch` off and delivers every change as a rollout, so all
replicas switch together.

Reference: [Helm chart README](../../deploy/helm/haltsql/README.md#availability-and-scheduling).

### Load balancing

- `POST /v1/verify` requests are independent. Any replica can answer any
  request, so no session affinity is needed.
- Clients use HTTP/1.1 keep-alive. A long-lived connection stays on one
  replica, so new replicas only receive traffic as clients open new
  connections. On shutdown the server sends `connection: close`, which moves
  clients off a draining replica.
- Health-check the load balancer target on `/readyz`.
- For `haltsql-proxy`, use a TCP load balancer. A PostgreSQL cancel request
  only works if it reaches the proxy process that owns the session, because
  the cancel-key mapping is per process. Rely on `statement_timeout` in the
  database rather than client-side cancel through a load balancer.

## Sizing

Every number below comes from [performance.md](../performance.md): one run on
one Apple M1 Max that was not idle. Treat it as a data point and run
`scripts/bench.sh` on your own hardware before you plan capacity.

| Measured | Value |
|---|---|
| `haltsql-server` throughput, one instance | levels off at about 4.5k requests/s; one event loop, one core |
| `haltsql-server` p50 on one connection | 278 µs (file audit sink) |
| `haltsql-server` p50 at 32 connections | 6,847 µs (queueing: the instance is saturated) |
| Cost of the file audit sink | about 10% of throughput at 32 connections |
| `haltsql-proxy` throughput, one instance | about 6k statements/s on one core |
| `haltsql-proxy` added latency | about 0.25–0.3 ms per statement at p50, plus about 5 µs per result row |
| Library verify (in process) | 48 µs (point lookup) to 247 µs (multi-CTE report) at p50 |

What this means for sizing:

- **Scale out, not up.** One server instance verifies on one event loop, so
  in the benchmark more connections only added queueing latency once it
  reached about 4.5k requests/s. Add replicas rather than cores per instance.
  performance.md suggests one core per ~4k verifies/s of similar traffic.
- **Stay well below saturation if p99 matters.** At saturation, latency grows
  with queue depth (Little's law: 32 connections / 4.2k/s ≈ 7.6 ms).
- **Query complexity, not policy size, drives cost.** Heavier agent queries
  (joins, CTEs, window functions) lower the per-instance ceiling. Benchmark
  with queries like yours.
- **Plan for losing a replica.** For example, if your measured per-instance
  ceiling were 4.5k/s and peak traffic 9k/s, two replicas would both run at
  saturation; you would want more, plus one to cover a failure or a rollout.
  Replace these numbers with your own measurements.
- **Memory is not measured.** The deployment examples use requests of
  32–64 MiB and limits of 128–256 MiB, but no published benchmark measures
  memory. Watch container memory under your own load.

## Graceful shutdown

`haltsql-server` on `SIGTERM` or `SIGINT`:

1. The listeners close. `/readyz` answers 503 with `"draining": true` on
   connections that are still open, and every response carries
   `connection: close`.
2. Idle keep-alive connections are closed.
3. In-flight requests get `--shutdown-timeout` seconds (default 15) to
   finish. After that, remaining connections are closed (logged as
   `shutdown timeout reached; closing remaining connections`).
4. Batching audit sinks (S3/GCS, Elasticsearch, Kafka) and the OTLP exporter
   are flushed. The process exits 0.

Because the listener closes at once, a load balancer that has not yet removed
the replica will see refused connections for a moment. In Kubernetes, give
endpoints time to update before the signal with a `preStop` sleep (Helm:
`preStopSleepSeconds`, which must be lower than
`terminationGracePeriodSeconds`), and keep the grace period longer than
`--shutdown-timeout`. Clients retry connection errors (see below), so a short
gap is normally absorbed by the retry.

`haltsql-proxy` on `SIGTERM` or `SIGINT` stops accepting, lets sessions run for
`shutdown_grace_seconds` (default 10), closes the rest, flushes its audit
sinks and exits 0. Clients see their connection closed and must reconnect.

## Hot reload

Reloading does not drop connections on either component.

| | `haltsql-server` | `haltsql-proxy` |
|---|---|---|
| Triggers | `SIGHUP`; file watch (`reload.watch`, polled every 2 s); a new bundle from a bundle source | `SIGHUP`; `reload.watch` (`reload.poll_interval_seconds`, default 2) |
| Atomicity | All policies, tokens, OIDC, mTLS, OPA, admin settings and TLS material are swapped together, or nothing changes. | New connections get the new config; existing sessions keep their snapshot until they close. |
| On error | `reload failed; keeping the last good configuration`, `haltsql_policy_reload_total{result="error"}` | `config reload failed; keeping the current configuration` |
| Needs a restart | listen address, health listener, turning TLS on or off, `audit` sinks, the list of `bundle_source` entries, `limits`, `logging`, `telemetry.metrics.prometheus` | listen address, audit sinks |

Notes:

- The server watches the config file, policy and bundle files and TLS files.
  It does not watch files referenced only through `${file:...}`, such as a
  token hash file. Send `SIGHUP` after changing those.
- In Kubernetes, ConfigMap files mounted with `subPath` are not updated in
  running pods. Mount the whole ConfigMap as a directory if you rely on
  `reload.watch`, or roll the deployment.
- During a file-watch rollout, replicas pick up a change at slightly different
  times. For changes that must apply everywhere at once, roll the deployment
  instead (the operator always does).

Reference: [config-reference.md](../config-reference.md#reload),
[proxy.md](../proxy.md#hot-reload).

## When the verifier is unavailable

HaltSQL is designed so that an outage denies queries instead of letting them
through.

**What the server returns.** These are HTTP errors, not verdicts. Clients
must treat them as denials:

| Response | Cause |
|---|---|
| connection refused, reset or timeout | The process is down, restarting, or saturated past `--max-connections` (new connections wait in the listen backlog). |
| `503 NOT_READY` | No policy is loaded. |
| `503 POLICY_UNAVAILABLE` | The caller's pinned policy is not loaded. |
| `503 AUDIT_UNAVAILABLE` | A `fail_closed` audit sink cannot be written. |
| `503 AUTH_UNAVAILABLE` (with `Retry-After`) | The OIDC provider's keys cannot be fetched and no usable cached keys remain. |

**What the official SDKs do.** They retry, then fail closed:

| | Python | TypeScript | Go | Java |
|---|---|---|---|---|
| Timeout per attempt | 2 s | 5 s | 5 s | 5 s |
| Retries after the first attempt | 2 | 2 | 2 | 2 |
| Retried on | connection errors, timeouts, 502/503/504 | network errors, timeouts, 503 | connection errors, timeouts, 503 | connection errors, timeouts, 503 |

Backoff is exponential with jitter and capped (also capping `Retry-After`).
After the last attempt the SDK raises an error and the query is not run. With
default settings, a call against a verifier that never answers takes roughly
three timeouts plus backoff before the agent sees the error. See
[integrations.md](../integrations.md#official-clients) and the SDK pages for
the exact options.

**What the proxy does.** A statement that cannot be audited under
`fail_closed` is refused with SQLSTATE `58030`
(`PROXY_AUDIT_UNAVAILABLE`); the connection stays usable. When the proxy
process is down, clients cannot connect at all.

**What the agent sees.** An error instead of rows. Make sure your agent
framework reports it as an infrastructure failure, not as a policy denial the
model should try to work around, and caps its retries.

For the response procedure, see [runbooks.md](runbooks.md#verifier-down).

## Dependencies that affect availability

| Dependency | Effect when it fails | Mitigation |
|---|---|---|
| Bundle source (OCI, S3, HTTPS) | Running servers keep the last good bundle. A restarting server starts from `cache_dir`; with no cache it fails to start. | Persistent `cache_dir`; alert on `haltsql_bundle_source_healthy == 0`. |
| OIDC provider | Cached keys stay usable for at most `min(jwks_cache_seconds, 3600)` seconds past expiry; then `503 AUTH_UNAVAILABLE` for that provider. | Alert on `haltsql_auth_total{result="unavailable"}`. |
| Audit sink destination | `fail_closed`: requests refused once the sink is unhealthy. `buffer`: requests continue until the bound, then refused. | See [runbooks.md](runbooks.md#audit-sink-outage). |
| OPA (optional) | `on_error: deny` denies every query HaltSQL allowed; `allow_haltsql_verdict` keeps HaltSQL's verdict. | Run OPA as a sidecar on `127.0.0.1` with a small `timeout_ms`. |
| Secret providers (Vault, AWS, GCP) | A placeholder that cannot be resolved fails startup, or rejects the reload (the last good config stays). | Restart only when the provider is reachable. |
| OTLP collector | None on verification: spans are dropped and counted. | `haltsql_otlp_spans_dropped_total`. |

## Related

- [Production checklist](production-checklist.md)
- [Runbooks](runbooks.md)
- [Troubleshooting](troubleshooting.md)
- [Deployment](../deployment.md)
- [Performance](../performance.md)
- [Audit sinks](../audit-sinks.md)
