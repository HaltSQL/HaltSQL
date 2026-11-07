# Deploying haltsql-server

`haltsql-server` is a stateless HTTP service. It never connects to a database
or makes outbound network calls. Every replica loads the same policies and
answers `POST /v1/verify`. This directory has:

| Path | What it is |
|---|---|
| `../Dockerfile` | Multi-stage image: static musl binaries on `distroless/static:nonroot` (uid 65532). |
| `helm/haltsql/` | Helm chart: Deployment, Service, ConfigMaps (config + policies), Secret (token hashes), PDB, HPA, NetworkPolicy, ServiceMonitor, ServiceAccount. |
| `k8s/sidecar-example.yaml` | haltsql as a sidecar next to an agent, reached over `127.0.0.1`. |
| `systemd/haltsql-server.service` | Hardened unit for VMs and bare metal. |

## Container image

```sh
docker build -t haltsql:dev .
docker run --rm -p 8080:8080 -v "$PWD/examples:/etc/haltsql:ro" haltsql:dev \
  --policy /etc/haltsql/policies/saas.yaml --allow-unauthenticated
```

- The entrypoint is `haltsql-server`. The default command is
  `--config /etc/haltsql/config.yaml`. The `haltsql` CLI is also in the image
  at `/usr/local/bin/haltsql`.
- `HALTSQL_LISTEN=0.0.0.0:8080` is set in the image because a container must
  listen on all interfaces. Because environment variables rank above the
  config file (flags > `HALTSQL_*` env > config file > defaults),
  `server.listen` in a config file has no effect inside the image. To change
  the address, pass `--listen` or set `HALTSQL_LISTEN`.
- The image is distroless, so it has no shell, no curl and no `HEALTHCHECK`.
  Use your orchestrator's HTTP probes (see the next section).
- Static linking is opt-in for local builds:
  `HALTSQL_STATIC=1 dune build --profile release ./bin` (needs musl, for
  example on Alpine). The default build is dynamic.

## Probes and lifecycle

| Endpoint | Use | Behavior |
|---|---|---|
| `GET /healthz` | liveness | `200` while the process is up. |
| `GET /readyz` | readiness | `200` once at least one policy is loaded, otherwise `503`. A failed hot reload does **not** make a pod unready: the last good policies stay active. |
| `GET /metrics` | Prometheus | Disable with `telemetry.metrics.prometheus: false` or `--no-metrics`. |

- `SIGTERM` / `SIGINT`: the server stops accepting connections, lets in-flight
  responses finish, and exits `0`. The chart sets
  `terminationGracePeriodSeconds: 20`.
- `SIGHUP`: reloads the config file's policies and the `--policy` files (and
  the token list from the config file). The swap is atomic: if **any** policy
  fails to load, nothing changes, the errors are logged and
  `haltsql_policy_reload_total{result="error"}` goes up. With
  `reload.watch: true` (or `--watch`) the server also polls the files every 2
  seconds. Kubernetes ConfigMap updates are picked up this way when the
  ConfigMap is mounted as a directory (not with `subPath`).
- Startup fails with exit code `2` if the config or any policy cannot be
  loaded, the listen address cannot be bound, or TLS is configured (below).

## TLS: terminate it in front of haltsql

This build of `haltsql-server` has **no TLS support**: the OCaml TLS stack is
not part of the dependency set yet. If `server.tls.cert` or `server.tls.key`
is set, the server **refuses to start** with an error, instead of silently
serving plain HTTP. Supported setups:

1. **Sidecar on loopback** (recommended): run haltsql in the same pod as the
   agent and call `http://127.0.0.1:8080`. Traffic never leaves the pod. See
   `k8s/sidecar-example.yaml`.
2. **Service mesh**: Istio, Linkerd or Consul provide mTLS between the agent
   and the haltsql Service. Keep the chart's NetworkPolicy so only the mesh
   reaches the pods.
3. **Reverse proxy**: Envoy, nginx or HAProxy terminates TLS (and optionally
   mTLS) and forwards to haltsql on `127.0.0.1`.

## Authentication

Callers send `Authorization: Bearer <token>`. The server stores only the
lower-case hex SHA-256 of each token and compares hashes in constant time.
Each token is pinned to one policy. A request that names another policy gets
`403`.

```sh
TOKEN="$(openssl rand -hex 32)"                       # give this to the agent
printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1      # goes in token_sha256
```

`allow_unauthenticated` / `--allow-unauthenticated` lets requests without a
token use `default_policy` (or the only loaded policy). It is for local
development only. An *invalid* token is still rejected with `401`.

## HTTP behavior summary

| Status | `error.code` | When |
|---|---|---|
| `200` | | Verdict JSON, for both allowed and denied SQL. |
| `400` | `BAD_REQUEST` | Body is not a JSON object, `sql` is missing or not a string, `context` is not an object or has invalid values, `policy` is not a string, or there are unknown fields. |
| `401` | `UNAUTHORIZED` | Missing token (unless unauthenticated mode is on), unknown token, or a non-Bearer scheme. |
| `403` | `FORBIDDEN` | `policy` differs from the token's pinned policy. |
| `404` | `POLICY_NOT_FOUND` / `NOT_FOUND` | Unknown policy (unauthenticated mode), no default policy, or an unknown route. |
| `405` | `METHOD_NOT_ALLOWED` | Wrong method on a known route (an `Allow` header is sent). |
| `413` | `PAYLOAD_TOO_LARGE` | Body exceeds `limits.max_request_bytes` (default 1 MiB). |
| `503` | `NOT_READY` / `POLICY_UNAVAILABLE` / `AUDIT_UNAVAILABLE` | No policy loaded; the token's pinned policy is not loaded; an audit sink write failed (see below). |

Every response carries `X-Request-Id`. A caller-supplied `X-Request-Id`
(1 to 128 characters from `[A-Za-z0-9._:-]`) is echoed back. Otherwise a UUID v4
is generated. Clients must treat any non-200 response as a denial.

## Audit log

Each `POST /v1/verify` that reaches the verifier writes one JSON line to every
configured sink (`stdout`, or an append-only file):

```json
{"ts":"2026-11-07T21:38:02.916Z","request_id":"…","caller":"analytics-agent","policy":"shop",
 "policy_version":"sha256:…","allowed":true,"shadow":false,"codes":[],"sql_sha256":"…",
 "fingerprint":"…","elapsed_us":250,"prev_hash":"000…000","hash":"b124…"}
```

- `sql` (the raw SQL) is added before `prev_hash` only with
  `audit.log_raw_sql: true` / `--log-raw-sql`.
- **Hash chain:** `hash = sha256_hex(prev_hash ++ L)`, where `L` is the
  compact JSON of the record without its `hash` field, with keys in the order
  written. The first record has `prev_hash` = 64 zeros. When the server
  restarts with an existing audit file, it continues that file's chain from
  its last record. Each sink has its own chain. Editing, reordering or
  deleting a record breaks the chain at that point.
  `Haltsql_server.Audit.verify_file` implements the check, and
  `test/server` exercises it.
- **Fail closed:** if a sink write fails (disk full, permissions), the request
  gets `503 AUDIT_UNAVAILABLE` instead of a verdict. The failure is logged to
  stderr and counted in `haltsql_audit_errors_total`. This is not
  configurable yet.
- Ship rotated files whole. Rotation starts a new file. To verify a rotated
  file on its own, anchor its first `prev_hash` to the previous file's last
  `hash`.

## Metrics

| Metric | Labels |
|---|---|
| `haltsql_verify_total` | `policy`, `result` = `allowed` \| `denied` \| `shadow_denied` |
| `haltsql_reasons_total` | `code` (denial and shadow-denial reasons) |
| `haltsql_verify_duration_seconds` | histogram, buckets 100µs to 1s |
| `haltsql_policy_reload_total` | `result` = `success` \| `error` |
| `haltsql_build_info` | `version`, `pg` |
| `haltsql_policies_loaded` | |
| `haltsql_audit_errors_total` | |
| `haltsql_http_requests_total` | `route`, `status` |

Suggested alerts: any increase of `haltsql_reasons_total{code="E_INTERNAL"}`,
`haltsql_policy_reload_total{result="error"}` or `haltsql_audit_errors_total`.

## Logs

Logs go to stderr as JSON lines (`logging.format: json`) or as text, filtered by
`logging.level`. Each request is logged at `info` with its request id, method,
path, status and duration. Probe and metrics requests are logged at `debug`.

## Helm

```sh
helm install haltsql deploy/helm/haltsql \
  --set-file 'policies.analytics-agent\.yaml=policies/analytics-agent.yaml' \
  --set 'tokens[0].name=analytics-agent' \
  --set 'tokens[0].sha256=<hex sha256 of the token>' \
  --set 'tokens[0].policy=analytics-agent'
```

- Token hashes go into a Secret and reach the config through
  `${env:HALTSQL_TOKEN_<i>_SHA256}` placeholders. To manage the Secret
  yourself, use `existingTokenSecret`. The chart refuses values that are not
  64-character hex digests, which guards against pasting a raw token.
- Policies go into a ConfigMap mounted at `/etc/haltsql/policies`.
  `reload.watch` is on by default, so a `helm upgrade` that changes only
  policies is hot-reloaded without restarting pods. Config or token changes
  roll the pods through checksum annotations.
- Security defaults: `runAsNonRoot`, uid/gid 65532, `readOnlyRootFilesystem`,
  all capabilities dropped, `seccompProfile: RuntimeDefault`, no service
  account token. The NetworkPolicy allows ingress only on the HTTP port, and
  denies all egress.
- `serviceMonitor.enabled=true` requires the Prometheus Operator CRDs.

## systemd

`systemd/haltsql-server.service` runs the static binary with `DynamicUser`,
`ProtectSystem=strict`, `NoNewPrivileges`, an empty capability set, a
syscall filter, and `IPAddressAllow=localhost`. `systemctl reload` sends
`SIGHUP`. Write audit files under `/var/log/haltsql` (`LogsDirectory`).
