# Deploying haltsql-server

`haltsql-server` is a stateless HTTP service. It never connects to a database.
It makes outbound calls only for features you turn on: OIDC/JWKS discovery,
secret providers (Vault, AWS Secrets Manager, GCP Secret Manager), S3/GCS audit
sinks and OTLP export. Every replica loads the same policies and answers
`POST /v1/verify`. This directory has:

| Path | What it is |
|---|---|
| `../Dockerfile` | Multi-stage image: static musl binaries on `distroless/static:nonroot` (uid 65532). |
| `helm/haltsql/` | Helm chart: Deployment, Service, ConfigMaps (config + policies), Secret (token hashes), PDB, HPA, NetworkPolicy, ServiceMonitor, ServiceAccount. |
| `operator/` | Kubernetes operator (Go, API `haltsql.dev/v1alpha1`): `HaltSQLPolicy` and `HaltSQLServer` CRDs reconciled into policy ConfigMaps and a haltsql-server Deployment. See [docs/kubernetes-operator.md](../docs/kubernetes-operator.md). |
| `k8s/sidecar-example.yaml` | haltsql as a sidecar next to an agent, reached over `127.0.0.1`. |
| `systemd/haltsql-server.service` | Hardened unit for VMs and bare metal. |
| `cloud/aws/`, `cloud/gcp/`, `cloud/azure/` | Reference manifests and IAM for each cloud. Guides: [AWS](../docs/deploy-aws.md), [Google Cloud](../docs/deploy-gcp.md), [Azure](../docs/deploy-azure.md). |
| `diagrams/` | Cloud architecture diagrams as code ([mingrammer/diagrams](https://github.com/mingrammer/diagrams)); `make diagrams` regenerates `docs/assets/cloud/`. |

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

- `SIGTERM` / `SIGINT`: the server stops accepting connections, `/readyz`
  returns `503` with `"draining": true`, idle keep-alive connections are
  closed, and in-flight requests get up to `--shutdown-timeout` (default 15 s)
  to finish (their responses carry `Connection: close`). Then it exits `0`.
  The chart sets `terminationGracePeriodSeconds: 20`; keep it above the
  shutdown timeout.
- Connection limits: `--max-connections` (default 1024),
  `--request-timeout` (30 s), `--idle-timeout` (60 s) and a 64 KiB cap on
  request heads protect against slow or abusive clients. The
  `haltsql_http_open_connections` gauge shows current usage.
- `SIGHUP`: reloads the config file's policies and the `--policy` files (and
  the token list from the config file). The swap is atomic: if **any** policy
  fails to load, nothing changes, the errors are logged and
  `haltsql_policy_reload_total{result="error"}` goes up. With
  `reload.watch: true` (or `--watch`) the server also polls the files every 2
  seconds. Kubernetes ConfigMap updates are picked up this way when the
  ConfigMap is mounted as a directory (not with `subPath`).
- Startup fails with exit code `2` if the config or any policy cannot be
  loaded, the listen address cannot be bound, or the TLS certificate/key
  cannot be read or do not match (below).

## TLS

`haltsql-server` has built-in TLS (`server.tls`): TLS 1.2/1.3 with ECDHE +
AEAD ciphers only, optional or required client certificates verified against
`server.tls.client_ca`, and certificate rotation on `SIGHUP` or file change
(the previous certificate stays active if the new one is broken). See
[docs/authentication.md](../docs/authentication.md).

```yaml
server:
  listen: 0.0.0.0:8443
  tls:
    cert: /etc/haltsql/tls/tls.crt
    key: /etc/haltsql/tls/tls.key
    client_ca: /etc/haltsql/tls/ca.crt
    client_auth: required
    min_version: "1.3"
```

With `client_auth: required`, start the server with
`--health-listen 0.0.0.0:8081` so kubelet probes can reach `/healthz` and
`/readyz` over plain HTTP (nothing else is served there). The Helm chart does
this automatically when `tls.enabled` is set:

```sh
helm install haltsql deploy/helm/haltsql \
  --set tls.enabled=true --set tls.secretName=haltsql-tls \
  --set tls.clientAuth=required --set tls.minVersion=1.3
```

`tls.secretName` is a `kubernetes.io/tls` Secret (for example from
cert-manager) with `tls.crt`, `tls.key` and, for client certificates,
`ca.crt`. It is mounted as a directory, so rotations are picked up by
`reload.watch` without restarting pods.

Alternatives that remain fully supported:

1. **Sidecar on loopback**: run haltsql in the same pod as the agent and call
   `http://127.0.0.1:8080`. Traffic never leaves the pod. See
   `k8s/sidecar-example.yaml`.
2. **Service mesh**: Istio, Linkerd or Consul provide mTLS between the agent
   and the haltsql Service. Keep the chart's NetworkPolicy so only the mesh
   reaches the pods.
3. **Reverse proxy**: Envoy, nginx or HAProxy terminates TLS and forwards to
   haltsql on `127.0.0.1`.

## Authentication

Besides static tokens (below), callers can authenticate with OIDC access
tokens (`server.auth.oidc`; Helm value `oidc`) or with client certificates
mapped to identities (`server.auth.mtls`; Helm value `mtlsIdentities`). Both
pin the policy and supply the tenant context from the identity, so the
request body cannot change it. See
[docs/authentication.md](../docs/authentication.md).

Static-token callers send `Authorization: Bearer <token>`. The server stores only the
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
- `extraPolicies` is a list of Config `policies[]` entries appended to the
  rendered `policies` (for example `bundle_source` entries pulling signed
  bundles from an OCI registry, S3 or HTTPS). A `bundle_source` entry without
  `cache_dir` gets `<cache.mountPath>/bundles`.
- `extraConfig` is a map deep-merged into the rendered Config document:
  nested maps merge key by key and `extraConfig` wins; lists and scalars
  replace the rendered value. Use it for settings the chart has no value for
  (`telemetry.otlp`, `secrets`, `opa`, `server.admin`, ...). `policies` is
  refused there (use `extraPolicies`), and the server still validates the
  merged document at startup, so an unknown key fails closed.
- `cache` is a writable volume for bundle-source caches (the root filesystem
  is read-only), mounted at `cache.mountPath` (default `/var/cache/haltsql`).
  The default `emptyDir` survives container restarts but not rescheduling;
  to keep the cache across rescheduling, replace it with exactly one other
  volume source, e.g.
  `--set cache.volume.emptyDir=null --set cache.volume.persistentVolumeClaim.claimName=haltsql-cache`.
- Outbound features (bundle sources, OIDC, Kafka/Elasticsearch sinks, OPA)
  need egress, which the chart's NetworkPolicy denies: allow it explicitly or
  disable `networkPolicy`.

## systemd

`systemd/haltsql-server.service` runs the static binary with `DynamicUser`,
`ProtectSystem=strict`, `NoNewPrivileges`, an empty capability set, a
syscall filter, and `IPAddressAllow=localhost`. `systemctl reload` sends
`SIGHUP`. Write audit files under `/var/log/haltsql` (`LogsDirectory`).
