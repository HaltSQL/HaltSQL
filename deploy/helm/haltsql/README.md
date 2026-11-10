# haltsql Helm chart

Deploys `haltsql-server`, the HaltSQL HTTP policy firewall, as a shared
Service (`POST /v1/verify`, plus `/healthz`, `/readyz` and `/metrics` on the
same port). For a per-pod sidecar see `deploy/k8s/sidecar-example.yaml`.

Requires Kubernetes 1.27 or newer and Helm 3.8 or newer. `values.schema.json`
validates every value, so a typo such as `replicacount` fails at
`helm install` time instead of being silently ignored.

```sh
helm install haltsql oci://ghcr.io/haltsql/charts/haltsql --version 0.0.3 -n haltsql --create-namespace \
  -f my-values.yaml
helm lint deploy/helm/haltsql -f my-values.yaml      # validate values first
```

## Secure defaults

Out of the box the chart:

- runs as uid/gid 65532 with `runAsNonRoot`, `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, every Linux capability dropped and the
  `RuntimeDefault` seccomp profile; only `/tmp` and `/var/log/haltsql` are
  writable (size-limited `emptyDir`s);
- does not mount a service account token and disables service-link env vars;
- requires a bearer token, OIDC or mTLS on every `/v1` call
  (`server.allowUnauthenticated: false`);
- stores only SHA-256 hashes of tokens, in a Secret, injected through
  `${env:...}` placeholders;
- creates a NetworkPolicy that admits traffic only from the release namespace
  and denies all egress (opened automatically for OIDC, see below);
- runs 2 replicas spread across zones (`topologySpread`, soft) and nodes
  (`podAntiAffinityPreset: soft`) with a PodDisruptionBudget and a
  zero-downtime rolling update (`maxUnavailable: 0`);
- rolls pods when the rendered Config or token hashes change
  (`checksum/config`, `checksum/tokens` annotations). Policy edits are
  hot-reloaded in place and do not restart pods.

## Supply chain: pin and verify the image

Release images are multi-arch, carry SBOM and SLSA provenance attestations, and
are signed keylessly with cosign from the release workflow. Pin by digest in
production:

```sh
cosign verify ghcr.io/haltsql/haltsql@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/HaltSQL/HaltSQL/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/haltsql/haltsql@sha256:<digest> \
  --repo HaltSQL/HaltSQL
```

```yaml
image:
  digest: sha256:<digest>   # wins over image.tag
```

## Values

### Image and workload

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `2` | Replicas when autoscaling is off. |
| `revisionHistoryLimit` | `5` | Old ReplicaSets kept for rollback. |
| `image.repository` | `ghcr.io/haltsql/haltsql` | Image repository. |
| `image.tag` | `""` | Tag; defaults to the chart `appVersion`. |
| `image.digest` | `""` | `sha256:...` digest; when set, wins over `tag`. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | `[{name: ...}]` for private mirrors. |
| `nameOverride` / `fullnameOverride` | `""` | Resource naming. |
| `serviceAccount.create` | `true` | Create a dedicated ServiceAccount. |
| `serviceAccount.name` | `""` | Name to create or use. |
| `serviceAccount.annotations` | `{}` | e.g. IRSA (`eks.amazonaws.com/role-arn`) or GKE Workload Identity, for the AWS/GCP secret and audit-sink clients. |
| `serviceAccount.automountServiceAccountToken` | `false` | Set `true` only for Vault's `kubernetes` auth method. |
| `podAnnotations` / `podLabels` | `{}` | Extra pod metadata. |
| `priorityClassName` | `""` | Use a high priority class: callers fail closed while haltsql is unavailable. |
| `runtimeClassName` | `""` | e.g. `gvisor` or `kata` for sandboxed runtimes. |

### haltsql-server configuration

The chart renders a `kind: Config` document into a ConfigMap. See
`docs/config-reference.md` for every key.

| Key | Default | Description |
|---|---|---|
| `server.port` | `8080` | Listen port (all interfaces inside the pod). |
| `server.maxRequestBytes` | `1048576` | `limits.max_request_bytes`. |
| `server.allowUnauthenticated` | `false` | Never enable outside development. |
| `server.defaultPolicy` | `""` | Policy for callers without one. |
| `server.reloadWatch` | `true` | Hot-reload policies, auth and TLS files on change. |
| `server.logLevel` | `info` | `debug`, `info`, `warn` or `error`. |
| `server.logFormat` | `json` | `json` or `text`. |
| `server.metrics` | `true` | Serve Prometheus `/metrics`. |
| `server.audit.sinks` | `[{type: stdout}]` | Audit sinks, rendered verbatim. |
| `server.audit.logRawSql` | `false` | Include raw SQL in audit records. |
| `server.extraConfig` | `{}` | Deep-merged over the rendered Config: `telemetry.otlp`, `secrets.vault`, S3/GCS audit sinks, etc. Remember `networkPolicy.egress`. `policies` is refused (use `extraPolicies`). |
| `extraConfig` | `{}` | Same as `server.extraConfig`, merged after it (this one wins). Nested maps merge key by key; lists and scalars replace the rendered value. `policies` is refused. Used by the Terraform `haltsql-kubernetes` module. |
| `policies` | `{}` | Policy documents keyed by file name; rendered into a ConfigMap. |
| `existingPolicyConfigMap` | `""` | Use your own ConfigMap of policies instead (GitOps, signed bundles). |
| `existingPolicyFiles` | `[]` | Keys of `existingPolicyConfigMap` to load. |
| `extraPolicies` | `[]` | Config `policies[]` entries (`path`, `inline`, `bundle` or `bundle_source`) appended to the rendered ones. A `bundle_source` entry without `cache_dir` gets `<cache.mountPath>/bundles`. Put credentials in `${env:...}` placeholders (with `extraEnv`), never inline. |
| `cache.mountPath` | `/var/cache/haltsql` | Writable mount for bundle-source caches (the root filesystem is read-only). |
| `cache.volume` | `{emptyDir: {sizeLimit: 256Mi}}` | Any single pod volume source. The emptyDir survives container restarts, not rescheduling; to keep the cache across rescheduling use e.g. `{emptyDir: null, persistentVolumeClaim: {claimName: haltsql-cache}}`. |

### Authentication and secrets

| Key | Default | Description |
|---|---|---|
| `tokens` | `[]` | `[{name, sha256, policy}]`. `sha256` must be a 64-hex digest (`printf '%s' "$TOKEN" \| sha256sum`); the chart refuses anything else. |
| `existingTokenSecret` | `""` | Use an existing Secret (External Secrets, Sealed Secrets, Vault Agent) with keys `HALTSQL_TOKEN_<INDEX>_SHA256`, 0-based in `tokens` order. `tokens` still supplies names and policies. Pods do not roll when an external Secret changes; use a reloader or bump `podAnnotations`. |
| `oidc` | `[]` | `server.auth.oidc` providers, rendered verbatim. |
| `mtlsIdentities` | `[]` | `server.auth.mtls.identities`; needs `tls.enabled` and `tls.clientAuth` `optional`/`required`. |
| `tls.enabled` | `false` | Built-in TLS. Probes move to a plain-HTTP health port. |
| `tls.secretName` | `""` | `kubernetes.io/tls` Secret (`tls.crt`, `tls.key`, optional `ca.crt`); required with TLS. |
| `tls.clientAuth` | `none` | `none`, `optional` or `required`. |
| `tls.minVersion` | `"1.2"` | `"1.2"` or `"1.3"`. |
| `tls.healthPort` | `8081` | Plain-HTTP port for `/healthz` and `/readyz` with TLS on. |

### Container extension points

| Key | Default | Description |
|---|---|---|
| `extraArgs` | `[]` | Appended to the `haltsql-server` command line. |
| `extraEnv` | `[]` | Extra `env` entries (`value` or `valueFrom`). |
| `extraEnvFrom` | `[]` | Extra `envFrom` sources (e.g. cloud credentials Secret). |
| `extraVolumes` | `[]` | Extra pod volumes. |
| `extraVolumeMounts` | `[]` | Extra mounts in the haltsql container. |
| `initContainers` | `[]` | Init containers. |
| `extraContainers` | `[]` | Sidecars, e.g. a log shipper for a file audit sink. |

### Service

| Key | Default | Description |
|---|---|---|
| `service.type` | `ClusterIP` | `ClusterIP`, `NodePort` or `LoadBalancer`. |
| `service.port` | `8080` | Service port. |
| `service.nodePort` | `null` | Fixed node port (NodePort/LoadBalancer). |
| `service.annotations` | `{}` | Cloud LB annotations, e.g. `service.beta.kubernetes.io/aws-load-balancer-scheme: internal`, `networking.gke.io/load-balancer-type: Internal`, `service.beta.kubernetes.io/azure-load-balancer-internal: "true"`. |
| `service.labels` | `{}` | Extra Service labels. |
| `service.loadBalancerClass` | `""` | LoadBalancer implementation. |
| `service.loadBalancerSourceRanges` | `[]` | Restrict LB clients by CIDR. |
| `service.externalTrafficPolicy` | `""` | `Cluster` or `Local` (keeps client IPs). |
| `service.internalTrafficPolicy` | `""` | `Cluster` or `Local`. |

Expose haltsql outside the cluster only with `tls.enabled` (or TLS terminated
in front) and an internal load balancer.

### Security context and resources

| Key | Default | Description |
|---|---|---|
| `podSecurityContext` | non-root 65532, `fsGroup` 65532, `RuntimeDefault` seccomp | Pod security context. |
| `securityContext` | read-only rootfs, no privilege escalation, `drop: [ALL]`, `RuntimeDefault` seccomp | Container security context; meets the Pod Security Standards `restricted` profile. |
| `resources` | requests `100m` / `64Mi`, limit `256Mi` memory | No CPU limit by default, to avoid throttling on the verify path. |

### Probes and lifecycle

| Key | Default | Description |
|---|---|---|
| `startupProbe` | `/healthz`, every 2s, 30 failures | Allows up to 60s for the first policy load before liveness applies. |
| `livenessProbe` | `/healthz`, every 10s | |
| `readinessProbe` | `/readyz`, every 5s | `/readyz` returns 503 until policies are loaded. |
| `*.enabled` | `true` | Disable a probe. Any standard probe field may be set. |
| `preStopSleepSeconds` | `0` | `lifecycle.preStop.sleep` (Kubernetes 1.30+) so endpoints drain before shutdown; e.g. `5`. |
| `terminationGracePeriodSeconds` | `20` | |

With `tls.enabled`, `httpGet` probes are pointed at the `health` port
automatically.

### Availability and scheduling

| Key | Default | Description |
|---|---|---|
| `podDisruptionBudget.enabled` | `true` | Created only when at least 2 replicas run. |
| `podDisruptionBudget.minAvailable` | `1` | |
| `podDisruptionBudget.maxUnavailable` | `null` | Wins over `minAvailable` when set. |
| `podDisruptionBudget.unhealthyPodEvictionPolicy` | `""` | `IfHealthyBudget` or `AlwaysAllow`. |
| `autoscaling.enabled` | `false` | HorizontalPodAutoscaler (autoscaling/v2). |
| `autoscaling.minReplicas` / `maxReplicas` | `2` / `10` | |
| `autoscaling.targetCPUUtilizationPercentage` | `70` | Needs `resources.requests.cpu`. |
| `autoscaling.targetMemoryUtilizationPercentage` | `null` | Needs `resources.requests.memory`. |
| `autoscaling.behavior` | `{}` | HPA scaling behavior, verbatim. |
| `nodeSelector` / `tolerations` | `{}` / `[]` | |
| `affinity` | `{}` | Full override; disables `podAntiAffinityPreset`. |
| `podAntiAffinityPreset` | `soft` | Spread over nodes: `soft`, `hard` or `""`. |
| `topologySpreadConstraints` | `[]` | Full override; disables `topologySpread`. |
| `topologySpread.enabled` | `true` | Zone spread for this release's pods. |
| `topologySpread.topologyKey` | `topology.kubernetes.io/zone` | |
| `topologySpread.maxSkew` | `1` | |
| `topologySpread.whenUnsatisfiable` | `ScheduleAnyway` | `DoNotSchedule` for strict spreading. |

### NetworkPolicy

| Key | Default | Description |
|---|---|---|
| `networkPolicy.enabled` | `true` | |
| `networkPolicy.ingressFrom` | `[]` | Peers allowed to call haltsql; empty means any pod in the namespace. |
| `networkPolicy.metricsFrom` | `[]` | Peers allowed to scrape `/metrics` (e.g. the monitoring namespace). |
| `networkPolicy.extraIngress` | `[]` | Extra ingress rules, verbatim. |
| `networkPolicy.egress.allowHTTPS` | `auto` | TCP 443 to any destination. `auto` enables it only when `oidc` is set (discovery and JWKS). Prefer `false` plus `extraRules` with your IdP's CIDRs if they are stable. |
| `networkPolicy.egress.allowDNS` | `auto` | UDP/TCP 53. `auto` enables it whenever any other egress is allowed. |
| `networkPolicy.egress.extraRules` | `[]` | Extra egress rules: OTLP collector, Vault, S3/GCS endpoints. |

Verification itself makes no network calls, so with no OIDC and no extra rules
the policy denies all egress. With `tls.enabled`, ingress to the plain-HTTP
health port is also allowed (for probes).

`networkPolicy.egress` may instead be a list of `NetworkPolicyEgressRule`
objects. The list is then the whole egress section, rendered verbatim (no
automatic DNS or HTTPS rules; `[]` denies all). The Terraform
`haltsql-kubernetes` module passes this form. Helm logs a harmless
"cannot overwrite table with non table" notice when a list replaces the
default map.

### Prometheus Operator

| Key | Default | Description |
|---|---|---|
| `serviceMonitor.enabled` | `false` | Create a `ServiceMonitor` (needs the CRD). |
| `serviceMonitor.namespace` | `""` | Namespace for the ServiceMonitor; defaults to the release namespace. |
| `serviceMonitor.interval` / `scrapeTimeout` | `30s` / `10s` | |
| `serviceMonitor.labels` | `{}` | e.g. `{release: kube-prometheus-stack}` to match your Prometheus selector. |
| `serviceMonitor.honorLabels` | `false` | |
| `serviceMonitor.relabelings` / `metricRelabelings` | `[]` | |
| `serviceMonitor.tlsConfig` | `{}` | Used when `tls.enabled` (scheme `https`). |

Also allow the Prometheus namespace in `networkPolicy.metricsFrom`.

## Examples

Production-style values with an internal LB, OIDC and a pinned image:

```yaml
image:
  digest: sha256:<digest>
priorityClassName: system-cluster-critical   # or your own high class
tls: { enabled: true, secretName: haltsql-tls }
oidc:
  - name: corp-okta
    issuer: https://corp.okta.com/oauth2/default
    audiences: [haltsql]
    policy_claim: haltsql_policy
    allowed_policies: [analytics-agent]
existingPolicyConfigMap: haltsql-policies
existingPolicyFiles: [analytics-agent.yaml]
service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-scheme: internal
  loadBalancerSourceRanges: [10.0.0.0/8]
networkPolicy:
  ingressFrom:
    - namespaceSelector: { matchLabels: { haltsql-client: "true" } }
  metricsFrom:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: monitoring } }
serviceMonitor: { enabled: true, labels: { release: kube-prometheus-stack } }
preStopSleepSeconds: 5
topologySpread: { whenUnsatisfiable: DoNotSchedule }
```

OpenTelemetry export through `extraConfig`, with matching egress:

```yaml
server:
  extraConfig:
    telemetry:
      otlp: { endpoint: http://otel-collector.observability:4318 }
networkPolicy:
  egress:
    extraRules:
      - to: [{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: observability } } }]
        ports: [{ port: 4318, protocol: TCP }]
```

## Validating changes to the chart

```sh
helm lint deploy/helm/haltsql
helm template t deploy/helm/haltsql | kubeconform -strict -summary
```
