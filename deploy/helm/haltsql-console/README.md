# haltsql-console Helm chart

Deploys `haltsql-console`, the HaltSQL control plane (signals, records,
agents, policies, fleet, data and evidence), as one replica with a persistent
state volume. The console only reads what the verifiers publish and is never
in the query path. Full guide, including AWS, Google Cloud and Azure:
[docs/console/deploy.md](../../../docs/console/deploy.md). Configuration
keys: [docs/console/config.md](../../../docs/console/config.md).

Requires Kubernetes 1.27 or newer and Helm 3.8 or newer. `values.schema.json`
validates every value.

```sh
kubectl -n haltsql create secret generic haltsql-console-env \
  --from-literal=HALTSQL_ADMIN_TOKEN="$CONSOLE_ADMIN_TOKEN"
helm install haltsql-console deploy/helm/haltsql-console -n haltsql -f my-values.yaml
helm lint deploy/helm/haltsql-console -f my-values.yaml
```

A minimal `my-values.yaml` next to a `haltsql` release named `haltsql`:

```yaml
console:
  config:
    environment: { org: Acme Corp, name: Production }
    auth:
      oidc:
        - { name: okta, issuer: https://acme.okta.com/oauth2/default, audience: haltsql-console }
      roles: { admin: [okta:haltsql-admins], analyst: [okta:security], audit: [okta:compliance] }
    verifiers:
      - name: haltsql
        url: http://haltsql.haltsql.svc:8080
        allow_insecure_http: true   # the admin token over plain HTTP: prefer https + ca_file
        token: ${env:HALTSQL_ADMIN_TOKEN}     # its name is in the verifiers' server.admin.callers
        workload: deployment/haltsql
    audit:
      sources:
        - { verifier: auto, s3: "s3://acme-audit/haltsql/audit/", region: eu-west-1 }
    policies:
      server_config: /etc/haltsql/config/config.yaml
existingSecret: haltsql-console-env
verifierConfig: { configMap: haltsql-config, policiesConfigMap: haltsql-policies }
rbac: { create: true, deployments: [haltsql] }
```

## Secure defaults

- one replica, `Recreate` strategy: two consoles never write the same
  `state_dir` (`replicaCount` is limited to 0 or 1);
- uid/gid 65532, `runAsNonRoot`, `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, every capability dropped, `RuntimeDefault`
  seccomp; only `state_dir` and a size-limited `/tmp` are writable; meets the
  Pod Security Standards `restricted` profile;
- no service account token and no service-link env vars, unless `rbac.create`
  needs the token for verifier restarts;
- the restart Role is namespaced and allows only `patch` on the named
  Deployments/StatefulSets: no `get`, `list`, `watch`, no other resources;
- secrets only through `existingSecret` and `${env:...}` placeholders (or the
  console's own `${vault:...}`, `${aws-sm:...}`, `${gcp-sm:...}`);
- NetworkPolicy: ingress only on the HTTP port, egress only to DNS, the
  verifiers, TCP 443 and explicit extra rules;
- `ClusterIP` Service; the Ingress is opt-in;
- with `oauth2Proxy.enabled`, the console listens on `127.0.0.1` only, so the
  trusted identity headers can only come from the sidecar.

## Values

### Image and workload

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `1` | `0` or `1`. The state volume is single-writer. |
| `revisionHistoryLimit` | `5` | |
| `image.repository` | `ghcr.io/haltsql/haltsql-console` | |
| `image.tag` | `""` | Defaults to the chart `appVersion`. |
| `image.digest` | `""` | `sha256:...`; wins over `tag`. Verify with cosign first. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride` / `fullnameOverride` | `""` | |
| `serviceAccount.create` / `name` | `true` / `""` | |
| `serviceAccount.annotations` | `{}` | IRSA, GKE or AKS Workload Identity for S3/GCS reads and secret managers. |
| `serviceAccount.automountServiceAccountToken` | `false` | Forced on by `rbac.create`. |
| `podAnnotations` / `podLabels` | `{}` | e.g. `azure.workload.identity/use: "true"`. |
| `priorityClassName` / `runtimeClassName` | `""` | |

### Console configuration

| Key | Default | Description |
|---|---|---|
| `console.port` | `8090` | Listen port (`--listen`). |
| `console.config` | see `values.yaml` | The console config ([config.md](../../../docs/console/config.md)), rendered into a ConfigMap. Do not set `listen` or `state_dir` (the chart sets them; the schema refuses them). With `oauth2Proxy.enabled` the chart sets `auth.proxy`; with `rbac.create`, `fleet.kubernetes.namespace`. |
| `console.existingConfigMap` | `""` | Your own ConfigMap with key `console.yaml` instead. Set `state_dir` to `persistence.mountPath` in it. |
| `console.devRole` | `""` | `--dev ROLE`: every request is a local user with that role. Development only. The console refuses to start with it unless it listens on a loopback address, so it is not reachable through the Service. |
| `console.frontendDir` | `""` | `frontend_dir`; the image reserves `/usr/share/haltsql-console/web`. |
| `existingSecret` | `""` | Secret whose keys become environment variables (`envFrom`) for `${env:NAME}` placeholders: admin tokens, GitHub token, webhook URLs. |
| `secretEnv` | `{}` | Testing only: key/values rendered into a chart Secret. They end up in the Helm release; prefer `existingSecret`. |
| `verifierConfig.configMap` | `""` | The verifiers' config, mounted at `/etc/haltsql/config` (with the `haltsql` chart: `<release>-config`). |
| `verifierConfig.policiesConfigMap` | `""` | The verifiers' policies, mounted at `/etc/haltsql/policies` (`<release>-policies`), so relative paths in the verifier config resolve the same way. |
| `auditVolume.volume` | `{}` | One pod volume source with the verifiers' audit files (file audit sources), mounted read-only. Leave empty for S3/GCS. |
| `auditVolume.mountPath` | `/var/log/haltsql` | |

### State

| Key | Default | Description |
|---|---|---|
| `persistence.enabled` | `true` | PVC for `state_dir`. When `false`, an `emptyDir` (state is lost on rescheduling). |
| `persistence.existingClaim` | `""` | Use an existing PVC. |
| `persistence.storageClass` | `""` | `""` = cluster default, `"-"` = none. `gp3`, `premium-rwo`, `managed-csi-premium`... |
| `persistence.accessModes` | `[ReadWriteOnce]` | |
| `persistence.size` | `10Gi` | |
| `persistence.annotations` | `{}` | e.g. `helm.sh/resource-policy: keep`. |
| `persistence.mountPath` | `/var/lib/haltsql-console` | Also written as `state_dir`. |

### Verifier restarts

| Key | Default | Description |
|---|---|---|
| `rbac.create` | `false` | Role + RoleBinding allowing only `patch` on the named workloads; mounts the token and sets `fleet.kubernetes.namespace`. |
| `rbac.namespace` | `""` | The verifiers' namespace; defaults to the release namespace. |
| `rbac.deployments` / `rbac.statefulsets` | `[]` | Workload names. At least one is required with `rbac.create`. |

### oauth2-proxy sidecar

| Key | Default | Description |
|---|---|---|
| `oauth2Proxy.enabled` | `false` | Run oauth2-proxy in the pod; the Service and probes go through it, the console binds to loopback, and `auth.proxy` trusts `X-Forwarded-Email`, `X-Forwarded-Groups` and `X-Forwarded-Preferred-Username`. `/healthz` and `/readyz` pass without a session. |
| `oauth2Proxy.image.*` | `quay.io/oauth2-proxy/oauth2-proxy:v7.8.1` | `repository`, `tag`, `digest`, `pullPolicy`. |
| `oauth2Proxy.port` | `4180` | |
| `oauth2Proxy.existingSecret` | `""` | Required: `OAUTH2_PROXY_CLIENT_ID`, `OAUTH2_PROXY_CLIENT_SECRET`, `OAUTH2_PROXY_COOKIE_SECRET`. |
| `oauth2Proxy.provider` | `oidc` | Any oauth2-proxy provider (`oidc`, `google`, `entra-id`, ...). |
| `oauth2Proxy.oidcIssuerUrl` | `""` | Required with `provider: oidc`. |
| `oauth2Proxy.redirectUrl` | `""` | `https://<host>/oauth2/callback`. |
| `oauth2Proxy.emailDomains` | `["*"]` | |
| `oauth2Proxy.allowedGroups` | `[]` | Only these groups may sign in. |
| `oauth2Proxy.scope` | `openid email profile` | Add `groups` where the IdP needs it. |
| `oauth2Proxy.extraArgs` | `[]` | Extra flags, e.g. `--google-group=...`. |
| `oauth2Proxy.extraVolumeMounts` | `[]` | Mounts into the sidecar (volumes from `extraVolumes`). |
| `oauth2Proxy.resources` | `10m`/`32Mi`, limit `128Mi` | |

### Service and ingress

| Key | Default | Description |
|---|---|---|
| `service.type` | `ClusterIP` | |
| `service.port` | `8090` | |
| `service.annotations` / `labels` | `{}` | e.g. `cloud.google.com/backend-config` for IAP. |
| `ingress.enabled` | `false` | |
| `ingress.className` | `""` | `alb`, `gce-internal`, `azure-application-gateway`, `nginx`... |
| `ingress.annotations` | `{}` | |
| `ingress.hosts` | `[]` | `[{host, paths: [{path, pathType}]}]`; required when enabled. |
| `ingress.tls` | `[]` | |

### Container, probes and scheduling

| Key | Default | Description |
|---|---|---|
| `extraArgs` / `extraEnv` / `extraEnvFrom` | `[]` | |
| `extraVolumes` / `extraVolumeMounts` | `[]` | e.g. a Secrets Store CSI volume. |
| `initContainers` / `extraContainers` | `[]` | |
| `resources` | requests `100m`/`256Mi`, limit `1Gi` | The record index is in memory; size the limit for `audit.max_records`. |
| `podSecurityContext` / `securityContext` | hardened (above) | |
| `startupProbe` | `/healthz`, 60 x 2 s | |
| `livenessProbe` | `/healthz`, every 10 s | |
| `readinessProbe` | `/readyz`, every 5 s | `503` while `state_dir` is not writable. |
| `terminationGracePeriodSeconds` | `30` | |
| `podDisruptionBudget.enabled` | `false` | With one replica a PDB blocks drains (`maxUnavailable: 0`) or allows the eviction anyway. |
| `podDisruptionBudget.maxUnavailable` / `minAvailable` | `1` / `null` | `maxUnavailable` wins. |
| `nodeSelector` / `tolerations` / `affinity` | empty | |

### NetworkPolicy

| Key | Default | Description |
|---|---|---|
| `networkPolicy.enabled` | `true` | |
| `networkPolicy.ingressFrom` | `[]` | Peers allowed to reach the console: the ingress controller, the load balancer's subnet. Empty = pods in the release namespace. |
| `networkPolicy.extraIngress` | `[]` | |
| `networkPolicy.egress.allowDNS` | `true` | |
| `networkPolicy.egress.verifiers` | pods `app.kubernetes.io/name: haltsql`, TCP 8080 | Egress rules to the verifiers' HTTP API. |
| `networkPolicy.egress.allowHTTPS` | `true` | TCP 443 anywhere: IdP, GitHub, Slack, PagerDuty, catalogs, S3/GCS, secret managers, Kubernetes API. Prefer `false` plus `extraRules` with fixed CIDRs where possible. |
| `networkPolicy.egress.kubernetesAPI` | `{to: [], port: 6443}` | With `rbac.create`, the API server when it is not on 443. |
| `networkPolicy.egress.extraRules` | `[]` | |

If the verifiers' own NetworkPolicy restricts ingress (the `haltsql` chart
does), allow the console there too (`networkPolicy.ingressFrom` of the
`haltsql` release) when it runs in another namespace.

### Prometheus Operator

| Key | Default | Description |
|---|---|---|
| `serviceMonitor.enabled` | `false` | Reserved: the console does not expose Prometheus metrics yet. |
| `serviceMonitor.path` / `interval` / `scrapeTimeout` / `labels` / `namespace` | `/metrics`, `30s`, `10s` | |

## Cloud overlays

| Cloud | Values | Also |
|---|---|---|
| AWS EKS | [`deploy/cloud/aws/console/eks.values.yaml`](../../cloud/aws/console/eks.values.yaml) | IRSA trust and permission policies in the same directory. |
| GKE | [`deploy/cloud/gcp/console/gke.values.yaml`](../../cloud/gcp/console/gke.values.yaml) | `iap-backendconfig.yaml`. |
| AKS | [`deploy/cloud/azure/console/aks.values.yaml`](../../cloud/azure/console/aks.values.yaml) | `secretproviderclass.yaml`, `audit-share.yaml`. |

## Validating changes to the chart

```sh
helm lint deploy/helm/haltsql-console --strict
for f in deploy/cloud/*/console/*.values.yaml; do helm lint deploy/helm/haltsql-console --strict -f "$f"; done
helm template t deploy/helm/haltsql-console | kubeconform -strict -summary
```
