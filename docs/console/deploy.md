# HaltSQL Console: deployment

`haltsql-console` is the control plane for a HaltSQL deployment. It reads what
the verifiers (`haltsql-server`, `haltsql-proxy`, `haltsql-mcp`) already
publish (audit records, `GET /v1/admin/status` and `/v1/admin/report`,
`/readyz`, `/metrics`) and the policy files they load. It is **never in the
query path**: if the console is down, enforcement does not change. See
[architecture.md](architecture.md) for the design, [config.md](config.md) for
every configuration key and [api.md](api.md) for the HTTP API.

This guide covers running it locally (Docker Compose or the bare binary), on
Kubernetes with the Helm chart, and on AWS, Google Cloud and Azure, both on
their Kubernetes services and on their serverless container platforms.

| Path | What it is |
|---|---|
| [`Dockerfile`](../../Dockerfile) (target `console`) | The `ghcr.io/haltsql/haltsql-console` image: static binary on `distroless/static:nonroot`. |
| [`deploy/console/`](../../deploy/console/) | Example config, the local Compose stack, `demo-traffic.sh`. |
| [`deploy/helm/haltsql-console/`](../../deploy/helm/haltsql-console/) | Helm chart. Values reference in its [README](../../deploy/helm/haltsql-console/README.md). |
| `deploy/cloud/{aws,gcp,azure}/console/` | Values overlays, IAM, ECS / Cloud Run / Container Apps definitions. |
| [`deploy/terraform/examples/console-kubernetes/`](../../deploy/terraform/examples/console-kubernetes/) | Terraform root module: the chart through `helm_release`. |

## What every deployment needs

Whatever the platform, the console needs the same five things:

1. **One replica and a persistent `state_dir`.** Cases, the activity log,
   signal workflow state and evidence packs are the only durable state, kept
   as files in `state_dir` (`/var/lib/haltsql-console` in the image). Run
   exactly one replica per environment on a single-writer volume, and stop the
   old instance before the new one starts (Kubernetes `Recreate`, ECS
   `minimumHealthyPercent: 0`, Cloud Run and Container Apps `maxScale: 1`).
   Everything else (the record index, fleet snapshots, signals) is rebuilt
   from the verifiers at startup. `/readyz` answers `503` while `state_dir`
   is not writable.
2. **An admin token on every verifier.** The console polls each verifier's
   admin API with a bearer token. On the verifier, that token is an ordinary
   `server.auth.tokens` entry (every token is pinned to a policy) whose name
   is listed in `server.admin.callers`:

   ```yaml
   # verifier config (haltsql-server)
   server:
     auth:
       tokens:
         - name: console
           token_sha256: ${env:HALTSQL_CONSOLE_TOKEN_SHA256}
           policy: analytics-agent      # any loaded policy; used only for admin calls
     admin:
       enabled: true
       callers: [token:console]         # or oidc:<provider>, mtls:<identity>
   ```

   ```yaml
   # console config
   verifiers:
     - name: haltsql
       url: http://haltsql.haltsql.svc:8080
       token: ${env:HALTSQL_ADMIN_TOKEN}   # the raw token, from a secret
       workload: deployment/haltsql        # optional: restarts from Fleet
   ```

   The admin endpoints are read-only. With the `haltsql` Helm chart, add
   `server.admin` through `extraConfig` and the token through `tokens`.
3. **The audit trail.** `audit.sources` points at what the verifiers write:
   files (a shared volume), `s3://bucket/prefix/` or `gs://bucket/prefix/`.
   Raw SQL is only in the records if the verifiers set `audit.log_raw_sql`.
4. **The verifiers' policies.** `policies.server_config` (or
   `policies.files`) points at the same config and policy files the verifiers
   load, mounted read-only, so the Playground, decision trails and exposure
   use exactly the verifiers' policies.
5. **Authentication in front.** One of: OIDC (`auth.oidc`), an identity-aware
   proxy that is the *only* way to reach the console (`auth.proxy`, for
   example the chart's oauth2-proxy sidecar), or automation tokens
   (`auth.tokens`). Roles come from groups (`auth.roles`), so the identity
   source must provide group membership. Never expose the console publicly;
   keep it on an internal load balancer or behind a private ingress.

Secrets (admin tokens, GitHub token, webhook URLs) go in `${env:NAME}`,
`${vault:...}`, `${aws-sm:...}` or `${gcp-sm:...}` placeholders, never in the
file. Resolved values are never logged or returned by the API.

## The image

```sh
docker build --target console -t haltsql-console-local:dev .   # or: make console-image
scripts/console-docker-smoke.sh                                 # or: make console-smoke
```

Release images are `ghcr.io/haltsql/haltsql-console:<version>`, multi-arch
(`linux/amd64`, `linux/arm64`), built by the release workflow from the same
builder stage as the `haltsql` image, with SPDX SBOM and SLSA provenance
attestations, signed keylessly with cosign. Pin by digest in production; the
identity regexp accepts only the release workflow on a version tag, not any
workflow or branch of the repository:

```sh
cosign verify ghcr.io/haltsql/haltsql-console@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/HaltSQL/HaltSQL/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/haltsql/haltsql-console@sha256:<digest> --repo HaltSQL/HaltSQL
```

| Property | Value |
|---|---|
| Base | `gcr.io/distroless/static-debian12:nonroot` (no shell, no libc, no package manager) |
| User | `65532:65532` |
| Root filesystem | Read-only (`docker run --read-only`, `readOnlyRootFilesystem: true`) |
| Entrypoint / command | `haltsql-console` / `--config /etc/haltsql-console/console.yaml` |
| Port | `8090` (`HALTSQL_CONSOLE_LISTEN=0.0.0.0:8090`) |
| Writable volume | `/var/lib/haltsql-console` (`state_dir`, `VOLUME`, owned by 65532) |
| Frontend | `/usr/share/haltsql-console/web` is reserved for `frontend_dir` |
| Health | `HEALTHCHECK` runs `haltsql-console --healthcheck` (`GET /healthz` on the listen port). Orchestrators should use HTTP probes: liveness `/healthz`, readiness `/readyz`. |
| Signals | `SIGTERM`/`SIGINT` stop the listener and exit `0`; configuration errors exit `2`. |

`--listen` > `HALTSQL_CONSOLE_LISTEN` > `listen:` in the config, so `listen:`
has no effect inside the image. Change the address with `--listen` or the
environment variable (`--healthcheck` probes that same address, using
loopback when it listens on all interfaces).

## Local: Docker Compose

[`deploy/console/docker-compose.yaml`](../../deploy/console/docker-compose.yaml)
runs a complete stack from this checkout:

| Service | What it does |
|---|---|
| `postgres` | PostgreSQL 17 with a small `app` schema ([`local/seed.sql`](../../deploy/console/local/seed.sql)). |
| `haltsql` | `haltsql-server` with [`local/haltsql.yaml`](../../deploy/console/local/haltsql.yaml): two policies (`saas-analytics` enforced, `support-bot` in shadow mode), `server.admin` enabled for the console's token, a file audit sink on the shared `audit` volume, `log_raw_sql: true`. Port `127.0.0.1:18080`. |
| `console` | `haltsql-console` with [`console.local.yaml`](../../deploy/console/console.local.yaml) (demo tokens: `demo-admin-token` is an admin, `demo-automation-token` an auditor): reads the audit file read-only, polls the server's admin API, loads the server's config. Port `127.0.0.1:8090`. |

```sh
make console-up        # docker compose -f deploy/console/docker-compose.yaml up -d --build
make console-demo      # deploy/console/demo-traffic.sh
curl -s -H 'authorization: Bearer demo-admin-token' localhost:8090/api/v1/me
curl -s -H 'authorization: Bearer demo-admin-token' 'localhost:8090/api/v1/overview?range=24h'
make console-down      # stops the stack and deletes its volumes
```

`demo-traffic.sh` sends a mix of queries through `POST /v1/verify`: allowed
tenant-scoped reads, denials (PII column, `DELETE`, missing `LIMIT`, system
catalog), cross-tenant attempts (another tenant's literal, `OR` across
tenants, no tenant predicate) and shadow-mode would-be denials.
`ROUNDS=20` produces enough cross-tenant records to trip the cross-tenant
signal; `EXECUTE=1` also runs each allowed query on the stack's Postgres as a
read-only role, the way an agent uses HaltSQL (verify, then execute).

The stack is a demo: the tokens in `local/haltsql.yaml` and
`console.local.yaml` are well-known strings, and both ports are bound to
`127.0.0.1`. It does not use dev mode: dev mode only runs on a loopback listen
address, and inside the container the console listens on `0.0.0.0`. All containers run
read-only with every capability dropped.

## Local: the bare binary

```sh
opam exec -- dune build ./bin/console          # or: make console
cp deploy/console/console.example.yaml console.yaml   # edit verifiers, audit, auth
mkdir -p console-state
_build/default/bin/console/main.exe --config console.yaml --listen 127.0.0.1:8090 --dev admin
```

`--dev ROLE` authenticates every request as a local user with that role. It
replaces every other auth method in the config, and the console refuses to
start with it unless `listen` is a loopback address (see
[Dev mode](config.md#dev-mode)).
Release builds are static (`HALTSQL_STATIC=1 dune build --profile release
./bin/console`, on musl). For a VM, run it under systemd with the same
hardening as [`deploy/systemd/haltsql-server.service`](../../deploy/systemd/haltsql-server.service)
and `StateDirectory=haltsql-console`.

## Kubernetes: Helm

```sh
kubectl -n haltsql create secret generic haltsql-console-env \
  --from-literal=HALTSQL_ADMIN_TOKEN="$CONSOLE_ADMIN_TOKEN"
helm upgrade --install haltsql-console deploy/helm/haltsql-console -n haltsql \
  -f my-console-values.yaml
```

The chart ([values reference](../../deploy/helm/haltsql-console/README.md))
renders:

- a **Deployment** with one replica and the `Recreate` strategy, the same
  hardening as the `haltsql` chart (uid/gid 65532, read-only root filesystem,
  no capabilities, `RuntimeDefault` seccomp, no service-link env vars, no
  service account token at pod level; with restarts enabled the token is
  projected into the console container only, never the oauth2-proxy sidecar
  or `extraContainers`), and startup, liveness and readiness probes. The
  chart has no dev mode: it refuses `console.devRole` and `--dev` in
  `extraArgs`, since dev mode needs a loopback listen address and signs every
  request in;
- a **PersistentVolumeClaim** for `state_dir` (`ReadWriteOnce`, 10 Gi;
  `persistence.existingClaim` to bring your own);
- a **ConfigMap** with the console config (`console.config`; the chart sets
  `listen` and `state_dir`), or your own (`console.existingConfigMap`). The
  default `audit.max_records` is 200,000: an index entry takes about 2.4 KB
  of memory, so keep `max_records` x 2.4 KB under half of
  `resources.limits.memory` (1 Gi by default) and raise both together. The
  console's own default of 2,000,000 records needs about 5 GB;
- **secrets** from `existingSecret` (every key becomes an environment
  variable for `${env:...}` placeholders), so tokens live in External Secrets,
  the Secrets Store CSI driver or Sealed Secrets, never in values;
- the **verifiers' config and policies** mounted read-only at
  `/etc/haltsql/config` and `/etc/haltsql/policies` (`verifierConfig`; with
  the `haltsql` chart these are the `<release>-config` and
  `<release>-policies` ConfigMaps);
- a **Service** (ClusterIP) and an optional **Ingress**;
- a **ServiceAccount** and, with `rbac.create`, a namespaced **Role and
  RoleBinding** that allow only `patch` on the listed Deployments and
  StatefulSets (verifier restarts); the chart then sets
  `fleet.kubernetes.namespace` and projects the token into the console
  container. RBAC cannot limit a patch to the `restartedAt` annotation the
  console sets, so the Role allows any patch of those workloads (image,
  command, env); see [Keeping it private](#keeping-it-private) for an
  admission policy that narrows it;
- a **NetworkPolicy**: ingress only on the HTTP port from `ingressFrom`
  (empty = every pod in the release namespace); egress only to DNS, the
  verifiers (pods of the `haltsql` chart on 8080 by default), TCP 443 (IdP,
  GitHub, Slack, PagerDuty, catalogs, S3/GCS, secret managers, the Kubernetes
  API) and `extraRules`;
- an optional **oauth2-proxy sidecar** (`oauth2Proxy.enabled`): the console
  then listens on `127.0.0.1` only, the Service points at the sidecar, and
  the chart sets `auth.proxy` to trust `X-Forwarded-Email`,
  `X-Forwarded-Groups` and `X-Forwarded-Preferred-Username`, which
  oauth2-proxy sets from the session and overwrites on every request, with
  `trusted_proxies: [127.0.0.1/32, "::1/128"]` (the console refuses an
  `auth.proxy` without `trusted_proxies` or a shared secret). Set
  `oauth2Proxy.allowedGroups` (or a provider group flag in `extraArgs`) so
  only the console's groups can sign in; the release notes warn otherwise.
  An `auth.proxy` of your own, without the sidecar, must set
  `trusted_proxies` or `secret_header` + `secret_sha256`, and without the
  secret the chart also requires a non-empty `networkPolicy.ingressFrom`;
- a **PodDisruptionBudget** (off by default) and a **ServiceMonitor** (off;
  the console has no Prometheus endpoint yet).

The verifiers' NetworkPolicy must admit the console, **even in the same
namespace**: a policy whose `ingressFrom` lists only the agents' namespace
drops the console's admin API calls. The shipped verifier policies
([`values-gke.yaml`](../../deploy/cloud/gcp/gke/values-gke.yaml), the EKS and
AKS `networkpolicy-shared.yaml`) admit pods labelled
`app.kubernetes.io/name: haltsql-console` in their namespace; add the same
`podSelector` to your own:

```yaml
networkPolicy:              # the haltsql chart's values
  ingressFrom:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: agents } }
    - podSelector: { matchLabels: { app.kubernetes.io/name: haltsql-console } }
```

If the console runs in a different namespace, put a `namespaceSelector` for
it in the same entry as that `podSelector`, and set `rbac.namespace` to the
verifiers' namespace.

Plain manifests: `helm template haltsql-console deploy/helm/haltsql-console
-n haltsql -f my-values.yaml > console.yaml` produces reviewable YAML for
GitOps tools that do not run Helm.

### Terraform

[`deploy/terraform/examples/console-kubernetes`](../../deploy/terraform/examples/console-kubernetes/)
installs the chart with `helm_release` next to a `haltsql` release (for
example one created by the `haltsql-kubernetes` module), wiring the verifier
URL, the restart Role, the verifiers' ConfigMaps and the state volume. Cloud
specifics come from the overlays below through `values_files`:

```sh
cd deploy/terraform/examples/console-kubernetes
terraform init
terraform apply -var kube_context=my-eks \
  -var 'values_files=["../../../cloud/aws/console/eks.values.yaml"]'
```

The admin-token Secret is referenced by name (`admin_token_secret`) and is
never written to Terraform state. `automation_tokens` are applied after
`values_files`, because Helm replaces lists: a values file that sets
`console.config.auth.tokens` would otherwise drop them silently. The cloud
overlays leave `auth.tokens` unset for the same reason.

## AWS

### EKS with the chart

[`deploy/cloud/aws/console/eks.values.yaml`](../../deploy/cloud/aws/console/eks.values.yaml)
installs the console next to the shared service from
[deploy-aws.md](../deploy-aws.md#b-eks-shared-service-helm) (namespace
`haltsql`):

```sh
kubectl -n haltsql create secret generic haltsql-console-env \
  --from-literal=HALTSQL_ADMIN_TOKEN="$CONSOLE_ADMIN_TOKEN"
kubectl -n haltsql create secret generic haltsql-console-oauth2 \
  --from-literal=OAUTH2_PROXY_CLIENT_ID=... --from-literal=OAUTH2_PROXY_CLIENT_SECRET=... \
  --from-literal=OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- '+/' '-_')"
helm upgrade --install haltsql-console deploy/helm/haltsql-console -n haltsql \
  -f deploy/cloud/aws/console/eks.values.yaml
```

- **IRSA.** The ServiceAccount `haltsql-console` is annotated with the role
  `haltsql-console`, whose trust policy
  ([`irsa-trust-policy.json`](../../deploy/cloud/aws/console/irsa-trust-policy.json))
  admits only `system:serviceaccount:haltsql:haltsql-console`. Its permission
  policy ([`iam-policy.json`](../../deploy/cloud/aws/console/iam-policy.json))
  is read-only and scoped to the audit prefix and the secrets the console
  itself resolves (`${aws-sm:...}`); list each one by name, never the whole
  `haltsql-console/` prefix:

  ```json
  { "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::corp-haltsql-audit",
    "Condition": { "StringLike": { "s3:prefix": ["haltsql/audit/", "haltsql/audit/*"] } } },
  { "Action": "s3:GetObject", "Resource": "arn:aws:s3:::corp-haltsql-audit/haltsql/audit/*" },
  { "Action": "kms:Decrypt", "Condition": { "StringEquals": { "kms:ViaService": "s3.eu-west-1.amazonaws.com" } } },
  { "Action": "secretsmanager:GetSecretValue", "Resource": ["arn:aws:secretsmanager:eu-west-1:111122223333:secret:haltsql-console/admin-token-??????"] }
  ```

  No `s3:PutObject` or `DeleteObject`: the console never writes the audit
  trail. AWS credentials come from the standard chain (web identity under
  IRSA), as for the server ([secrets.md](../secrets.md)).
- **Audit source.** `{ verifier: auto, s3: "s3://corp-haltsql-audit/haltsql/audit/", region: eu-west-1 }`,
  the bucket and prefix of the verifiers' S3 Object Lock sink.
- **Secrets.** The admin token comes from the `haltsql-console-env` Secret
  (synced from Secrets Manager by External Secrets Operator, for example), or
  directly from Secrets Manager with `token: ${aws-sm:haltsql-console/admin-token}`
  and `console.config.secrets.aws.region`.
- **Sign-in.** An internal ALB (`alb.ingress.kubernetes.io/scheme: internal`,
  TLS 1.3 policy, ACM certificate) forwards to the oauth2-proxy sidecar,
  which signs users in with your IdP (Okta, Entra ID, Cognito) and passes
  `X-Forwarded-Email`/`-Groups` to the console. The ALB's own
  `auth-type: oidc` action is not used: it forwards identity in
  `x-amzn-oidc-*` headers without a plain groups header, so the console
  could not map users to roles.
- **State.** An EBS `gp3` volume (EBS CSI driver), with
  `helm.sh/resource-policy: keep` so `helm uninstall` does not delete it.
- **Restarts.** `rbac.create: true` with `deployments: [haltsql]`. If the EKS
  API endpoint is private and not on 443 from the pod network, add its CIDR
  under `networkPolicy.egress.kubernetesAPI`.
- **Network.** The NetworkPolicy admits only the VPC CIDR (the ALB targets
  pod IPs) and allows egress to the verifiers, DNS and 443. Keep the console
  in private subnets; reach it over VPN or Direct Connect.

### ECS Fargate alternative

[`console-task-definition.json`](../../deploy/cloud/aws/console/console-task-definition.json)
runs the console and an oauth2-proxy container in one Fargate task, with
`state_dir` on an EFS access point (POSIX user 65532, `transitEncryption` and
IAM authorization enabled):

- Build the config image with
  [`Dockerfile.ecs`](../../deploy/cloud/aws/console/Dockerfile.ecs), which
  bakes [`console.ecs.yaml`](../../deploy/cloud/aws/console/console.ecs.yaml)
  and the verifiers' config and policies into a derived image, the same
  pattern as the verifier on ECS ([deploy-aws.md](../deploy-aws.md#c-ecs-fargate-shared-service)).
- The console listens on `127.0.0.1:8090`; only oauth2-proxy (port 4180) is
  registered with an **internal** ALB target group (health check
  `/readyz`). Secrets (`HALTSQL_ADMIN_TOKEN`, the oauth2-proxy client and
  cookie secrets) are injected by ECS from Secrets Manager; the execution
  role needs `secretsmanager:GetSecretValue` on them. The oauth2-proxy
  secrets live under their own name (`haltsql-console-oauth2`), outside the
  `haltsql-console/` prefix, so the task role (which the console's code runs
  with) cannot read the cookie secret and forge oauth2-proxy sessions.
- [`console.ecs.yaml`](../../deploy/cloud/aws/console/console.ecs.yaml) sets
  `auth.proxy.trusted_proxies: [127.0.0.1/32, "::1/128"]`: the containers of
  a task share the loopback interface, and the console accepts identity
  headers only from that connection. oauth2-proxy admits only the console's
  groups (`--allowed-group`).
- The task role gets the S3 read and Secrets Manager statements of
  `iam-policy.json` plus `elasticfilesystem:ClientMount` and `ClientWrite`
  on the access point.
- Create the service with `desiredCount: 1`, `minimumHealthyPercent: 0` and
  `maximumPercent: 100` so ECS stops the old task before starting the new
  one (two tasks must never share `state_dir`).
- Verifier restarts are Kubernetes-only; on ECS use
  `aws ecs update-service --force-new-deployment` from your runbooks.

## Google Cloud

### GKE with the chart

[`deploy/cloud/gcp/console/gke.values.yaml`](../../deploy/cloud/gcp/console/gke.values.yaml)
installs the console next to the GKE shared service from
[deploy-gcp.md](../deploy-gcp.md#pattern-1b-shared-service-on-gke):

```sh
kubectl apply -n haltsql -f deploy/cloud/gcp/console/iap-backendconfig.yaml
helm upgrade --install haltsql-console deploy/helm/haltsql-console -n haltsql \
  -f deploy/cloud/gcp/console/gke.values.yaml
```

- **Workload Identity.** Bind the Kubernetes ServiceAccount to a Google
  service account that can only read the audit prefix and the console's
  secrets:

  ```sh
  gcloud iam service-accounts create haltsql-console --project "$PROJECT_ID"
  gcloud iam service-accounts add-iam-policy-binding \
    haltsql-console@$PROJECT_ID.iam.gserviceaccount.com \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:$PROJECT_ID.svc.id.goog[haltsql/haltsql-console]"
  # Read-only on the audit objects (condition: only the haltsql/ prefix).
  gcloud storage buckets add-iam-policy-binding "gs://$PROJECT_ID-haltsql-audit" \
    --member "serviceAccount:haltsql-console@$PROJECT_ID.iam.gserviceaccount.com" \
    --role roles/storage.objectViewer \
    --condition='title=haltsql-audit-prefix,expression=resource.name.startsWith("projects/_/buckets/'"$PROJECT_ID"'-haltsql-audit/objects/haltsql/")'
  gcloud secrets add-iam-policy-binding haltsql-console-admin-token \
    --member "serviceAccount:haltsql-console@$PROJECT_ID.iam.gserviceaccount.com" \
    --role roles/secretmanager.secretAccessor
  ```

  Listing objects under a condition on `resource.name` needs the bucket-level
  `storage.objects.list`; if your organization does not allow conditional
  `objectViewer`, grant it on a dedicated audit bucket instead.
- **Audit source.** `{ verifier: auto, gcs: "gs://PROJECT-haltsql-audit/haltsql/audit/shared/" }`,
  the verifiers' GCS sink.
- **Secrets.** `token: ${gcp-sm:haltsql-console-admin-token}` with
  `secrets.gcp.project`; credentials come from the metadata server
  (Workload Identity).
- **Sign-in with IAP.** The internal Application Load Balancer
  (`className: gce-internal`) has Identity-Aware Proxy enabled through the
  BackendConfig, so only principals with `roles/iap.httpsResourceAccessor`
  reach the console at all. IAP sets `x-goog-authenticated-user-email`
  (`accounts.google.com:user@example.com`) and a signed
  `x-goog-iap-jwt-assertion`, but **no group membership**, and the console
  derives roles from groups. The overlay therefore runs the oauth2-proxy
  sidecar behind IAP with the Google provider, which looks up Workspace
  groups through the Admin SDK (`--google-group`, a service account with
  domain-wide delegation and the read-only group scope) and passes them in
  `X-Forwarded-Groups`. If you need IAP's header alone, the console cannot
  map roles from it yet.
- **State.** A `premium-rwo` Persistent Disk; schedule snapshots with a
  `VolumeSnapshotClass` or a GKE Backup plan.
- **Network.** The NetworkPolicy admits Google's health-check ranges and the
  internal ALB's proxy-only subnet; egress is DNS, the verifiers, 443 and the
  GKE metadata server (`169.254.169.252:988`, and `169.254.169.254:80` on
  Dataplane V2), without which Workload Identity tokens, and with them the
  `${gcp-sm:...}` admin token and GCS audit reads, fail. The verifiers'
  `values-gke.yaml` admits the console's pods on the API port.

### Cloud Run alternative

[`cloudrun-service.yaml`](../../deploy/cloud/gcp/console/cloudrun-service.yaml)
runs the console as a Cloud Run service with:

- **one instance only**: `minScale: 1` and `maxScale: 1`, and
  `cpu-throttling: "false"` so the background loops (audit ingestion, fleet
  polling, signals) keep running between requests;
- `ingress: internal` and Direct VPC egress, so it is reachable only from
  the VPC and reaches the verifiers over private ranges;
- oauth2-proxy as the ingress container (port 4180), the console on
  `127.0.0.1:8090`;
- `state_dir` on a **Filestore** NFS share (gen2 execution environment). A
  Cloud Storage FUSE volume also mounts, but the console replaces its state
  files with an atomic rename, which Cloud Storage FUSE does not guarantee;
  use it only for disposable demos. The share must be writable by uid 65532;
- the console config mounted from Secret Manager, and the verifiers' config
  (the `haltsql-internal-config` secret of
  [`service-internal.yaml`](../../deploy/cloud/gcp/cloudrun/service-internal.yaml))
  at the verifier's own path, `/etc/haltsql/config/config.yaml`, with the
  signed bundle it loads on the same read-only Cloud Storage volume at
  `/etc/haltsql/bundles`. Without the bundle the console loads no policies
  and the Playground, decision trails and exposure stay empty. Grant
  `haltsql-console@` `roles/storage.objectViewer` on the policy bucket.

The console config (secret `haltsql-console-config`) points at those paths
and trusts oauth2-proxy over loopback only:

```yaml
auth:
  proxy:
    user_header: X-Forwarded-Email
    name_header: X-Forwarded-Preferred-Username
    groups_header: X-Forwarded-Groups
    label: oauth2-proxy
    trusted_proxies: [127.0.0.1/32, "::1/128"]   # required; oauth2-proxy is on loopback
  roles: { admin: [haltsql-admins@acme.example], audit: [compliance@acme.example] }
policies:
  server_config: /etc/haltsql/config/config.yaml
audit:
  max_records: 400000     # about 2.4 KB each; fits the 2 GiB limit
```

Verifier restarts are not available on Cloud Run; redeploy the verifier
service from your runbooks.

## Azure

### AKS with the chart

[`deploy/cloud/azure/console/aks.values.yaml`](../../deploy/cloud/azure/console/aks.values.yaml)
installs the console next to the AKS shared service from
[deploy-azure.md](../deploy-azure.md#aks-shared-service-helm):

```sh
kubectl apply -n haltsql -f deploy/cloud/azure/console/secretproviderclass.yaml
kubectl apply -n haltsql -f deploy/cloud/azure/console/audit-share.yaml
helm upgrade --install haltsql-console deploy/helm/haltsql-console -n haltsql \
  -f deploy/cloud/azure/console/aks.values.yaml
```

- **Workload Identity.** A user-assigned managed identity federated with
  `system:serviceaccount:haltsql:haltsql-console`; the pod carries
  `azure.workload.identity/use: "true"`:

  ```sh
  az identity create -g "$RG" -n id-haltsql-console
  az identity federated-credential create -g "$RG" --identity-name id-haltsql-console \
    --name haltsql-console --issuer "$AKS_OIDC_ISSUER" \
    --subject system:serviceaccount:haltsql:haltsql-console --audiences api://AzureADTokenExchange
  # Read only the console's secrets.
  az role assignment create --role "Key Vault Secrets User" --assignee "$CLIENT_ID" \
    --scope "$KV_ID/secrets/haltsql-console-admin-token"
  ```

- **Secrets.** Key Vault is **not** a console secrets provider yet. The
  Secrets Store CSI driver
  ([`secretproviderclass.yaml`](../../deploy/cloud/azure/console/secretproviderclass.yaml))
  fetches the admin token with the workload identity and syncs it into the
  `haltsql-console-env` Secret, which the chart exposes as
  `HALTSQL_ADMIN_TOKEN` for `${env:HALTSQL_ADMIN_TOKEN}`. The CSI volume is
  mounted (`extraVolumes`) because the driver syncs only for mounted pods.
- **Audit source.** Azure Blob is not a console audit source yet. The
  verifiers write one file sink per pod (`/var/log/haltsql-shared/${env:POD_NAME}.jsonl`)
  to an Azure Files share
  ([`audit-share.yaml`](../../deploy/cloud/azure/console/audit-share.yaml),
  `ReadWriteMany`, files owned by 65532), alongside the stdout or Blob sinks
  they already have; the console mounts the same claim read-only
  (`auditVolume`) and reads `/var/log/haltsql/*.jsonl`.
- **Sign-in.** An Application Gateway (AGIC, private frontend IP) routes to
  the oauth2-proxy sidecar, which signs users in with Entra ID
  (`provider: oidc`, issuer `https://login.microsoftonline.com/<tenant>/v2.0`).
  Turn on `groupMembershipClaims: SecurityGroup` on the app registration;
  group claims are object IDs, so `auth.roles` lists object IDs.
- **State.** An Azure Disk (`managed-csi-premium`, or `-zrs` for zone
  redundancy); Azure Files also works if you need to move the volume
  across zones.
- **Network.** The NetworkPolicy admits only the Application Gateway subnet;
  egress is DNS, the verifiers and 443 (Entra ID, Key Vault through the CSI
  driver, the AKS API).

### Azure Container Apps alternative

[`containerapp.yaml`](../../deploy/cloud/azure/console/containerapp.yaml)
runs the console with `minReplicas: 1`, `maxReplicas: 1` and
`activeRevisionsMode: Single`, internal-only ingress to an oauth2-proxy
container (Entra ID), and the console on `127.0.0.1:8090`:

- `state_dir` is an Azure Files share registered as environment storage,
  mounted with `uid=65532,gid=65532`;
- secrets are Container Apps secrets that reference Key Vault through the
  app's managed identity (`keyVaultUrl` + `identity`); Container Apps
  resolves them and the console sees plain environment variables;
- the console config is mounted from a secret volume; its `auth.proxy` sets
  `trusted_proxies: [127.0.0.1/32, "::1/128"]` (as in the Cloud Run example
  above), since oauth2-proxy reaches the console over the replica's loopback;
- oauth2-proxy admits only the console's Entra groups (`--allowed-group`
  with the groups' object IDs);
- the verifiers' file audit sinks are read from a shared Azure Files share.

Verifier restarts are not available on Container Apps; restart the verifier
revision from your runbooks (`az containerapp revision restart`).

## Operations

### Backups of `state_dir`

Only `state_dir` needs backups; everything else is rebuilt from the
verifiers. Its files are rewritten atomically, so a crash-consistent volume
snapshot is a valid backup:

| Platform | Backup |
|---|---|
| Kubernetes | `VolumeSnapshot` on a schedule (EBS, PD and Azure Disk CSI drivers support it), or Velero. |
| AWS ECS | AWS Backup plan on the EFS file system. |
| Cloud Run | Filestore backups. |
| Container Apps | Azure Files share snapshots or Azure Backup for file shares. |
| VM / compose | Stop the console (or snapshot the filesystem) and copy the directory. |

To restore, stop the console, restore the volume, start it again.
Evidence packs can also be downloaded (`GET /api/v1/evidence/packs/{id}/download`)
and archived elsewhere.

### Upgrades

1. Read the release notes; the console and the verifiers share a version
   and are released together. Upgrade the verifiers first, then the console
   (the console reads what the verifiers publish).
2. Pin the new image digest and verify its signature (above).
3. `helm upgrade` (or a new ECS task definition, Cloud Run revision or
   Container Apps revision). The single replica is replaced in place
   (`Recreate`), so expect a short console outage; enforcement is unaffected.
   Changes to `console.config` roll the pod through the `checksum/config`
   annotation. Changes to `console.existingConfigMap`, `existingSecret` or
   `secretEnv` do not (the chart cannot see the first two, and does not put
   a hash of secret values in a pod annotation): run
   `kubectl rollout restart deployment/haltsql-console` or use a reloader.
4. After the upgrade, `/readyz` must answer `200` and Fleet must show every
   verifier; the record index rebuilds from the audit sources in the
   background.

Roll back with `helm rollback` (or the previous revision). Take a snapshot of
`state_dir` before upgrades that the release notes say change its format.

### Keeping it private

- Expose the console only through an internal load balancer or a private
  ingress with authentication in front; keep `service.type: ClusterIP`.
- Enable `auth.proxy` only when the proxy is the sole path to the console
  (the chart guarantees this for its sidecar by binding the console to
  loopback).
- Keep the NetworkPolicy on and narrow `allowHTTPS` to known CIDRs where your
  IdP and APIs have stable addresses.
- Verifier admin tokens are read-only, but rotate them like any secret: add
  the new token to the verifiers, update the console's secret, restart the
  console, then remove the old token.
- The console never writes to verifiers. Restarts go through a namespaced
  Role that allows only `patch` on the named workloads. RBAC cannot narrow
  that patch to the `kubectl.kubernetes.io/restartedAt` annotation, so a
  compromised console container could change those workloads' image,
  command or env. To close that, admit only restart patches from the
  console's service account, for example with a ValidatingAdmissionPolicy
  (Kubernetes 1.30+):

  ```yaml
  apiVersion: admissionregistration.k8s.io/v1
  kind: ValidatingAdmissionPolicy
  metadata: { name: haltsql-console-restart-only }
  spec:
    failurePolicy: Fail
    matchConstraints:
      resourceRules:
        - apiGroups: [apps]
          apiVersions: [v1]
          operations: [UPDATE]
          resources: [deployments, statefulsets]
    matchConditions:
      - name: console
        expression: request.userInfo.username == "system:serviceaccount:haltsql:haltsql-console"
    validations:
      - expression: >-
          object.spec.template.spec == oldObject.spec.template.spec &&
          object.spec.replicas == oldObject.spec.replicas
        message: haltsql-console may only restart workloads
  ```

  Bind it with a `ValidatingAdmissionPolicyBinding` scoped to the verifiers'
  namespace.
