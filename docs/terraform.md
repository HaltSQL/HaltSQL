# Terraform

`deploy/terraform` has four Terraform modules that deploy `haltsql-server`,
and one example for each:

| Module | Runs haltsql-server on | Example |
|---|---|---|
| `modules/haltsql-kubernetes` | Any Kubernetes cluster (EKS, AKS, GKE, kind, self-managed), through the Helm chart in `deploy/helm/haltsql` | `examples/kind` |
| `modules/haltsql-aws` | Amazon ECS on Fargate | `examples/aws` |
| `modules/haltsql-azure` | Azure Container Apps | `examples/azure` |
| `modules/haltsql-gcp` | Google Cloud Run (v2 API) | `examples/gcp` |

All four modules share these rules:

- **Fail closed.** Bad input is a plan error, raised by a `validation`
  block. Examples: a token instead of its SHA-256, a bundle source without
  public keys, an `http` OIDC issuer, public ingress without an allow-list.
  A feature that the target cannot carry out is also a plan error, raised by
  a `precondition`. It is never silently dropped.
- **No secrets in configuration.** The Config document holds only
  placeholders such as `${env:NAME}`. Each platform fills them from its own
  secret store: Kubernetes Secrets, Secrets Manager or SSM, Key Vault, or
  Secret Manager. See [secrets.md](secrets.md).
- **Least privilege.** Every identity the modules create can read only the
  secrets, bundle objects and registries named in its inputs, never a whole
  vault, bucket or project.
- **Internal by default.** No module exposes haltsql-server to the internet.

> **What has been tested.** The Kubernetes module is applied for real against
> a local kind cluster by `deploy/terraform/test/e2e-kind.sh`. That test
> sends HTTP requests to the server, checks that a second plan shows no
> changes, then destroys the release. **The AWS, Azure and GCP modules have
> not been applied anywhere.** No cloud accounts were available. They pass
> `terraform validate`, `tflint` (with the aws, azurerm and google rulesets)
> and `trivy config`, but nothing has run them against a real cloud API. The
> manual workflow `.github/workflows/terraform-cloud.yml` plans them, or
> applies and then destroys them, once you configure credentials (see
> [Cloud workflow](#cloud-workflow)). Read [Known limitations](#known-limitations)
> before you use them.

## Versions

The modules set a minimum provider version and stay within its major
version. The examples pin exact versions, all released before 2026-10:

| Provider | Module constraint | Example pin |
|---|---|---|
| `hashicorp/helm` | `~> 3.3` | `3.3.0` |
| `hashicorp/kubernetes` | `~> 3.2` | `3.2.1` |
| `hashicorp/aws` | `~> 6.67` | `6.67.0` |
| `hashicorp/azurerm` | `~> 5.7` | `5.7.0` |
| `hashicorp/google` | `~> 8.5` | `8.5.0` |

Terraform `>= 1.9` is required, because validation blocks refer to other
variables. The tests ran on Terraform 1.14.3.

## haltsql-kubernetes

```hcl
module "haltsql" {
  source = "github.com/HaltSQL/HaltSQL//deploy/terraform/modules/haltsql-kubernetes"

  namespace = "haltsql"
  image     = { repository = "ghcr.io/haltsql/haltsql", digest = "sha256:..." }
  replicas  = 3

  tokens = [{
    name   = "analytics-agent"
    sha256 = "3f7c...e9" # printf '%s' "$TOKEN" | sha256sum
    policy = "analytics-agent"
  }]
  policies = {
    "analytics-agent.yaml" = file("${path.module}/policies/analytics-agent.yaml")
  }

  oidc_providers = [{
    name             = "corp-okta"
    issuer           = "https://corp.okta.com/oauth2/default"
    audiences        = ["haltsql"]
    policy_claim     = "haltsql_policy"
    allowed_policies = ["analytics-agent"]
  }]

  network_policy = {
    ingress_from = [{ podSelector = { matchLabels = { app = "agent" } } }]
  }
  service_monitor   = { enabled = true }
  workload_identity = { provider = "eks-irsa", aws_role_arn = "arn:aws:iam::123456789012:role/haltsql" }
}
```

The module creates the namespace, labelled with Pod Security Standard
`restricted`; set `create_namespace = false` to use an existing one. It
then installs the chart with `helm_release`, and renders every value the
chart takes. A failed install or upgrade is rolled back (`atomic = true`).
The chart comes from the local path `deploy/helm/haltsql` by default. To use
a chart repository instead, set `chart_repository` (`https://` or `oci://`)
together with `chart_version`, which is then required.

| Variable | What it sets |
|---|---|
| `image` | `repository`, `tag` or `digest` (a digest wins), `pull_policy`. |
| `replicas`, `autoscaling` | Replica count, or a CPU HorizontalPodAutoscaler. |
| `resources` | Requests and limits. A memory limit is always set. |
| `server` | Port, request size limit, log level and format, metrics, `audit_sinks` (Config `audit.sinks` shape), `log_raw_sql`, `default_policy`, `reload_watch`. |
| `tokens`, `existing_token_secret` | Static bearer tokens. Each has a name, a SHA-256 and the one policy it is pinned to. The chart stores the hashes in a Secret, or you name an existing Secret. |
| `policies`, `existing_policy_config_map` | Policy documents keyed by file name, or an existing ConfigMap. Each value must parse as YAML with `kind: Policy`. |
| `bundle_sources` | Signed bundles pulled from OCI, S3 or HTTPS (Config `bundle_source`; see [policy-bundles.md](policy-bundles.md)). `public_keys` is mandatory. Uses the chart's `extraPolicies` and its bundle cache volume. |
| `config`, `config_yaml` | Extra Config keys such as `telemetry`, `secrets` and `opa`, given as an object or as YAML. Uses the chart's `extraConfig`. |
| `secret_env` | Environment variables from existing Kubernetes Secrets, for `${env:NAME}` placeholders. Needs a chart extension. |
| `oidc_providers` | Config `server.auth.oidc`. Exactly one of `policy`, `policy_claim` (with `allowed_policies`) or `policy_from_groups`. `https` issuers only. `HS*` algorithms are rejected. |
| `tls`, `mtls_identities` | Built-in TLS from a `kubernetes.io/tls` Secret, and client-certificate identities. Identities require `client_auth` to be `optional` or `required`. |
| `service` | Service type (ClusterIP by default), port and annotations. |
| `network_policy` | Ingress allow-list. `egress` rules need a chart extension (see below). |
| `pod_disruption_budget` | `min_available`. |
| `service_monitor` | Prometheus Operator ServiceMonitor. |
| `workload_identity` | Cloud identity for the pods (next section). |
| `proxy` | Optionally run `haltsql-proxy` as well. Needs a chart extension. |
| `extra_values` | Raw Helm values as YAML, applied last. Use this for chart options the module does not model. |

The plan fails when there is no way to authenticate: no tokens, OIDC
providers or mTLS identities, and `allow_unauthenticated` not set. It also
fails when there are no policies.

Outputs: `namespace`, `release_name`, `chart_version`, `service_name`,
`service_account`, `service_port`, `endpoint` and `endpoints` (the base,
`/v1/verify`, `/healthz` and `/readyz` URLs inside the cluster).

### Workload identity

`workload_identity.provider` annotates or labels the pods' ServiceAccount
for the cloud identity system:

| Provider | Cluster | What the module sets | What you create |
|---|---|---|---|
| `eks-irsa` | EKS | SA annotation `eks.amazonaws.com/role-arn` | An IAM role whose trust policy allows `system:serviceaccount:<namespace>:<service_account output>` through the cluster's OIDC provider. |
| `eks-pod-identity` | EKS | nothing | `aws_eks_pod_identity_association` for the `service_account` output. See the limitation below. |
| `aks` | AKS | SA annotations `azure.workload.identity/client-id` (and `tenant-id`), pod label `azure.workload.identity/use: "true"` | A user-assigned identity, with a federated credential for the cluster's OIDC issuer and the ServiceAccount subject. |
| `gke` | GKE | SA annotation `iam.gke.io/gcp-service-account` | A Google service account, with `roles/iam.workloadIdentityUser` granted to `serviceAccount:<project>.svc.id.goog[<namespace>/<sa>]`. |

What haltsql-server does with each identity:

- **EKS IRSA.** The server's AWS credential chain reads web identity tokens.
  `${aws-sm:...}` secrets, S3 audit sinks and S3 bundle sources work with
  IRSA.
- **EKS Pod Identity.** This hands out credentials through the container
  credentials endpoint, which the server cannot read yet: it reads
  environment variables, web identity and IMDS. The module raises a `check`
  warning. Use IRSA.
- **AKS.** haltsql-server makes no Azure API calls of its own. An AKS
  identity is only useful to sidecars or CSI drivers, such as the Key Vault
  Secrets Store CSI driver, that mount secrets for it.
- **GKE.** The metadata server provides tokens. `${gcp-sm:...}` and GCS
  audit sinks work.

The chart sets `automountServiceAccountToken: false`. The IRSA and AKS
webhooks inject their own projected token volumes, so they still work, and
GKE uses the metadata server.

### Chart extensions

Some module inputs need chart values that not every version of
`deploy/helm/haltsql` has. A module input only sends its value when you use
it. When the chart is a local path, the module checks the chart's
`values.yaml`. If the key is missing, the plan fails with an error that names
the key, so the setting is never silently dropped:

| Module input | Chart value it needs | In the chart |
|---|---|---|
| `bundle_sources` | `extraPolicies`: a list appended to the rendered `policies` | Yes. `bundle_source` entries without `cache_dir` get `<cache.mountPath>/bundles` on the chart's `cache` volume |
| `config`, `config_yaml` | `extraConfig`: deep-merged into the rendered Config | Yes (`extraConfig.policies` is refused; use `extraPolicies`) |
| `secret_env` | `extraEnv`: appended to the container's `env` | Not yet |
| `network_policy.egress` | `networkPolicy.egress`: replaces the chart's deny-all `egress: []` | Not yet |
| `proxy` | `proxy.{enabled,replicas,port,config}`: a haltsql-proxy Deployment and Service | Not yet |

The chart's NetworkPolicy denies all egress. Without `egress` rules, OIDC
key fetches, bundle downloads, cloud audit sinks and secret providers all
fail. The server fails closed, and the module raises a `check` warning when
you configure any of these with the NetworkPolicy on.

## haltsql-aws (ECS Fargate)

```hcl
module "haltsql" {
  source      = "github.com/HaltSQL/HaltSQL//deploy/terraform/modules/haltsql-aws"
  name        = "haltsql"
  cluster_arn = aws_ecs_cluster.this.arn
  vpc_id      = var.vpc_id
  subnet_ids  = var.private_subnet_ids
  image       = "ghcr.io/haltsql/haltsql@sha256:..."

  config_yaml = file("haltsql.yaml")
  secrets     = { HALTSQL_AGENT_TOKEN_SHA256 = aws_secretsmanager_secret.token_hash.arn }

  ingress_cidr_blocks = ["10.0.0.0/16"]
  internal_nlb        = { enabled = true }
}
```

- **Task.** The haltsql image is distroless and has no shell. So a
  non-essential `config-writer` container (busybox, `config_init_image`)
  starts first. It base64-decodes `config_yaml` into a task-scoped volume
  and exits. Then `haltsql-server` starts with `dependsOn: SUCCESS`, as uid
  65532, with a read-only root filesystem, no Linux capabilities, an init
  process and the config mounted read-only. Each config change creates a
  new task definition revision. A failed deployment rolls back through the
  ECS circuit breaker.
- **Secrets.** `secrets` maps environment variables to Secrets Manager ARNs
  (optionally `ARN:json-key::`) or SSM parameter ARNs. ECS injects them at
  start.
- **Execution role** (used by ECS). It can write to its own log stream and
  read exactly the injected secrets (plus `kms:Decrypt` on `kms_key_arns`).
  When the image is in ECR, it can also pull from that one repository.
  `ecr:GetAuthorizationToken` needs `Resource: *`, which AWS requires.
- **Task role** (used by haltsql-server). It gets `s3:GetObject` on exactly
  the `s3_bundle_objects` keys and `s3:PutObject` under the
  `s3_audit_destinations` prefixes (plus `s3:PutObjectRetention` with object
  lock). It gets `secretsmanager:GetSecretValue` on exactly the
  `runtime_secret_arns` (for `${aws-sm:...}`) and `kms:Decrypt` or
  `kms:GenerateDataKey` on `kms_key_arns`. With none of these inputs, the
  role has no permissions at all.
- **Network.**
  - The task security group admits the container port only from
    `ingress_cidr_blocks` (`0.0.0.0/0` is rejected), from
    `ingress_security_group_ids`, and from the NLB.
  - Egress is TCP 443 only, to `egress_cidr_blocks` (default `0.0.0.0/0`,
    needed for image pulls and AWS APIs without VPC endpoints) and to
    `egress_prefix_list_ids`. Narrow it to your VPC endpoints where you can.
    This is the one Trivy finding ignored in the modules, `AVD-AWS-0104`,
    and it is ignored explicitly in `network.tf`.
  - `alb_target_group` creates an IP target group that checks `/readyz`,
    for you to attach to your own ALB listener.
  - `internal_nlb` creates an internal NLB with its own security group, and
    deletion protection on by default. The listener passes TCP through, or
    terminates TLS when you set `certificate_arn`.
  - `server_tls` and `health_port` switch the health checks to HTTPS, or to
    the plain-HTTP `--health-listen` port.
- **Logs.** The CloudWatch log group `/ecs/<name>` keeps logs for 365 days by
  default. Use `log_kms_key_arn` to encrypt it, because stdout audit records
  land there too.

## haltsql-azure (Container Apps)

```hcl
module "haltsql" {
  source              = "github.com/HaltSQL/HaltSQL//deploy/terraform/modules/haltsql-azure"
  name                = "haltsql"
  resource_group_name = azurerm_resource_group.this.name
  location            = "westeurope"
  config_yaml         = file("haltsql.yaml")

  key_vault_secrets = {
    HALTSQL_AGENT_TOKEN_SHA256 = { key_vault_id = azurerm_key_vault.this.id, secret_name = "agent-token-sha256" }
  }
}
```

- **Environment.** The module creates a Container Apps environment and a
  Log Analytics workspace (90-day retention), unless you pass
  `container_app_environment_id`. With `environment.infrastructure_subnet_id`
  the environment joins the VNet and uses an internal load balancer by
  default.
- **Identity.** One user-assigned managed identity. It gets
  `Key Vault Secrets User` on each listed secret, scoped to the secret and
  not the vault. The vault must use Azure RBAC. With `acr_id`, it also gets
  `AcrPull` on that one registry, and pulls with the identity. Container
  Apps resolves the Key Vault references with this identity and passes the
  values to the container as environment variables.
- **Config.** `config_yaml` is stored as a Container Apps secret. It is
  mounted read-only at `/etc/haltsql/config/config.yaml` from a secret
  volume, through `sub_path`, so the Key Vault-backed secrets in the same
  volume are not visible as files.
- **Ingress.** Internal by default (`external_enabled = false`), reachable
  only from the environment or its VNet. External ingress requires
  `ingress.allowed_cidrs` (IP restrictions); `0.0.0.0/0` is rejected.
  Container Apps terminates TLS, so `server.tls` in `config_yaml` is
  rejected. `allow_insecure_connections` is off, so the ingress serves
  HTTPS only.
- **Probes and scaling.** A startup probe on `/readyz`, liveness on
  `/healthz` and readiness on `/readyz`. `min_replicas` defaults to 1. An
  HTTP concurrency rule scales out.

## haltsql-gcp (Cloud Run)

```hcl
module "haltsql" {
  source      = "github.com/HaltSQL/HaltSQL//deploy/terraform/modules/haltsql-gcp"
  project_id  = "corp-prod"
  region      = "europe-west1"
  image       = "europe-docker.pkg.dev/corp-prod/haltsql/haltsql@sha256:..."
  config_yaml = file("haltsql.yaml")

  secret_env      = { HALTSQL_AGENT_TOKEN_SHA256 = { secret = "agent-token-sha256", version = "3" } }
  invoker_members = ["serviceAccount:agent@corp-prod.iam.gserviceaccount.com"]
}
```

- **Service account.** A dedicated account with no project-level roles. It
  gets `roles/secretmanager.secretAccessor` on exactly the config secret,
  the `secret_env` secrets and the `runtime_secret_ids` (for
  `${gcp-sm:...}`). It gets `roles/storage.objectCreator` on each
  `audit_gcs_buckets` bucket, so it can create audit objects but not read,
  overwrite or delete them.
- **Config.** `config_yaml` is stored in a Secret Manager secret, which can
  use CMEK or user-managed replication. It is mounted read-only at
  `/etc/haltsql/config.yaml`, the path the image's default command reads.
  The mount pins the secret version, so a config change creates a new
  revision.
- **Ingress and authentication.**
  - Ingress is `INGRESS_TRAFFIC_INTERNAL_ONLY` by default.
  - The Cloud Run invoker IAM check stays on. Callers send a Google ID token
    in `X-Serverless-Authorization` and their haltsql bearer token in
    `Authorization`.
  - `invoker_iam_disabled` leaves authentication to haltsql alone. It is
    accepted only with internal ingress.
  - `allUsers` and `allAuthenticatedUsers` are rejected as invokers.
- **Network.** `vpc_access` enables a Serverless VPC Access connector or
  Direct VPC egress (`network` and `subnetwork`), with `PRIVATE_RANGES_ONLY`
  egress by default.
- **Scaling.** `min_instances` (default 1), `max_instances`, per-instance
  `concurrency`, a startup probe on `/readyz` and liveness on `/healthz`.
  Deletion protection is on by default.

## Tests

The tests use no mock providers and no fake cloud APIs.

```sh
# fmt, init + validate (all 8 directories), terraform test, tflint
# (terraform + aws/azurerm/google rulesets), trivy config (fails on
# HIGH/CRITICAL), and the example Config documents in the real haltsql CLI.
deploy/terraform/test/static-checks.sh

# Real apply on kind: creates the cluster haltsql-terraform, loads a local
# haltsql image (newest haltsql-local:*, else builds one from the
# Dockerfile; HALTSQL_E2E_IMAGE overrides), applies examples/kind, checks
# /healthz, /readyz, /v1/verify (allowed and denied) and 401s through
# kubectl port-forward, plans again (must be empty), destroys, and deletes
# the cluster.
deploy/terraform/test/e2e-kind.sh
```

`modules/haltsql-kubernetes/tests/validation.tftest.hcl` runs with
`terraform test`. It checks that every validation block and fail-closed
precondition rejects bad input. Every run is expected to fail before
Terraform contacts the cluster, so no Kubernetes API is needed.

Both scripts print `SKIP` and exit 0 when Docker or a required tool is
missing.

## Cloud workflow

`.github/workflows/terraform-cloud.yml` is started by hand
(`workflow_dispatch`). Its `action` input is `plan` or `apply-and-destroy`;
its `clouds` input is a subset of `aws,azure,gcp`. Each cloud's job runs only
when that cloud's secrets and variables are set. It authenticates through
OIDC federation and stores no keys:

| Cloud | Secrets | Variables |
|---|---|---|
| AWS | `AWS_ROLE_TO_ASSUME` | `AWS_REGION`, `AWS_VPC_ID`, `AWS_PRIVATE_SUBNET_IDS` (JSON list), `AWS_CALLER_CIDRS` (JSON list) |
| Azure | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | `AZURE_LOCATION` |
| GCP | `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT` | `GCP_PROJECT_ID`, `GCP_REGION`, `GCP_IMAGE` |

`apply-and-destroy` generates a throwaway token hash for each run.
Terraform state stays local to the job, and the job always destroys what it
applied, even after a failure.

Before destroying, each job checks that the deployment is healthy:

- **AWS:** the ECS service reached a steady state, with tasks healthy behind
  the NLB's `/readyz` checks.
- **Azure:** the Container Apps revision is `Healthy`.
- **GCP:** the Cloud Run revision is `Ready`, which means its `/readyz`
  startup probe passed.

## Known limitations

- **The cloud modules have not been applied.** Two Azure behaviours in
  particular are unverified: whether a Container Apps secret volume
  supports `sub_path`, and whether Key Vault references are resolved when
  the role assignment has only just been created. RBAC propagation can take
  minutes, so the first apply may need a retry.
- **The AWS task role is not used by haltsql-server yet.** ECS hands task
  role credentials to containers through the container credentials
  endpoint (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`), which the server's
  AWS credential chain does not read. So on Fargate, `${aws-sm:...}`
  placeholders, S3 bundle sources and S3 audit sinks with `credentials:
  {source: env}` fail closed. They also fail with `web_identity` or `imds`,
  because neither exists on Fargate. Secrets injected by ECS through
  `secrets` (`${env:NAME}`) are not affected. The same gap affects EKS Pod
  Identity.
- **Client certificates do not reach the server on Container Apps or Cloud
  Run.** Both platforms terminate TLS at their ingress, so
  `server.auth.mtls` identities cannot be used there. Use tokens or OIDC,
  or the Kubernetes module with `tls`.
- **The Kubernetes module depends on the Helm chart for some features.**
  `secret_env`, `network_policy.egress` and `proxy` need chart values the
  chart does not have yet (see [Chart extensions](#chart-extensions)); the
  plan fails when you use them. `bundle_sources` and `config`/`config_yaml`
  work with the bundled chart. PDBs
  support only `minAvailable`.
