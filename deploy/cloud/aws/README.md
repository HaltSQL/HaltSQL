# AWS reference artifacts

Starting points for running HaltSQL on AWS. The walkthrough, with diagrams, is
in [docs/deploy-aws.md](../../../docs/deploy-aws.md). Every file uses
placeholder values: account `111122223333`, region `eu-west-1`, bucket
`corp-haltsql-audit`, and so on. Replace them before use.

| Path | What it is |
|---|---|
| `eks/sidecar.yaml` | EKS sidecar pattern: ServiceAccount with IRSA, config and policy ConfigMaps, agent Deployment with a `haltsql` container, and a no-ingress NetworkPolicy. Token hashes come from Secrets Manager (`${aws-sm:...}`). Audit goes to S3 with Object Lock. OTLP goes to an ADOT collector. |
| `eks/values-eks.yaml` | Helm overlay for `deploy/helm/haltsql` (shared service on EKS): IRSA annotation, S3 Object Lock sink, built-in TLS, HPA, PDB, zone spreading. |
| `eks/networkpolicy-shared.yaml` | Replaces the chart's deny-all-egress NetworkPolicy, so that STS, S3 and the ADOT collector are reachable. |
| `ecs/task-definition.json` | ECS Fargate shared service: `haltsql-server` on `:8443` with TLS, secrets injected from Secrets Manager, audit to CloudWatch Logs (`awslogs`, blocking mode), and an ADOT sidecar that sends traces to X-Ray and metrics to AMP. |
| `ecs/Dockerfile`, `ecs/config.yaml`, `ecs/policies/` | Derived image that bakes in the config and policies, since ECS has no ConfigMaps. |
| `ecs/proxy-task-definition.json`, `ecs/Dockerfile.proxy`, `ecs/proxy.yaml` | `haltsql-proxy` on Fargate behind an internal NLB, in front of RDS. An init container writes the TLS certificate and key files. (The proxy also accepts inline PEM, for example through `${env:...}`.) |
| `iam/haltsql-policy.json` | Least privilege for `haltsql-server`: `s3:PutObject` and `s3:PutObjectRetention` on the audit prefix, `secretsmanager:GetSecretValue` on named secrets, and KMS restricted with `kms:ViaService`. |
| `iam/irsa-trust-policy.json` | Trust policy that lets one Kubernetes service account assume the role. |
| `iam/ecs-task-execution-policy.json` | Lets the ECS execution role inject the secrets. |
| `iam/adot-task-role-policy.json` | ADOT sidecar permissions: X-Ray writes and `aps:RemoteWrite`. |
| `terraform/` | Supporting resources, not the server itself (for that, see `deploy/terraform/modules/haltsql-aws` and [terraform.md](../../../docs/terraform.md)):  KMS key, Object Lock audit bucket (versioning, SSE-KMS, TLS-only, no public access, Glacier IR lifecycle), the IAM policy, and an optional IRSA role. |

## Validation

The following checks were run on these files:

- `jq empty` on every JSON file.
- `kubeconform` on `eks/*.yaml`, and on the chart rendered with
  `values-eks.yaml` (`helm template`).
- `haltsql config show` on `ecs/config.yaml`, on the config embedded in
  `eks/sidecar.yaml`, and on the config the chart renders.
- `haltsql validate` on `ecs/policies/*`.
- `haltsql-proxy validate` on `ecs/proxy.yaml`.
- `terraform fmt -check` and `terraform validate` on `terraform/`.

Re-run them after you edit the files:

```sh
jq empty deploy/cloud/aws/iam/*.json deploy/cloud/aws/ecs/*.json
helm template haltsql deploy/helm/haltsql -f deploy/cloud/aws/eks/values-eks.yaml | kubeconform -summary -
kubeconform -summary deploy/cloud/aws/eks/sidecar.yaml deploy/cloud/aws/eks/networkpolicy-shared.yaml
(cd deploy/cloud/aws/terraform && terraform init -backend=false && terraform validate)
```
