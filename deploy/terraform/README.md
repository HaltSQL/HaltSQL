# Terraform modules for haltsql-server

| Path | What it is |
|---|---|
| `modules/haltsql-kubernetes` | Any Kubernetes cluster (EKS, AKS, GKE, kind) through `deploy/helm/haltsql`. Applied for real on kind by `test/e2e-kind.sh`. |
| `modules/haltsql-aws` | ECS Fargate. Validated and scanned, not yet applied. |
| `modules/haltsql-azure` | Azure Container Apps. Validated and scanned, not yet applied. |
| `modules/haltsql-gcp` | Cloud Run. Validated and scanned, not yet applied. |
| `examples/{kind,aws,azure,gcp}` | One root module per target, with exact provider pins. |
| `examples/console-kubernetes` | `haltsql-console` (control plane) through `deploy/helm/haltsql-console`, next to a haltsql release. Validated, not applied by a test. Guide: [docs/console/deploy.md](../../docs/console/deploy.md#terraform). |
| `test/static-checks.sh` | fmt, validate, `terraform test`, tflint, trivy. |
| `test/e2e-kind.sh` | Real apply, HTTP checks and destroy on a kind cluster. |

The full documentation is in [docs/terraform.md](../../docs/terraform.md).
