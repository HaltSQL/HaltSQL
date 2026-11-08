# Cloud architecture diagrams

The cloud reference architectures in [`docs/deploy-aws.md`](../../docs/deploy-aws.md),
[`docs/deploy-gcp.md`](../../docs/deploy-gcp.md) and
[`docs/deploy-azure.md`](../../docs/deploy-azure.md) are drawn as code with
[mingrammer/diagrams](https://github.com/mingrammer/diagrams). Every other
diagram in the docs is Mermaid, written inline in the Markdown.

One script per diagram, each writing one PNG to `docs/assets/cloud/`:

| Script | Output | Shows |
|---|---|---|
| `aws_eks_sidecar.py` | `aws-eks-sidecar.png` | AWS: EKS sidecar with IRSA |
| `aws_ecs_shared.py` | `aws-ecs-shared.png` | AWS: ECS Fargate shared service |
| `aws_proxy_rds.py` | `aws-proxy-rds.png` | AWS: haltsql-proxy in front of RDS |
| `gcp_gke_sidecar.py` | `gcp-gke-sidecar.png` | GCP: GKE sidecar with Workload Identity |
| `gcp_cloud_run_sidecar.py` | `gcp-cloud-run-sidecar.png` | GCP: Cloud Run, sidecar container |
| `gcp_cloud_run_internal.py` | `gcp-cloud-run-internal.png` | GCP: Cloud Run, internal shared service |
| `gcp_proxy_cloud_sql.py` | `gcp-proxy-cloud-sql.png` | GCP: haltsql-proxy in front of Cloud SQL |
| `azure_aks_sidecar.py` | `azure-aks-sidecar.png` | Azure: AKS sidecar with Workload Identity |
| `azure_container_apps_sidecar.py` | `azure-container-apps-sidecar.png` | Azure: Container Apps, sidecar container |
| `azure_container_apps_shared.py` | `azure-container-apps-shared.png` | Azure: Container Apps, shared internal service |
| `azure_proxy.py` | `azure-proxy.png` | Azure: haltsql-proxy in front of Flexible Server |

## Regenerating

You need Python 3.9+ and Graphviz (`brew install graphviz` or
`apt-get install graphviz`). From the repository root:

```sh
make diagrams
```

This creates a virtualenv in `deploy/diagrams/.venv`, installs the pinned
`diagrams` version from `requirements.txt`, and runs every script. To run one
script directly:

```sh
deploy/diagrams/.venv/bin/python deploy/diagrams/aws_eks_sidecar.py
```

The scripts resolve output paths from their own location, so they can be run
from any directory. Commit the regenerated PNGs together with the script change.

## Style

`_style.py` holds the shared look: edges are routed orthogonally (only
horizontal and vertical segments) and every label is lifted above its line.
Import `Edge` and `ORTHO` from it instead of from `diagrams`, and merge `ORTHO`
into the diagram's `graph_attr`. Graphviz places labels before it routes
orthogonal edges, so after a layout change check each PNG for a label that
drifted onto another line. Setting `HALTSQL_DIAGRAM_SPLINES=polyline` (or
`spline`) renders with another routing mode for comparison.
