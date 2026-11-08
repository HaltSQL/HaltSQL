# Google Cloud manifests for HaltSQL

Ready-to-edit files for the patterns in
[docs/deploy-gcp.md](../../../docs/deploy-gcp.md). Read that guide first: it
explains when to use each pattern, the IAM model, networking, audit retention
and the production checklist.

| Path | Pattern | What it is |
|---|---|---|
| `iam/setup.sh` | all | `gcloud` commands for service accounts, secrets, buckets and least-privilege IAM bindings, one subcommand per pattern. |
| `gke/sidecar.yaml` | GKE sidecar | Namespace, KSA with the Workload Identity annotation, haltsql config + policy, agent Deployment with haltsql-server and Cloud SQL Auth Proxy as native sidecars, NetworkPolicy, PodMonitoring. |
| `gke/otel-collector.yaml` | GKE (both) | OpenTelemetry Collector that forwards haltsql spans to Cloud Trace. |
| `gke/values-gke.yaml` | GKE shared service | Helm values for `deploy/helm/haltsql`: Workload Identity, GCS audit sink, built-in TLS, Google ID token (OIDC) auth, egress for the metadata server. |
| `gke/shared-extras.yaml` | GKE shared service | PodMonitoring for the chart (Managed Service for Prometheus). |
| `cloudrun/service-sidecar.yaml` | Cloud Run sidecar | Multi-container service: agent (ingress) + haltsql-server + OTel Collector. |
| `cloudrun/haltsql-sidecar-config.yaml` | Cloud Run sidecar | haltsql config, uploaded to Secret Manager and mounted as a file. |
| `cloudrun/otel-collector-config.yaml` | Cloud Run sidecar | Collector config: OTLP traces to Cloud Trace, `/metrics` scrape to Managed Prometheus. |
| `cloudrun/service-internal.yaml` | Cloud Run internal | haltsql-server as its own service, `ingress: internal`, IAM invoker only, signed bundle from a Cloud Storage volume. |
| `cloudrun/haltsql-internal-config.yaml` | Cloud Run internal | haltsql config with one Google ID token provider per calling service account. |
| `proxy/haltsql-proxy.yaml` | Proxy | haltsql-proxy + Cloud SQL Auth Proxy on GKE, secrets from the GKE Secret Manager add-on, internal load balancer. |

Every value to change is spelled `REPLACE_ME...`:

```sh
grep -rn REPLACE_ME deploy/cloud/gcp/
```

## Validation done on these files

- Every YAML file parses; Kubernetes objects pass
  `kubeconform -strict` (Kubernetes 1.30 schemas plus the CRD catalog for
  PodMonitoring, SecretProviderClass and the Knative `Service` that Cloud Run
  accepts).
- `helm template deploy/helm/haltsql -f gke/values-gke.yaml` renders, and the
  rendered config passes `haltsql config show`.
- The haltsql configs (GKE sidecar, both Cloud Run configs) pass
  `haltsql config show` with the placeholders filled in, including a real
  signed bundle for the internal service. The proxy config passes
  `haltsql-proxy validate`.
- `iam/setup.sh` passes `bash -n` and `shellcheck`.

None of this was applied to a live project. Run the manifests in a staging
project first.
