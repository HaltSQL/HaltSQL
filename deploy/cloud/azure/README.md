# HaltSQL on Microsoft Azure: manifests

These are ready-to-edit manifests for [docs/deploy-azure.md](../../../docs/deploy-azure.md).
Replace every `REPLACE_*` value before applying anything. The guide
explains the patterns, the `az` CLI steps that create the identities, Key
Vault, storage and Entra ID app, and the current Azure limitations.

HaltSQL has no Azure-native integrations yet: no Key Vault provider, no Blob
audit sink, no managed-identity credentials. These manifests connect it to
Azure through the Secrets Store CSI driver, Container Apps secret references,
a Vector shipper and an OpenTelemetry Collector. `haltsql-server` itself
needs no Azure identity.

| File | What it is |
|---|---|
| `aks/secretproviderclass.yaml` | Two `SecretProviderClass`es (Key Vault via Workload Identity): the raw token for the agent container, its SHA-256 for the haltsql container. |
| `aks/agent-sidecar.yaml` | **Pattern 1.** Agent + `haltsql-server` sidecar + Vector (audit file to immutable Blob), ServiceAccount for Workload Identity, NetworkPolicy, Managed Prometheus `PodMonitor`. |
| `aks/otel-collector.yaml` | OpenTelemetry Collector: OTLP/HTTP in, `azuremonitor` (Application Insights) out. |
| `aks/values-aks.yaml` | Helm overlay for `deploy/helm/haltsql` as a **shared service**: Entra ID OIDC, TLS 1.3, zone spread, HPA, PDB. |
| `aks/networkpolicy-shared.yaml` | Replaces the chart's deny-all-egress NetworkPolicy (OIDC needs `login.microsoftonline.com`), plus an `azmonitoring.coreos.com` PodMonitor. |
| `aks/externalsecret-tls.yaml` | Optional: sync the chart's TLS Secret from a Key Vault certificate with External Secrets Operator. |
| `aks/proxy.yaml` | **Pattern 3.** `haltsql-proxy` in front of Azure Database for PostgreSQL Flexible Server, with secrets from Key Vault via CSI. |
| `containerapps/Dockerfile` | Bakes the config and policies into an image on top of `ghcr.io/haltsql/haltsql`. |
| `containerapps/haltsql/sidecar.yaml`, `shared.yaml` | haltsql configs for the two Container Apps options (static token / Entra ID). |
| `containerapps/haltsql/policies/` | Example policy. |
| `containerapps/app.yaml` | **Pattern 2A.** Agent + haltsql + collector sidecars in one Container App (`az containerapp create --yaml`). |
| `containerapps/shared-service.yaml` | **Pattern 2B.** haltsql as an internal-ingress shared service. |

## Quick start (AKS sidecar)

```sh
kubectl create namespace agents
kubectl create namespace observability
kubectl -n observability create secret generic appinsights \
  --from-literal=connection-string="$APPINSIGHTS_CONNECTION_STRING"
kubectl apply -f aks/otel-collector.yaml
kubectl apply -f aks/secretproviderclass.yaml
kubectl apply -f aks/agent-sidecar.yaml
```

## Quick start (Container Apps sidecar)

```sh
az acr build -r "$ACR" -t haltsql-analytics:1.0.0 --build-arg CONFIG=sidecar.yaml containerapps
az containerapp create -g "$RG" -n analytics-agent --yaml containerapps/app.yaml
```

## Validation

All YAML files parse. The Kubernetes manifests pass `kubeconform -strict`,
using the CRD catalog schemas for `SecretProviderClass`, `ExternalSecret`,
`SecretStore` and the `azmonitoring.coreos.com` `PodMonitor`. The haltsql
configs load with `haltsql config show`, and the proxy config with
`haltsql-proxy validate`. `values-aks.yaml` renders with `helm template`.
The Container Apps YAML follows the `az containerapp create --yaml` schema
but has not been deployed by CI. To check it, deploy it to a test
environment first.
