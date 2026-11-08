#!/usr/bin/env bash
# Least-privilege Google Cloud setup for HaltSQL. Each subcommand creates the
# service accounts, secrets, buckets and IAM bindings for one pattern in
# docs/deploy-gcp.md. Every grant is on a single resource (a secret, a bucket)
# unless the role only exists at project level (Cloud SQL, Trace, Monitoring).
#
#   export PROJECT_ID=my-project REGION=europe-west1
#   deploy/cloud/gcp/iam/setup.sh apis
#   deploy/cloud/gcp/iam/setup.sh audit-bucket
#   deploy/cloud/gcp/iam/setup.sh gke-sidecar          # or another pattern
#
# Subcommands are idempotent where gcloud allows it: "already exists" errors
# from create calls are reported and skipped. Nothing here deletes anything.
# Read each function before running it in a production project.
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:?set REGION}"
AUDIT_BUCKET="${AUDIT_BUCKET:-${PROJECT_ID}-haltsql-audit}"
POLICY_BUCKET="${POLICY_BUCKET:-${PROJECT_ID}-haltsql-policies}"
AUDIT_RETENTION="${AUDIT_RETENTION:-400d}"   # how long audit objects cannot be deleted
AR_REPO="${AR_REPO:-ghcr}"                     # Artifact Registry remote repo for ghcr.io
K8S_NAMESPACE="${K8S_NAMESPACE:-agents}"
K8S_SA="${K8S_SA:-analytics-agent}"

gcloud config set project "$PROJECT_ID" >/dev/null

sa_email() { printf '%s@%s.iam.gserviceaccount.com' "$1" "$PROJECT_ID"; }

sha256_hex() {
  if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}

try() { "$@" || echo "  (skipped: $1 ${2:-} ${3:-} failed, probably already exists)"; }

create_sa() { # name, description
  try gcloud iam service-accounts create "$1" --display-name "$2"
}

secret_from_stdin() { # name; value on stdin, never on the command line
  if gcloud secrets describe "$1" >/dev/null 2>&1; then
    gcloud secrets versions add "$1" --data-file=-
  else
    gcloud secrets create "$1" --replication-policy=automatic --data-file=-
  fi
}

grant_secret() { # secret, sa-name
  gcloud secrets add-iam-policy-binding "$1" \
    --member "serviceAccount:$(sa_email "$2")" \
    --role roles/secretmanager.secretAccessor >/dev/null
}

grant_audit_writer() { # sa-name. Create-only: no get, list, overwrite or delete.
  gcloud storage buckets add-iam-policy-binding "gs://${AUDIT_BUCKET}" \
    --member "serviceAccount:$(sa_email "$1")" \
    --role roles/storage.objectCreator >/dev/null
}

grant_project() { # sa-name, role
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member "serviceAccount:$(sa_email "$1")" --role "$2" \
    --condition=None >/dev/null
}

workload_identity() { # gsa-name, namespace, ksa
  gcloud iam service-accounts add-iam-policy-binding "$(sa_email "$1")" \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:${PROJECT_ID}.svc.id.goog[$2/$3]" >/dev/null
}

new_agent_token() { # token-secret, hash-secret. The token is never printed.
  local token
  token="$(openssl rand -hex 32)"
  printf '%s' "$token" | secret_from_stdin "$1"
  printf '%s' "$token" | sha256_hex | tr -d '\n' | secret_from_stdin "$2"
  unset token
}

cmd_apis() {
  gcloud services enable \
    secretmanager.googleapis.com storage.googleapis.com iamcredentials.googleapis.com \
    container.googleapis.com run.googleapis.com artifactregistry.googleapis.com \
    sqladmin.googleapis.com cloudtrace.googleapis.com monitoring.googleapis.com \
    logging.googleapis.com
}

cmd_audit_bucket() {
  try gcloud storage buckets create "gs://${AUDIT_BUCKET}" \
    --location "$REGION" \
    --uniform-bucket-level-access \
    --public-access-prevention \
    --retention-period "$AUDIT_RETENTION"
  cat <<EOF

Audit bucket gs://${AUDIT_BUCKET} has an UNLOCKED ${AUDIT_RETENTION} retention policy.
After you have checked the retention period, lock it (irreversible: the policy
can then never be shortened or removed, and the bucket cannot be deleted while
it holds objects younger than the retention period):

  gcloud storage buckets update gs://${AUDIT_BUCKET} --lock-retention-period
EOF
}

# Mirror ghcr.io through an Artifact Registry remote repository. Cloud Run only
# pulls from Artifact Registry, Container Registry and Docker Hub.
cmd_image() {
  try gcloud artifacts repositories create "$AR_REPO" \
    --repository-format docker --location "$REGION" \
    --mode remote-repository --remote-docker-repo https://ghcr.io \
    --description "ghcr.io mirror"
  echo "Image: ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/haltsql/haltsql:<version>"
}

# GKE sidecar: agent + haltsql-server + cloud-sql-proxy share one pod, so they
# share one identity (haltsql-agent).
cmd_gke_sidecar() {
  local gsa=haltsql-agent
  create_sa "$gsa" "HaltSQL agent pod (GKE sidecar)"
  new_agent_token haltsql-analytics-agent-token haltsql-analytics-agent-token-sha256
  grant_secret haltsql-analytics-agent-token-sha256 "$gsa"   # haltsql-server
  grant_secret haltsql-analytics-agent-token "$gsa"          # the agent
  grant_audit_writer "$gsa"
  grant_project "$gsa" roles/cloudsql.client                 # cloud-sql-proxy
  grant_project "$gsa" roles/cloudsql.instanceUser           # IAM database login
  workload_identity "$gsa" "$K8S_NAMESPACE" "$K8S_SA"
  echo "Create the IAM database user:"
  echo "  gcloud sql users create $(sa_email "$gsa" | sed 's/\.gserviceaccount\.com$//') --instance INSTANCE --type cloud_iam_service_account"
}

# Shared haltsql-server on GKE (Helm chart, values-gke.yaml). Callers use
# Google ID tokens, so there are no token secrets.
cmd_gke_shared() {
  local gsa=haltsql-server
  create_sa "$gsa" "HaltSQL shared server"
  grant_audit_writer "$gsa"
  workload_identity "$gsa" haltsql haltsql
  echo "Unique ID of each calling GSA (goes in required_claims.sub):"
  echo "  gcloud iam service-accounts describe EMAIL --format='value(uniqueId)'"
}

# OpenTelemetry Collector on GKE (gke/otel-collector.yaml).
cmd_collector() {
  local gsa=haltsql-otel
  create_sa "$gsa" "OpenTelemetry Collector for HaltSQL"
  grant_project "$gsa" roles/cloudtrace.agent
  grant_project "$gsa" roles/monitoring.metricWriter
  workload_identity "$gsa" observability otel-collector
}

# Cloud Run multi-container service (cloudrun/service-sidecar.yaml).
cmd_cloud_run_sidecar() {
  local gsa=haltsql-agent here
  here="$(cd "$(dirname "$0")/../cloudrun" && pwd)"
  create_sa "$gsa" "HaltSQL agent service (Cloud Run sidecar)"
  new_agent_token haltsql-analytics-agent-token haltsql-analytics-agent-token-sha256
  secret_from_stdin haltsql-sidecar-config < "$here/haltsql-sidecar-config.yaml"
  secret_from_stdin haltsql-otel-config < "$here/otel-collector-config.yaml"
  : "${POLICY_FILE:?set POLICY_FILE to the analytics-agent policy file}"
  secret_from_stdin haltsql-policy-analytics-agent < "$POLICY_FILE"
  for s in haltsql-analytics-agent-token haltsql-analytics-agent-token-sha256 \
           haltsql-sidecar-config haltsql-otel-config haltsql-policy-analytics-agent; do
    grant_secret "$s" "$gsa"
  done
  grant_audit_writer "$gsa"
  grant_project "$gsa" roles/cloudtrace.agent
  grant_project "$gsa" roles/monitoring.metricWriter
  grant_project "$gsa" roles/cloudsql.client
  grant_project "$gsa" roles/cloudsql.instanceUser
}

# Shared internal Cloud Run service (cloudrun/service-internal.yaml).
cmd_cloud_run_internal() {
  local gsa=haltsql-server here
  here="$(cd "$(dirname "$0")/../cloudrun" && pwd)"
  create_sa "$gsa" "HaltSQL shared server (Cloud Run)"
  try gcloud storage buckets create "gs://${POLICY_BUCKET}" \
    --location "$REGION" --uniform-bucket-level-access --public-access-prevention
  gcloud storage buckets add-iam-policy-binding "gs://${POLICY_BUCKET}" \
    --member "serviceAccount:$(sa_email "$gsa")" \
    --role roles/storage.objectViewer >/dev/null
  echo "Edit $here/haltsql-internal-config.yaml (public key, unique IDs) before uploading it."
  secret_from_stdin haltsql-internal-config < "$here/haltsql-internal-config.yaml"
  grant_secret haltsql-internal-config "$gsa"
  grant_audit_writer "$gsa"
  echo "Grant each caller roles/run.invoker on the service after deploying it:"
  echo "  gcloud run services add-iam-policy-binding haltsql --region $REGION \\"
  echo "    --member serviceAccount:CALLER_EMAIL --role roles/run.invoker"
}

# haltsql-proxy in front of Cloud SQL (proxy/haltsql-proxy.yaml).
cmd_proxy() {
  local gsa=haltsql-proxy
  create_sa "$gsa" "HaltSQL wire proxy"
  for s in haltsql-proxy-upstream-password haltsql-proxy-tls-crt \
           haltsql-proxy-tls-key haltsql-proxy-scram-analytics-agent; do
    if ! gcloud secrets describe "$s" >/dev/null 2>&1; then
      echo "  create secret $s first, e.g.: gcloud secrets create $s --data-file=FILE"
      continue
    fi
    grant_secret "$s" "$gsa"
  done
  grant_project "$gsa" roles/cloudsql.client
  workload_identity "$gsa" haltsql haltsql-proxy
  echo "SCRAM verifier for a proxy user (password read from stdin, never stored):"
  echo "  haltsql-proxy scram-verifier | gcloud secrets create haltsql-proxy-scram-analytics-agent --data-file=-"
}

case "${1:-}" in
  apis) cmd_apis ;;
  audit-bucket) cmd_audit_bucket ;;
  image) cmd_image ;;
  gke-sidecar) cmd_gke_sidecar ;;
  gke-shared) cmd_gke_shared ;;
  collector) cmd_collector ;;
  cloud-run-sidecar) cmd_cloud_run_sidecar ;;
  cloud-run-internal) cmd_cloud_run_internal ;;
  proxy) cmd_proxy ;;
  *)
    echo "usage: $0 {apis|audit-bucket|image|gke-sidecar|gke-shared|collector|cloud-run-sidecar|cloud-run-internal|proxy}" >&2
    exit 2 ;;
esac
