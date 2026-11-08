#!/usr/bin/env bash
# Real end-to-end test of the haltsql-kubernetes module: a local kind cluster,
# a locally built haltsql image, terraform apply of examples/kind, HTTP checks
# through a port-forward, an idempotency plan, terraform destroy, and cluster
# deletion. No mocks: the real chart, the real server, a real Kubernetes API.
#
# Usage: deploy/terraform/test/e2e-kind.sh
#
# Environment:
#   HALTSQL_E2E_IMAGE   image to load (default: newest haltsql-local:* image,
#                       otherwise one is built from the repository Dockerfile)
#   HALTSQL_E2E_PORT    local port for the port-forward (default 18480)
#   KEEP_CLUSTER=1      leave the kind cluster running afterwards
#
# Exits 0 with a SKIP message when Docker, kind, kubectl or terraform is
# missing, so it can run unconditionally from a test runner.

set -euo pipefail

CLUSTER=haltsql-terraform
LOCAL_IMAGE=haltsql-local:e2e
PORT="${HALTSQL_E2E_PORT:-18480}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
EXAMPLE="$REPO/deploy/terraform/examples/kind"

skip() { echo "SKIP: $*"; exit 0; }
log() { printf '\n==> %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in docker kind kubectl terraform curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed"
done
docker info >/dev/null 2>&1 || skip "the Docker daemon is not reachable"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/haltsql-tf-e2e.XXXXXX")"
KUBECONFIG_FILE="$WORK/kubeconfig"
STATE="$WORK/terraform.tfstate"
export TF_DATA_DIR="$WORK/tfdata"
export TF_IN_AUTOMATION=1
PF_PID=""
CREATED_CLUSTER=0
APPLIED=0

cleanup() {
  local rc=$?
  set +e
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null && wait "$PF_PID" 2>/dev/null
  if [ "$APPLIED" = 1 ]; then
    log "cleanup: terraform destroy"
    terraform -chdir="$EXAMPLE" destroy -auto-approve -input=false -no-color \
      -state="$STATE" "${TFVARS[@]}" >"$WORK/destroy.log" 2>&1 || tail -20 "$WORK/destroy.log"
  fi
  if [ "$CREATED_CLUSTER" = 1 ] && [ "${KEEP_CLUSTER:-0}" != 1 ]; then
    log "cleanup: deleting kind cluster $CLUSTER"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
log "kind cluster $CLUSTER"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "reusing the existing cluster"
else
  kind create cluster --name "$CLUSTER" --wait 180s >"$WORK/kind.log" 2>&1 \
    || { tail -20 "$WORK/kind.log"; fail "kind create cluster"; }
  CREATED_CLUSTER=1
fi
kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG_FILE"
KCTL=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "kind-$CLUSTER")
"${KCTL[@]}" wait --for=condition=Ready node --all --timeout=180s >/dev/null

# ---------------------------------------------------------------------------
log "image"
IMAGE="${HALTSQL_E2E_IMAGE:-}"
if [ -z "$IMAGE" ]; then
  IMAGE="$(docker images haltsql-local --format '{{.Repository}}:{{.Tag}}' | grep -v ':<none>$' | head -1 || true)"
fi
if [ -z "$IMAGE" ]; then
  echo "no haltsql-local image: building one from $REPO/Dockerfile (slow the first time)"
  docker build -t "$LOCAL_IMAGE" "$REPO" >"$WORK/build.log" 2>&1 \
    || { tail -40 "$WORK/build.log"; fail "docker build"; }
  IMAGE="$LOCAL_IMAGE"
fi
echo "using $IMAGE"
[ "$IMAGE" = "$LOCAL_IMAGE" ] || docker tag "$IMAGE" "$LOCAL_IMAGE"
kind load docker-image "$LOCAL_IMAGE" --name "$CLUSTER" >/dev/null

# ---------------------------------------------------------------------------
log "terraform apply (examples/kind)"
TOKEN="$(openssl rand -hex 32)"
TOKEN_SHA256="$(printf '%s' "$TOKEN" | openssl dgst -sha256 -r | cut -d' ' -f1)"
TFVARS=(-var "kubeconfig_path=$KUBECONFIG_FILE" -var "kube_context=kind-$CLUSTER"
  -var "image_repository=${LOCAL_IMAGE%%:*}" -var "image_tag=${LOCAL_IMAGE##*:}"
  -var "token_sha256=$TOKEN_SHA256")

terraform -chdir="$EXAMPLE" init -backend=false -input=false -no-color >"$WORK/init.log" 2>&1 \
  || { cat "$WORK/init.log"; fail "terraform init"; }
APPLIED=1
terraform -chdir="$EXAMPLE" apply -auto-approve -input=false -no-color \
  -state="$STATE" "${TFVARS[@]}" >"$WORK/apply.log" 2>&1 \
  || { tail -40 "$WORK/apply.log"; fail "terraform apply"; }
grep -E '^Apply complete' "$WORK/apply.log"

NS="$(terraform -chdir="$EXAMPLE" output -state="$STATE" -raw namespace)"
SVC="$(terraform -chdir="$EXAMPLE" output -state="$STATE" -raw service_name)"
SVC_PORT="$(terraform -chdir="$EXAMPLE" output -state="$STATE" -raw service_port)"
echo "service $NS/$SVC:$SVC_PORT"

log "cluster objects"
"${KCTL[@]}" -n "$NS" get deploy,svc,pdb,networkpolicy,sa -o name
READY="$("${KCTL[@]}" -n "$NS" get deploy "$SVC" -o jsonpath='{.status.readyReplicas}')"
[ "$READY" = 2 ] || fail "expected 2 ready replicas, got '$READY'"
echo "ready replicas: $READY"
PSS="$("${KCTL[@]}" get ns "$NS" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
[ "$PSS" = restricted ] || fail "namespace is not labelled pod-security enforce=restricted"
echo "namespace pod-security enforce: $PSS"

# ---------------------------------------------------------------------------
log "idempotency: terraform plan after apply must be empty"
set +e
terraform -chdir="$EXAMPLE" plan -detailed-exitcode -input=false -no-color \
  -state="$STATE" "${TFVARS[@]}" >"$WORK/plan.log" 2>&1
PLAN_RC=$?
set -e
[ "$PLAN_RC" = 0 ] || { tail -40 "$WORK/plan.log"; fail "plan after apply is not empty (exit $PLAN_RC)"; }
echo "no changes"

# ---------------------------------------------------------------------------
log "HTTP checks through kubectl port-forward svc/$SVC $PORT:$SVC_PORT"
"${KCTL[@]}" -n "$NS" port-forward "svc/$SVC" "$PORT:$SVC_PORT" >"$WORK/pf.log" 2>&1 &
PF_PID=$!
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 60); do
  curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null && break
  sleep 0.5
done

check_status() { # name expected-status curl-args...
  local name=$1 want=$2; shift 2
  local got
  got="$(curl -sS -o "$WORK/body" -w '%{http_code}' "$@")"
  if [ "$got" != "$want" ]; then
    echo "body: $(head -c 400 "$WORK/body")"
    fail "$name: HTTP $got, expected $want"
  fi
  echo "ok   $name -> $got"
}

check_status "GET /healthz" 200 "$BASE/healthz"
check_status "GET /readyz" 200 "$BASE/readyz"

verify() { # name sql expected-allowed
  local name=$1 sql=$2 want=$3
  check_status "POST /v1/verify ($name)" 200 "$BASE/v1/verify" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"sql\":\"$sql\",\"context\":{\"tenant_id\":\"acme\"}}"
  grep -q "\"allowed\": *$want" "$WORK/body" \
    || { echo "body: $(head -c 400 "$WORK/body")"; fail "$name: expected allowed=$want"; }
  echo "     allowed=$want"
}
verify "tenant-scoped select" "SELECT id, status FROM orders WHERE tenant_id = \$1 LIMIT 10" true
grep -q '"value": *"acme"' "$WORK/body" || fail "the verdict does not bind tenant_id to acme"
echo "     bind_params: \$1 = acme"
verify "tenant literal is denied (bound mode)" "SELECT id FROM orders WHERE tenant_id = 'acme' LIMIT 10" false
verify "delete is denied" "DELETE FROM orders WHERE tenant_id = 'acme'" false
verify "unknown table is denied" "SELECT * FROM pg_shadow LIMIT 1" false

check_status "POST /v1/verify without a token" 401 "$BASE/v1/verify" \
  -H 'Content-Type: application/json' -d '{"sql":"SELECT 1"}'
check_status "POST /v1/verify with a wrong token" 401 "$BASE/v1/verify" \
  -H "Authorization: Bearer $(openssl rand -hex 32)" -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT 1"}'

kill "$PF_PID" 2>/dev/null; wait "$PF_PID" 2>/dev/null || true
PF_PID=""

# ---------------------------------------------------------------------------
log "terraform destroy"
terraform -chdir="$EXAMPLE" destroy -auto-approve -input=false -no-color \
  -state="$STATE" "${TFVARS[@]}" >"$WORK/destroy.log" 2>&1 \
  || { tail -40 "$WORK/destroy.log"; fail "terraform destroy"; }
APPLIED=0
grep -E '^Destroy complete' "$WORK/destroy.log"
for _ in $(seq 1 60); do
  "${KCTL[@]}" get ns "$NS" >/dev/null 2>&1 || break
  sleep 1
done
if "${KCTL[@]}" get ns "$NS" >/dev/null 2>&1; then fail "namespace $NS still exists after destroy"; fi
echo "namespace $NS is gone"

log "PASS: haltsql-kubernetes end-to-end on kind"
