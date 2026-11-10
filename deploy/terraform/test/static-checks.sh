#!/usr/bin/env bash
# Static checks for deploy/terraform: no cloud credentials, no mock providers.
#
#   1. terraform fmt -check (whole tree)
#   2. terraform init -backend=false + validate (every module and example)
#   3. terraform test (haltsql-kubernetes input validation and preconditions;
#      haltsql-aws/modules/bundle-object-arns)
#   4. tflint with the terraform, aws, azurerm and google rulesets (Docker)
#   5. trivy config, failing on HIGH/CRITICAL misconfigurations (Docker)
#   6. the example Config documents load in the real haltsql CLI (Docker,
#      when a local haltsql image exists)
#   7. the haltsql-aws bundle read statement against real MinIO (Docker):
#      aws-bundle-policy-minio.sh
#
# Usage: deploy/terraform/test/static-checks.sh
# Environment: GITHUB_TOKEN (optional, avoids GitHub API rate limits when
# tflint downloads its rulesets), HALTSQL_E2E_IMAGE (image for step 6).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_ROOT="$(cd "$HERE/.." && pwd)"

TFLINT_IMAGE=ghcr.io/terraform-linters/tflint:v0.64.0
TRIVY_IMAGE=aquasec/trivy:0.74.0

# directory -> tflint config
DIRS=(
  "modules/haltsql-kubernetes:kubernetes"
  "modules/haltsql-aws:aws"
  "modules/haltsql-azure:azurerm"
  "modules/haltsql-gcp:google"
  "examples/kind:kubernetes"
  "examples/console-kubernetes:kubernetes"
  "examples/aws:aws"
  "examples/azure:azurerm"
  "examples/gcp:google"
)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/haltsql-tf-static.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export TF_IN_AUTOMATION=1
FAILED=0
log() { printf '\n==> %s\n' "$*"; }
bad() { echo "FAIL: $*"; FAILED=1; }

log "terraform fmt -check -recursive"
if terraform fmt -check -recursive -diff "$TF_ROOT"; then echo "ok"; else bad "terraform fmt"; fi

log "terraform init -backend=false + validate"
for entry in "${DIRS[@]}"; do
  dir="${entry%%:*}"
  data="$WORK/tfdata/${dir//\//_}"
  if ! TF_DATA_DIR="$data" terraform -chdir="$TF_ROOT/$dir" init -backend=false -input=false -no-color >"$WORK/init.log" 2>&1; then
    cat "$WORK/init.log"; bad "init $dir"; continue
  fi
  if out="$(TF_DATA_DIR="$data" terraform -chdir="$TF_ROOT/$dir" validate -no-color 2>&1)"; then
    echo "ok   $dir: $(echo "$out" | head -1)"
  else
    echo "$out"; bad "validate $dir"
  fi
done

log "terraform test (modules/haltsql-kubernetes)"
data="$WORK/tfdata/modules_haltsql-kubernetes"
if TF_DATA_DIR="$data" terraform -chdir="$TF_ROOT/modules/haltsql-kubernetes" test -no-color >"$WORK/test.log" 2>&1; then
  tail -1 "$WORK/test.log"
else
  cat "$WORK/test.log"; bad "terraform test"
fi

log "terraform test (modules/haltsql-aws/modules/bundle-object-arns)"
data="$WORK/tfdata/modules_haltsql-aws_bundle-object-arns"
arns_dir="$TF_ROOT/modules/haltsql-aws/modules/bundle-object-arns"
if TF_DATA_DIR="$data" terraform -chdir="$arns_dir" init -backend=false -input=false -no-color >"$WORK/init.log" 2>&1 &&
  TF_DATA_DIR="$data" terraform -chdir="$arns_dir" test -no-color >"$WORK/test.log" 2>&1; then
  tail -1 "$WORK/test.log"
else
  cat "$WORK/init.log" "$WORK/test.log" 2>/dev/null; bad "terraform test bundle-object-arns"
fi

if ! docker info >/dev/null 2>&1; then
  log "SKIP: tflint, trivy, config and MinIO checks need Docker, which is not reachable"
  [ "$FAILED" = 0 ] || exit 1
  exit 0
fi

log "tflint ($TFLINT_IMAGE)"
PLUGINS="$TF_ROOT/.tflint.d"
mkdir -p "$PLUGINS"
TFLINT=(docker run --rm -e TFLINT_PLUGIN_DIR=/plugins -e GITHUB_TOKEN="${GITHUB_TOKEN:-}"
  -v "$PLUGINS:/plugins" -v "$TF_ROOT:/tf:ro" --entrypoint tflint "$TFLINT_IMAGE")
for cfg in kubernetes aws azurerm google; do
  if ! "${TFLINT[@]}" --init --config "/tf/test/tflint/$cfg.hcl" >"$WORK/tflint-init.log" 2>&1; then
    cat "$WORK/tflint-init.log"; bad "tflint --init ($cfg ruleset)"
  fi
done
for entry in "${DIRS[@]}"; do
  dir="${entry%%:*}"; cfg="${entry##*:}"
  if out="$("${TFLINT[@]}" --chdir "/tf/$dir" --config "/tf/test/tflint/$cfg.hcl" --format compact 2>&1)"; then
    if [ "$cfg" = kubernetes ]; then rules=terraform; else rules="terraform, $cfg"; fi
    echo "ok   $dir (rulesets: $rules)"
  else
    echo "$out"; bad "tflint $dir"
  fi
done

log "trivy config --severity HIGH,CRITICAL ($TRIVY_IMAGE)"
mkdir -p "$WORK/trivy-cache"
# Run as the invoking user: as root, trivy fills the cache with root-owned
# files (the checks bundle it downloads) that the EXIT trap cannot delete on a
# non-root CI runner, which fails the script after every check has passed.
if docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$TF_ROOT:/src:ro" -v "$WORK/trivy-cache:/cache" "$TRIVY_IMAGE" \
  config --cache-dir /cache --quiet --severity HIGH,CRITICAL --exit-code 1 \
  --skip-dirs '**/.terraform' /src >"$WORK/trivy.log" 2>&1; then
  grep -E 'Tests:|Failures:' "$WORK/trivy.log" | head -5 || true
  echo "ok   no HIGH or CRITICAL misconfigurations"
else
  cat "$WORK/trivy.log"; bad "trivy config"
fi

log "example Config documents load in the haltsql CLI"
IMAGE="${HALTSQL_E2E_IMAGE:-$(docker images haltsql-local --format '{{.Repository}}:{{.Tag}}' | grep -v ':<none>$' | head -1 || true)}"
if [ -z "$IMAGE" ]; then
  echo "SKIP: no local haltsql image (set HALTSQL_E2E_IMAGE or build haltsql-local)"
else
  hash="$(printf 'example' | openssl dgst -sha256 -r | cut -d' ' -f1)"
  for cloud in aws azure gcp; do
    if docker run --rm -e HALTSQL_AGENT_TOKEN_SHA256="$hash" -v "$TF_ROOT/examples/$cloud:/cfg:ro" \
      --entrypoint /usr/local/bin/haltsql "$IMAGE" config show --config /cfg/haltsql.yaml >"$WORK/cfg.log" 2>&1; then
      echo "ok   examples/$cloud/haltsql.yaml ($IMAGE)"
    else
      cat "$WORK/cfg.log"; bad "examples/$cloud/haltsql.yaml does not load"
    fi
  done
fi

log "haltsql-aws bundle read statement against MinIO"
if "$HERE/aws-bundle-policy-minio.sh"; then :; else bad "aws-bundle-policy-minio.sh"; fi

if [ "$FAILED" = 0 ]; then log "PASS: static checks"; else log "FAILED: static checks"; exit 1; fi
