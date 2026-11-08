#!/usr/bin/env bash
# The haltsql-aws task role's ReadPolicyBundles statement, checked against a
# real S3 implementation (MinIO in Docker): the ARNs come from the module's own
# modules/bundle-object-arns (terraform apply, no providers, no credentials),
# the statement has the same shape as in iam.tf (s3:GetObject on exactly those
# ARNs), and a user holding only that policy must be able to GET the bundle key
# and key.sig, and nothing else.
#
# Regression: the statement listed the bundle key only, so the signature GET
# was denied and every S3 bundle_source deployed with haltsql-aws failed.
#
# Usage: deploy/terraform/test/aws-bundle-policy-minio.sh  (needs terraform, Docker)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE="$(cd "$HERE/../modules/haltsql-aws/modules/bundle-object-arns" && pwd)"
IMAGE=pgsty/minio:latest
NAME="haltsql-tfcheck-minio-$$"

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: the MinIO check needs Docker, which is not reachable"; exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/haltsql-tf-minio.XXXXXX")"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

cp "$MODULE"/*.tf "$WORK/"
cat >"$WORK/check.auto.tfvars.json" <<'JSON'
{"partition": "aws",
 "objects": [{"bucket": "bundles", "key": "prod/policy.haltsqlbundle"}]}
JSON
TF_DATA_DIR="$WORK/.tf" terraform -chdir="$WORK" init -backend=false -input=false >/dev/null
TF_DATA_DIR="$WORK/.tf" terraform -chdir="$WORK" apply -auto-approve -input=false -no-color \
  -state="$WORK/state.tfstate" >/dev/null
ARNS="$(TF_DATA_DIR="$WORK/.tf" terraform -chdir="$WORK" output -state="$WORK/state.tfstate" -json arns)"
echo "ARNs: $ARNS"

ROOT_PW="$(openssl rand -hex 16)"
USER_PW="$(openssl rand -hex 16)"
docker run -d --name "$NAME" -e MINIO_ROOT_USER=haltsql-root -e MINIO_ROOT_PASSWORD="$ROOT_PW" \
  "$IMAGE" server /data >/dev/null
# credentials reach mc through the environment of docker exec, never argv
mcx() { docker exec -e MC_HOST_root="http://haltsql-root:$ROOT_PW@127.0.0.1:9000" \
  -e MC_HOST_task="http://taskuser:$USER_PW@127.0.0.1:9000" "$NAME" mc "$@"; }
for _ in $(seq 1 60); do mcx ready root >/dev/null 2>&1 && break; sleep 1; done
mcx ready root >/dev/null

printf '{"Version":"2012-10-17","Statement":[{"Sid":"ReadPolicyBundles","Effect":"Allow","Action":["s3:GetObject"],"Resource":%s}]}' \
  "$ARNS" >"$WORK/policy.json"
docker cp "$WORK/policy.json" "$NAME:/tmp/policy.json"
docker exec "$NAME" sh -c 'echo bundle >/tmp/b; echo sig >/tmp/s; echo other >/tmp/o'
mcx mb --quiet root/bundles >/dev/null
mcx cp --quiet /tmp/b root/bundles/prod/policy.haltsqlbundle >/dev/null
mcx cp --quiet /tmp/s root/bundles/prod/policy.haltsqlbundle.sig >/dev/null
mcx cp --quiet /tmp/o root/bundles/prod/other >/dev/null
mcx admin policy create root bundleread /tmp/policy.json >/dev/null
docker exec -e MC_HOST_root="http://haltsql-root:$ROOT_PW@127.0.0.1:9000" -e PW="$USER_PW" "$NAME" \
  sh -c 'mc admin user add root taskuser "$PW"' >/dev/null
mcx admin policy attach root bundleread --user taskuser >/dev/null

FAILED=0
expect() { # expect allow|deny KEY
  if mcx cat "task/bundles/$2" >/dev/null 2>&1; then got=allow; else got=deny; fi
  if [ "$got" = "$1" ]; then echo "ok   $1 GET $2"; else echo "FAIL: GET $2: expected $1, got $got"; FAILED=1; fi
}
expect allow prod/policy.haltsqlbundle
expect allow prod/policy.haltsqlbundle.sig
expect deny prod/other
[ "$FAILED" = 0 ] && echo "PASS: the task role reads the bundle and its signature, nothing else"
exit "$FAILED"
