#!/usr/bin/env bash
# Smoke test of the haltsql-console image (Dockerfile target "console"):
#
#   1. image metadata: uid 65532, HEALTHCHECK, /var/lib/haltsql-console volume,
#      port 8090, no shell in the image
#   2. runs with a read-only root filesystem, no capabilities and
#      no-new-privileges; GET /healthz and /readyz answer 200
#   3. the image HEALTHCHECK (`haltsql-console --healthcheck`) reports healthy
#   4. /api/v1/me: 401 without a token, 200 with an automation token
#   5. a read-only state_dir makes /readyz answer 503
#   6. an invalid config exits with status 2
#
# Usage:
#   docker build --target console -t haltsql-console-local:dev .
#   scripts/console-docker-smoke.sh
#
# Environment:
#   IMAGE          image under test   (default haltsql-console-local:dev)
#   CLIENT_IMAGE   curl client image  (default: curl 8.11.1 from curlimages, by digest)
#
# Without a Docker daemon the script prints SKIPPED and exits 0. Creates (and
# always removes) the network and containers haltsql-console-smoke-<pid>-*.
#
# pass() always succeeds, so `test && pass || fail` is a safe if-then-else.
# shellcheck disable=SC2015

set -euo pipefail

IMAGE=${IMAGE:-haltsql-console-local:dev}
CLIENT_IMAGE=${CLIENT_IMAGE:-curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69}

if ! docker info > /dev/null 2>&1; then
  echo "console-docker-smoke: SKIPPED (no Docker daemon reachable)"
  exit 0
fi
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  echo "console-docker-smoke: image $IMAGE not found; build it first:" >&2
  echo "  docker build --target console -t $IMAGE ." >&2
  exit 1
fi

NAME=haltsql-console-smoke-$$
NET=$NAME-net
WORK=$(mktemp -d "${TMPDIR:-/tmp}/haltsql-console-smoke.XXXXXX")
FAILED=0
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  docker rm -fv "$NAME-ok" "$NAME-ro" > /dev/null 2>&1 || true
  docker network rm "$NET" > /dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; FAILED=1; }

# A random automation token; only its SHA-256 goes into the config.
TOKEN=smoke-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
if command -v sha256sum > /dev/null; then
  HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
else
  HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)
fi
mkdir -p "$WORK/conf" "$WORK/state-ro"
cat > "$WORK/conf/console.yaml" <<EOF
environment: { org: Smoke, name: CI }
state_dir: /var/lib/haltsql-console
auth:
  tokens:
    - { name: smoke, sha256: "$HASH", role: audit }
EOF
printf 'auth: {}\nstate_dir: /var/lib/haltsql-console\n' > "$WORK/conf/invalid.yaml"
chmod -R a+rX "$WORK/conf"

echo "== 1. image metadata ($IMAGE)"
user=$(docker image inspect "$IMAGE" --format '{{.Config.User}}')
[ "$user" = "65532:65532" ] && pass "runs as $user" || fail "user is '$user', expected 65532:65532"
hc=$(docker image inspect "$IMAGE" --format '{{json .Config.Healthcheck.Test}}')
case "$hc" in *--healthcheck*) pass "HEALTHCHECK $hc" ;; *) fail "no HEALTHCHECK ($hc)" ;; esac
vols=$(docker image inspect "$IMAGE" --format '{{json .Config.Volumes}}')
case "$vols" in *'/var/lib/haltsql-console'*) pass "volume $vols" ;; *) fail "state volume missing ($vols)" ;; esac
ports=$(docker image inspect "$IMAGE" --format '{{json .Config.ExposedPorts}}')
case "$ports" in *8090*) pass "exposes $ports" ;; *) fail "port 8090 not exposed ($ports)" ;; esac
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c true > /dev/null 2>&1; then
  fail "the image has a shell"
else
  pass "no shell in the image"
fi

docker network create "$NET" > /dev/null
HARDEN=(--read-only --cap-drop ALL --security-opt no-new-privileges:true --network "$NET"
        -v "$WORK/conf:/etc/haltsql-console:ro")
curl_in_net() { docker run --rm --network "$NET" "$CLIENT_IMAGE" -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== 2. hardened run, /healthz and /readyz"
docker run -d --name "$NAME-ok" "${HARDEN[@]}" "$IMAGE" > /dev/null
ok=0
for _ in $(seq 60); do
  [ "$(curl_in_net "http://$NAME-ok:8090/healthz" || true)" = 200 ] && { ok=1; break; }
  sleep 1
done
[ $ok = 1 ] && pass "/healthz 200" || { fail "/healthz never answered 200"; docker logs "$NAME-ok"; }
code=$(curl_in_net "http://$NAME-ok:8090/readyz" || true)
[ "$code" = 200 ] && pass "/readyz 200 (state_dir writable on a read-only rootfs)" || fail "/readyz $code"

echo "== 3. image HEALTHCHECK"
if docker exec "$NAME-ok" /usr/local/bin/haltsql-console --healthcheck; then
  pass "haltsql-console --healthcheck exits 0"
else
  fail "haltsql-console --healthcheck failed"
fi
status=unknown
for _ in $(seq 45); do
  status=$(docker inspect --format '{{.State.Health.Status}}' "$NAME-ok")
  [ "$status" = healthy ] && break
  sleep 1
done
[ "$status" = healthy ] && pass "container health: healthy" || echo "note: health status '$status' (interval 30s; skipped)"

echo "== 4. authentication"
code=$(curl_in_net "http://$NAME-ok:8090/api/v1/me" || true)
[ "$code" = 401 ] && pass "/api/v1/me without a token: 401" || fail "/api/v1/me without a token: $code"
code=$(curl_in_net -H "Authorization: Bearer $TOKEN" "http://$NAME-ok:8090/api/v1/me" || true)
[ "$code" = 200 ] && pass "/api/v1/me with the automation token: 200" || fail "/api/v1/me with a token: $code"

echo "== 5. read-only state_dir"
docker run -d --name "$NAME-ro" "${HARDEN[@]}" -v "$WORK/state-ro:/var/lib/haltsql-console:ro" "$IMAGE" > /dev/null
code=000
for _ in $(seq 30); do
  code=$(curl_in_net "http://$NAME-ro:8090/readyz" || true)
  [ "$code" = 503 ] && break
  sleep 1
done
[ "$code" = 503 ] && pass "/readyz 503 when state_dir is read-only" || fail "/readyz $code with a read-only state_dir"

echo "== 6. invalid config"
set +e
docker run --rm "${HARDEN[@]}" "$IMAGE" --config /etc/haltsql-console/invalid.yaml > /dev/null 2>&1
rc=$?
set -e
[ $rc = 2 ] && pass "invalid config exits 2" || fail "invalid config exited $rc, expected 2"

if [ $FAILED = 0 ]; then echo "console-docker-smoke: PASS"; else echo "console-docker-smoke: FAIL"; fi
exit $FAILED
