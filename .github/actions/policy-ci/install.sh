#!/usr/bin/env bash
# Install the haltsql CLI for the current runner and print its path on stdout.
#
# Environment:
#   INPUT_VERSION         "latest" (default) or a release tag such as v0.2.0 / 0.2.0
#   INPUT_INSTALL_METHOD  auto (default) | release | docker
#   INPUT_HALTSQL_PATH    use this existing binary instead of installing (local tests)
#   INPUT_VERIFY_SIGNATURE  true: also verify SHA256SUMS with cosign (keyless); the
#                         container image, when used, must pass `cosign verify`
#                         too, and a failed release download never falls back
#   HALTSQL_REPO          GitHub repository (default HaltSQL/HaltSQL)
#   HALTSQL_IMAGE         container image (default ghcr.io/haltsql/haltsql)
#   HALTSQL_RELEASE_BASE_URL  https mirror of the GitHub release downloads (optional)
#   GITHUB_TOKEN          optional, raises the GitHub API rate limit for "latest"
#   RUNNER_TEMP, RUNNER_OS, RUNNER_ARCH, GITHUB_PATH  set by GitHub Actions
#
# Security: the release archive must match its line in the release's SHA256SUMS; a
# mismatch is fatal and never falls back to another install method. The container image
# is always run by digest (resolved once at install time, never a mutable tag). With
# verify-signature, the image digest must pass `cosign verify` with the same identity
# constraints as the release, and a release download failure is fatal instead of
# falling back to the container.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=SCRIPTDIR/lib.sh
. "$here/lib.sh"

repo=${HALTSQL_REPO:-HaltSQL/HaltSQL}
image=${HALTSQL_IMAGE:-ghcr.io/haltsql/haltsql}
method=${INPUT_INSTALL_METHOD:-auto}
version=${INPUT_VERSION:-latest}
verify_sig=false
if haltsql_is_true "${INPUT_VERIFY_SIGNATURE:-false}"; then verify_sig=true; fi
cosign_identity="^https://github.com/$repo/"
cosign_issuer=https://token.actions.githubusercontent.com
dest_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/haltsql-install

case "$method" in auto | release | docker) ;; *) haltsql_die "install-method must be auto, release or docker" ;; esac

case "${HALTSQL_RELEASE_BASE_URL:-https://}" in
  https://*) ;;
  *) haltsql_die "HALTSQL_RELEASE_BASE_URL must be an https URL" ;;
esac

add_to_path() {
  if [ -n "${GITHUB_PATH:-}" ]; then printf '%s\n' "$1" >>"$GITHUB_PATH"; fi
}

if [ -n "${INPUT_HALTSQL_PATH:-}" ]; then
  [ -x "$INPUT_HALTSQL_PATH" ] || haltsql_die "haltsql-path is not an executable: $INPUT_HALTSQL_PATH"
  bin=$(cd "$(dirname "$INPUT_HALTSQL_PATH")" && pwd)/$(basename "$INPUT_HALTSQL_PATH")
  "$bin" version >&2 || haltsql_die "$bin does not run"
  printf '%s\n' "$bin"
  exit 0
fi

# -- platform
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; esac
platform="$os-$arch"
supported=false
case "$platform" in linux-amd64 | linux-arm64 | darwin-arm64) supported=true ;; esac

curl_gh() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -H "Authorization: Bearer $GITHUB_TOKEN" "$@"
  else
    curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$@"
  fi
}

# -- version
if [ "$version" = latest ]; then
  tag=$(curl_gh -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$repo/releases/latest" | jq -r '.tag_name // empty') ||
    tag=""
  [ -n "$tag" ] || haltsql_die "cannot resolve the latest HaltSQL release of $repo"
else
  tag=$version
  case "$tag" in v*) ;; *) tag="v$tag" ;; esac
fi
if ! printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  haltsql_die "invalid HaltSQL version: $tag"
fi
haltsql_log "HaltSQL $tag for $platform"

install_release() {
  local asset="haltsql-$tag-$platform.tar.gz"
  local base="${HALTSQL_RELEASE_BASE_URL:-https://github.com/$repo/releases/download}/$tag"
  local dir="$dest_root/$tag-$platform"
  rm -rf "$dir" && mkdir -p "$dir"
  curl_gh -o "$dir/$asset" "$base/$asset" || return 3
  curl_gh -o "$dir/SHA256SUMS" "$base/SHA256SUMS" || return 3
  if [ "$verify_sig" = true ]; then
    command -v cosign >/dev/null 2>&1 ||
      haltsql_die "verify-signature needs cosign (add sigstore/cosign-installer before this action)"
    curl_gh -o "$dir/SHA256SUMS.sigstore.json" "$base/SHA256SUMS.sigstore.json" || return 3
    cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" \
      --certificate-identity-regexp "$cosign_identity" \
      --certificate-oidc-issuer "$cosign_issuer" \
      "$dir/SHA256SUMS" >&2 || haltsql_die "cosign could not verify SHA256SUMS"
  fi
  haltsql_verify_sha256 "$dir/SHA256SUMS" "$dir/$asset" "$asset" || exit 2
  tar -xzf "$dir/$asset" -C "$dir" || haltsql_die "cannot extract $asset"
  local bin="$dir/haltsql-$tag-$platform/haltsql"
  [ -x "$bin" ] || haltsql_die "haltsql binary missing from $asset"
  "$bin" version >&2 || haltsql_die "installed haltsql does not run"
  add_to_path "$(dirname "$bin")"
  printf '%s\n' "$bin"
}

install_docker() {
  command -v docker >/dev/null 2>&1 || haltsql_die "docker is not available for the container fallback"
  if [ "$verify_sig" = true ]; then
    command -v cosign >/dev/null 2>&1 ||
      haltsql_die "verify-signature needs cosign to verify the container image (add sigstore/cosign-installer before this action)"
  fi
  local tagref="$image:${tag#v}" dir="$dest_root/docker-$tag" ref="" d
  docker pull "$tagref" >&2 || haltsql_die "cannot pull $tagref"
  # Pin the image by digest: the wrapper must never re-resolve a mutable tag.
  while IFS= read -r d; do
    case "$d" in
      "$image@sha256:"*)
        if printf '%s' "${d#"$image@sha256:"}" | grep -Eq '^[0-9a-f]{64}$'; then
          ref=$d
          break
        fi
        ;;
    esac
  done <<EOF_DIGESTS
$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$tagref" 2>/dev/null || true)
EOF_DIGESTS
  [ -n "$ref" ] || haltsql_die "cannot resolve the digest of $tagref"
  if [ "$verify_sig" = true ]; then
    cosign verify --certificate-identity-regexp "$cosign_identity" \
      --certificate-oidc-issuer "$cosign_issuer" "$ref" >/dev/null ||
      haltsql_die "cosign could not verify the container image $ref"
    haltsql_log "verified container image signature: $ref"
  else
    haltsql_log "using container image $ref (signature not verified; set verify-signature: true to require it)"
  fi
  mkdir -p "$dir"
  # The wrapper mounts the workspace at the same path so relative paths keep working.
  # RUNNER_TEMP is mounted too: reports and bundles are written there.
  cat >"$dir/haltsql" <<WRAP
#!/usr/bin/env bash
mounts=(-v "\$PWD:\$PWD")
if [ -n "\${RUNNER_TEMP:-}" ]; then mounts+=(-v "\$RUNNER_TEMP:\$RUNNER_TEMP"); fi
exec docker run --rm -i --user "\$(id -u):\$(id -g)" "\${mounts[@]}" -w "\$PWD" \\
  -e HALTSQL_SIGNING_KEY --entrypoint /usr/local/bin/haltsql "$ref" "\$@"
WRAP
  chmod +x "$dir/haltsql"
  "$dir/haltsql" version >&2 || haltsql_die "haltsql in $ref does not run"
  add_to_path "$dir"
  printf '%s\n' "$dir/haltsql"
}

if [ "$method" = docker ]; then install_docker; exit 0; fi
if [ "$supported" != true ]; then
  [ "$method" = release ] && haltsql_die "no release binary for $platform"
  haltsql_log "no release binary for $platform; using the container image"
  install_docker
  exit 0
fi
set +e
install_release
rc=$?
set -e
if [ "$rc" -eq 0 ]; then exit 0; fi
# Only a download failure (rc 3) may fall back; checksum errors exit 2 above. With
# verify-signature a download failure is fatal: falling back would trade a signed binary
# for whatever the registry serves.
if [ "$rc" -eq 3 ] && [ "$verify_sig" = true ]; then
  haltsql_die "release download failed; verify-signature does not allow falling back to the container image"
fi
if [ "$method" = auto ] && [ "$rc" -eq 3 ]; then
  haltsql_log "release download failed; falling back to the container image"
  install_docker
  exit 0
fi
haltsql_die "could not install haltsql $tag"
