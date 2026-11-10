#!/usr/bin/env bash
# Verify a HaltSQL release the way docs/security/supply-chain.md tells users to.
#
#   scripts/verify-release.sh v0.1.0                 # download the GitHub release and verify it
#   scripts/verify-release.sh --dir assets v0.1.0    # verify files already downloaded
#
# Runs, for the release TAG:
#   1. cosign verify-blob of SHA256SUMS (keyless, release workflow identity)
#   2. sha256sum -c SHA256SUMS, and that every expected asset is present
#   3. cosign verify-blob of every checksummed file's own .sigstore.json bundle
#   4. gh attestation verify of every tarball and the Helm chart archive
#   5. the CycloneDX SBOM parses, and each tarball holds all three binaries
#   6. for the images and the chart listed in haltsql-<tag>.oci.txt: cosign verify,
#      gh attestation verify oci://..., the BuildKit SBOM and SLSA provenance on
#      the images, the chart archive's digest in the registry, and, for a real
#      release, that the version tags point at the signed digests
#
# Options:
#   --dir DIR             use assets in DIR instead of downloading the release
#   --repo OWNER/NAME     repository (default HaltSQL/HaltSQL)
#   --identity URI        exact certificate identity, e.g. for a manual run
#                         https://github.com/HaltSQL/HaltSQL/.github/workflows/release.yml@refs/heads/main
#   --identity-regexp RE  certificate identity regexp (default: the release
#                         workflow on any v* tag, as in the docs)
#   --skip-oci            skip step 6 (no registry access)
#
# Needs cosign (v2.4 or later), gh (2.49 or later), jq, and docker with buildx for
# step 6. Drafts (dry runs) can be downloaded by anyone with write access to the
# repository; private dry-run packages need `docker login ghcr.io` with a token
# that has read:packages. Exits non-zero if any check fails.
# The sh -c snippets take their values as positional arguments, on purpose.
# shellcheck disable=SC2016
set -uo pipefail

repo=HaltSQL/HaltSQL
dir=""
identity=""
identity_re=""
skip_oci=0
tag=""
issuer=https://token.actions.githubusercontent.com

usage() { sed -n '2,33p' "$0"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?}"; shift 2 ;;
    --repo) repo="${2:?}"; shift 2 ;;
    --identity) identity="${2:?}"; shift 2 ;;
    --identity-regexp) identity_re="${2:?}"; shift 2 ;;
    --skip-oci) skip_oci=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "verify-release: unknown option $1" >&2; exit 2 ;;
    *) [ -z "$tag" ] || { echo "verify-release: one tag only" >&2; exit 2; }; tag="$1"; shift ;;
  esac
done
[ -n "$tag" ] || { usage >&2; exit 2; }
case "$tag" in v*) ;; *) echo "verify-release: $tag is not a v* tag" >&2; exit 2 ;; esac
version="${tag#v}"

if [ -z "$identity" ] && [ -z "$identity_re" ]; then
  owner_re="$(printf '%s' "$repo" | sed 's/[.]/\\./g')"
  identity_re="^https://github.com/${owner_re}/\\.github/workflows/release\\.yml@refs/tags/v"
fi
if [ -n "$identity" ]; then
  id_args=(--certificate-identity "$identity")
else
  id_args=(--certificate-identity-regexp "$identity_re")
fi

for tool in cosign gh jq; do
  command -v "$tool" > /dev/null || { echo "verify-release: $tool is required" >&2; exit 2; }
done
if command -v sha256sum > /dev/null; then sha_check=(sha256sum -c); else sha_check=(shasum -a 256 -c); fi

passed=0
failed=0
# check LABEL CMD...: run CMD, record the outcome, keep going.
check() {
  local label="$1"; shift
  local log
  if log="$("$@" 2>&1)"; then
    printf 'PASS  %s\n' "$label"
    passed=$((passed + 1))
  else
    printf 'FAIL  %s\n' "$label"
    printf '%s\n' "$log" | sed 's/^/        /' | tail -n 20
    failed=$((failed + 1))
  fi
}
fail() { printf 'FAIL  %s\n' "$1"; failed=$((failed + 1)); }

# ---- assets ----------------------------------------------------------------
if [ -z "$dir" ]; then
  dir="$(mktemp -d "${TMPDIR:-/tmp}/haltsql-verify.XXXXXX")"
  echo "Downloading release $tag from $repo into $dir"
  if ! gh release download "$tag" --repo "$repo" --dir "$dir"; then
    echo "verify-release: could not download release $tag (a draft needs write access)" >&2
    exit 1
  fi
fi
cd "$dir" || exit 2
echo "Verifying $tag in $(pwd)"
echo "Certificate identity: ${identity:-$identity_re}"
echo

expected=(
  "haltsql-$tag-linux-amd64.tar.gz"
  "haltsql-$tag-linux-arm64.tar.gz"
  "haltsql-$tag-darwin-arm64.tar.gz"
  "haltsql-$version.tgz"
  "haltsql-$tag.cdx.json"
  "haltsql-$tag.oci.txt"
  "SHA256SUMS"
)
for f in "${expected[@]}"; do
  [ -f "$f" ] || fail "asset $f is missing"
  [ -f "$f.sigstore.json" ] || fail "asset $f.sigstore.json is missing"
done

# ---- 1-3. checksums and blob signatures ------------------------------------
check "cosign verify-blob SHA256SUMS" \
  cosign verify-blob --bundle SHA256SUMS.sigstore.json "${id_args[@]}" \
  --certificate-oidc-issuer "$issuer" SHA256SUMS

# Every asset (other than signatures and SHA256SUMS itself) must be listed.
for f in *; do
  case "$f" in *.sigstore.json|SHA256SUMS) continue ;; esac
  grep -q "  $f\$" SHA256SUMS || fail "$f is not listed in SHA256SUMS"
done
check "sha256sum -c SHA256SUMS" "${sha_check[@]}" SHA256SUMS

while read -r _ f; do
  check "cosign verify-blob $f" \
    cosign verify-blob --bundle "$f.sigstore.json" "${id_args[@]}" \
    --certificate-oidc-issuer "$issuer" "$f"
done < SHA256SUMS

# ---- 4. build provenance -----------------------------------------------------
for f in haltsql-"$tag"-*.tar.gz "haltsql-$version.tgz"; do
  [ -f "$f" ] || continue
  check "gh attestation verify $f" gh attestation verify "$f" --repo "$repo"
done

# ---- 5. contents -------------------------------------------------------------
check "SBOM is CycloneDX JSON with components" \
  jq -e '.bomFormat == "CycloneDX" and (.components | length) > 0' "haltsql-$tag.cdx.json"
for f in haltsql-"$tag"-*.tar.gz; do
  [ -f "$f" ] || continue
  top="${f%.tar.gz}"
  check "$f holds haltsql, haltsql-server, haltsql-proxy and the licences" sh -c '
    list=$(tar -tzf "$1") || exit 1
    for m in haltsql haltsql-server haltsql-proxy LICENSE NOTICE LICENSE.libpg_query; do
      printf "%s\n" "$list" | grep -qx "$2/$m" || { echo "missing $2/$m"; exit 1; }
    done' _ "$f" "$top"
done

# ---- 6. images and chart -----------------------------------------------------
if [ "$skip_oci" = 1 ]; then
  echo "SKIP  OCI checks (--skip-oci)"
elif [ -f "haltsql-$tag.oci.txt" ]; then
  have_docker=1
  docker buildx version > /dev/null 2>&1 || { have_docker=0; echo "note: docker buildx not found; image SBOM/provenance and tag checks need it"; }
  while read -r kind ref; do
    [ -n "$ref" ] || continue
    case "$ref" in
      *@sha256:*) ;;
      *) fail "$kind: $ref is not pinned by digest"; continue ;;
    esac
    check "cosign verify $kind ($ref)" \
      cosign verify "$ref" "${id_args[@]}" --certificate-oidc-issuer "$issuer"
    check "gh attestation verify oci://$ref" \
      gh attestation verify "oci://$ref" --repo "$repo"

    name="${ref%@*}"
    digest="${ref#*@}"
    if [ "$have_docker" = 1 ]; then
      case "$kind" in
        image|mcp-image)
          check "$kind has a BuildKit SBOM" sh -c \
            'docker buildx imagetools inspect "$1" --format "{{ json .SBOM }}" | jq -e "length > 0" > /dev/null' _ "$ref"
          check "$kind has SLSA provenance" sh -c \
            'docker buildx imagetools inspect "$1" --format "{{ json .Provenance }}" | jq -e "length > 0" > /dev/null' _ "$ref"
          ;;
        helm-chart)
          # The chart's content layer is the released archive, byte for byte.
          check "helm-chart content layer is haltsql-$version.tgz" sh -c '
            want="sha256:$(awk -v f="$2" "\$2 == f {print \$1}" SHA256SUMS)"
            got=$(docker buildx imagetools inspect --raw "$1" \
              | jq -r ".layers[] | select(.mediaType == \"application/vnd.cncf.helm.chart.content.v1.tar+gzip\") | .digest")
            [ "$got" = "$want" ] || { echo "registry layer $got, release archive $want"; exit 1; }' _ "$ref" "haltsql-$version.tgz"
          ;;
      esac
      # A real release is also reachable by its version tag; it must be the signed digest.
      case "$name" in
        */dryrun/*) ;;
        *)
          check "$name:$version is $digest" sh -c '
            got=$(docker buildx imagetools inspect --raw "$1" | { command -v sha256sum >/dev/null && sha256sum || shasum -a 256; } | cut -d" " -f1)
            [ "sha256:$got" = "$2" ] || { echo "tag resolves to sha256:$got"; exit 1; }' _ "$name:$version" "$digest"
          ;;
      esac
    fi
  done < "haltsql-$tag.oci.txt"
fi

echo
echo "verify-release: $passed passed, $failed failed"
[ "$failed" = 0 ]
