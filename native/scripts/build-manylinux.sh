#!/usr/bin/env bash
# Builds libhaltsql.so inside a manylinux_2_28 container (AlmaLinux 8, glibc 2.28) so
# the Python wheel can carry the manylinux_2_28 tag, and runs the ABI tests against it.
#
#   docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux_2_28_$(uname -m) \
#     native/scripts/build-manylinux.sh out/
#
# Used by .github/workflows/native-packages.yml. The CLI binary in the wheel and npm
# packages is the fully static musl build from the Dockerfile's `dist` stage instead
# (it runs on any Linux), so only the shared library needs the old-glibc toolchain.
#
# Environment:
#   OCAML_VERSION   compiler for the opam switch (default 5.2.1)
#   OPAMROOT        opam root (default ~/.opam; cache it between CI runs)
set -euo pipefail

out="${1:?usage: build-manylinux.sh OUT_DIR}"
OCAML_VERSION="${OCAML_VERSION:-5.2.1}"
OPAM_VERSION=2.3.0

case "$(uname -m)" in
  x86_64) opam_arch=x86_64; opam_sha=324e78e3f33efeba279aacf9f9610cfec7b2df7d7e0e1640f75f09de85f96cc9 ;;
  aarch64) opam_arch=arm64; opam_sha=c363d070b1771b6830c6806eb9fd5ff1a54d0fe97bf389cd2dff20b6d203b2ad ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# Build dependencies of the core library (gmp: zarith, pulled in by opam deps).
dnf install -y -q gmp-devel bubblewrap rsync patch unzip which >/dev/null

if ! command -v opam >/dev/null; then
  curl -fsSL -o /usr/local/bin/opam \
    "https://github.com/ocaml/opam/releases/download/${OPAM_VERSION}/opam-${OPAM_VERSION}-${opam_arch}-linux"
  echo "${opam_sha}  /usr/local/bin/opam" | sha256sum -c -
  chmod 0755 /usr/local/bin/opam
fi

export OPAMYES=1 OPAMCONFIRMLEVEL=unsafe-yes OPAMROOTISOK=1
if [ ! -d "${OPAMROOT:-$HOME/.opam}/default" ]; then
  opam init --bare --disable-sandboxing -n
  opam switch create default "ocaml-base-compiler.${OCAML_VERSION}"
fi
eval "$(opam env --switch=default --set-switch)"

# Only the `haltsql` package's dependencies (no server/proxy TLS stack needed).
opam install dune
opam exec -- dune build --root . haltsql.opam
opam install ./haltsql.opam --deps-only

# libpg_query first: the stubs include its headers, which dune copies into _build only
# as part of this rule (same ordering as the Dockerfile).
opam exec -- dune build --root . --profile release lib/pgquery/libpg_query.a
opam exec -- dune build --root . --profile release native/libhaltsql.so
opam exec -- dune build --root . --profile release @native/test/runtest

mkdir -p "$out"
install -m 0755 _build/default/native/libhaltsql.so "$out/libhaltsql.so"
strip --strip-unneeded "$out/libhaltsql.so"

echo "--- $out/libhaltsql.so"
file "$out/libhaltsql.so"
ldd "$out/libhaltsql.so"
# Highest glibc symbol version required; must be <= 2.28 for manylinux_2_28.
objdump -T "$out/libhaltsql.so" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
