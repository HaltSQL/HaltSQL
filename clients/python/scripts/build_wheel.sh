#!/usr/bin/env bash
# Build haltsql Python distributions into clients/python/dist/.
#
#   clients/python/scripts/build_wheel.sh            # platform wheel with the bundled engine
#   clients/python/scripts/build_wheel.sh --pure     # pure py3-none-any wheel (HTTP + LocalVerifier)
#   clients/python/scripts/build_wheel.sh --sdist    # platform wheel + sdist (the sdist never
#                                                    # contains binaries)
#   clients/python/scripts/build_wheel.sh --pure --sdist
#
# A platform wheel ships haltsql/_native/libhaltsql.so (in-process NativeVerifier) and
# haltsql/_native/haltsql (the CLI: process backend, LocalVerifier, `haltsql` console
# script). Supported targets: macOS arm64 (and x86_64), manylinux_2_28 x86_64/aarch64.
#
# Environment:
#   HALTSQL_PREBUILT_DIR     directory with libhaltsql.so (or .dylib) and haltsql; skips dune
#   HALTSQL_BUILD_DIR        dune build dir (default <repo>/_build_wheel, so the release build
#                            never disturbs the dev build in _build)
#   MACOSX_DEPLOYMENT_TARGET macOS only, default 11.0
#   HALTSQL_WHEEL_PLAT       override the platform tag (e.g. macosx_11_0_arm64)
#   HALTSQL_MANYLINUX        Linux only, default manylinux_2_28 (auditwheel repair --plat)
#   HALTSQL_DIST_DIR         output directory (default clients/python/dist)
#   HALTSQL_KEEP_NATIVE=1    keep src/haltsql/_native/ after the build
#
# src/haltsql/_native/ is a staging area owned by this script (it is gitignored): it is
# emptied before staging and again on exit (unless HALTSQL_KEEP_NATIVE=1), so a later
# editable or pure build never picks up stale binaries.
set -euo pipefail

PY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$PY_DIR/../.." && pwd)"
NATIVE="$PY_DIR/src/haltsql/_native"
DIST="${HALTSQL_DIST_DIR:-$PY_DIR/dist}"
OS="$(uname -s)"
ARCH="$(uname -m)"

PURE=0
SDIST=0
for arg in "$@"; do
  case "$arg" in
    --pure) PURE=1 ;;
    --sdist) SDIST=1 ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg (see --help)" >&2; exit 2 ;;
  esac
done

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ "${HALTSQL_KEEP_NATIVE:-0}" != "1" ]; then rm -rf "$NATIVE"; fi
  rm -rf "$PY_DIR/build"
  if [ -n "${TMP_OUT:-}" ]; then rm -rf "$TMP_OUT"; fi
}
trap cleanup EXIT

# build_dist <--wheel|--sdist> <outdir>
build_dist() {
  # setuptools' in-tree build/ would otherwise carry files from one build into the next
  rm -rf "$PY_DIR/build"
  if command -v uv >/dev/null 2>&1; then
    uv build "$1" --out-dir "$2" "$PY_DIR"
  else
    (cd "$PY_DIR" && python3 -m build "$1" --outdir "$2")
  fi
}

mkdir -p "$DIST"
rm -rf "$NATIVE"
TMP_OUT="$(mktemp -d)"

if [ "$SDIST" = "1" ]; then
  log "building sdist (no binaries)"
  build_dist --sdist "$DIST"
fi

if [ "$PURE" = "1" ]; then
  log "building pure py3-none-any wheel"
  build_dist --wheel "$DIST"
  ls -1 "$DIST"
  exit 0
fi

# ---------------------------------------------------------------- engine binaries
if [ "$OS" = "Darwin" ]; then
  export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
fi

if [ -n "${HALTSQL_PREBUILT_DIR:-}" ]; then
  LIB="$HALTSQL_PREBUILT_DIR/libhaltsql.so"
  [ -f "$LIB" ] || LIB="$HALTSQL_PREBUILT_DIR/libhaltsql.dylib"
  BIN="$HALTSQL_PREBUILT_DIR/haltsql"
  [ -f "$LIB" ] || die "no libhaltsql.so/.dylib in HALTSQL_PREBUILT_DIR=$HALTSQL_PREBUILT_DIR"
  [ -f "$BIN" ] || die "no haltsql in HALTSQL_PREBUILT_DIR=$HALTSQL_PREBUILT_DIR"
  log "using prebuilt engine from $HALTSQL_PREBUILT_DIR"
else
  BUILD_DIR="${HALTSQL_BUILD_DIR:-$ROOT/_build_wheel}"
  log "building libhaltsql and the haltsql CLI (dune, release profile, $BUILD_DIR)"
  # libpg_query first: its headers reach _build only through that rule (see Dockerfile).
  (cd "$ROOT" && opam exec -- dune build --root . --build-dir "$BUILD_DIR" --profile release \
      lib/pgquery/libpg_query.a \
    && opam exec -- dune build --root . --build-dir "$BUILD_DIR" --profile release \
      native/libhaltsql.so bin/haltsql/main.exe)
  LIB="$BUILD_DIR/default/native/libhaltsql.so"
  BIN="$BUILD_DIR/default/bin/haltsql/main.exe"
fi

mkdir -p "$NATIVE"
cp "$LIB" "$NATIVE/libhaltsql.so"
cp "$BIN" "$NATIVE/haltsql"
chmod 0755 "$NATIVE/libhaltsql.so" "$NATIVE/haltsql"

# macos_minos <file>: the LC_BUILD_VERSION minimum macOS version (e.g. 11.0)
macos_minos() { otool -l "$1" | awk '/LC_BUILD_VERSION/{f=1} f && $1=="minos"{print $2; exit}'; }
# macos_external_deps <file>: dylibs outside the OS that the file links against
macos_external_deps() {
  otool -L "$1" | tail -n +2 | awk '{print $1}' |
    grep -v -E '^(/usr/lib/|/System/Library/|@rpath/libhaltsql\.dylib$)' || true
}

if [ "$OS" = "Darwin" ]; then
  strip -x "$NATIVE/libhaltsql.so"
  strip "$NATIVE/haltsql"
  install_name_tool -id @rpath/libhaltsql.dylib "$NATIVE/libhaltsql.so" 2>/dev/null
  # strip/install_name_tool invalidate the ad-hoc signature; arm64 refuses to run unsigned code.
  codesign --force --sign - "$NATIVE/libhaltsql.so" "$NATIVE/haltsql" 2>/dev/null
  if [ -z "${HALTSQL_WHEEL_PLAT:-}" ]; then
    # Tag with the newest minimum macOS version among the deployment target and both
    # binaries, so pip never installs the wheel where the engine cannot load.
    major=0; minor=0
    for v in "$MACOSX_DEPLOYMENT_TARGET" "$(macos_minos "$NATIVE/libhaltsql.so")" \
             "$(macos_minos "$NATIVE/haltsql")"; do
      [ -n "$v" ] || continue
      M="${v%%.*}"; m="$(echo "$v" | cut -d. -f2)"; m="${m:-0}"
      if [ "$M" -gt "$major" ] || { [ "$M" -eq "$major" ] && [ "$m" -gt "$minor" ]; }; then
        major="$M"; minor="$m"
      fi
    done
    # From macOS 11 on, pip only matches X_0 tags.
    if [ "$major" -ge 11 ]; then minor=0; fi
    if [ "$major" != "${MACOSX_DEPLOYMENT_TARGET%%.*}" ]; then
      warn "binaries require macOS $major.$minor (> MACOSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET); tagging accordingly"
    fi
    export HALTSQL_WHEEL_PLAT="macosx_${major}_${minor}_${ARCH}"
  fi
elif [ "$OS" = "Linux" ]; then
  strip --strip-unneeded "$NATIVE/libhaltsql.so" "$NATIVE/haltsql"
  export HALTSQL_WHEEL_PLAT="${HALTSQL_WHEEL_PLAT:-linux_${ARCH}}"
else
  die "unsupported OS for a platform wheel: $OS (use --pure)"
fi

# Sanity: the staged CLI runs and the library loads with the expected ABI.
"$NATIVE/haltsql" version >/dev/null || die "staged haltsql CLI does not run"
python3 - "$NATIVE/libhaltsql.so" <<'PY' || die "staged libhaltsql does not load"
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
abi = lib.haltsql_abi_version()
assert abi == 1, f"ABI version {abi} != 1"
PY

# ---------------------------------------------------------------- wheel
log "building platform wheel ($HALTSQL_WHEEL_PLAT)"
build_dist --wheel "$TMP_OUT"
WHEEL="$(ls "$TMP_OUT"/*.whl)"

if [ "$OS" = "Darwin" ]; then
  EXT="$(macos_external_deps "$NATIVE/libhaltsql.so"; macos_external_deps "$NATIVE/haltsql")"
  if [ -n "$EXT" ]; then
    log "bundling non-system dylibs with delocate: $(echo $EXT)"
    if command -v delocate-wheel >/dev/null 2>&1; then
      DELOCATE=(delocate-wheel)
    elif command -v uvx >/dev/null 2>&1; then
      DELOCATE=(uvx --from delocate delocate-wheel)
    else
      die "the engine links non-system dylibs ($EXT); install delocate (pip install delocate)"
    fi
    # delocate refuses dylibs that need a newer macOS than MACOSX_DEPLOYMENT_TARGET.
    # Raise the target (and so the wheel tag) to what the bundled dylibs really need,
    # loudly. Homebrew's gmp targets the build host's macOS: release CI should use a gmp
    # built with MACOSX_DEPLOYMENT_TARGET=11.0 so the wheel keeps the macosx_11_0 tag.
    TARGET="${HALTSQL_WHEEL_PLAT#macosx_}"; TARGET="${TARGET%_*}"; TARGET="${TARGET/_/.}"
    for dep in $EXT; do
      [ -f "$dep" ] || continue
      v="$(macos_minos "$dep")"; [ -n "$v" ] || continue
      if [ "${v%%.*}" -gt "${TARGET%%.*}" ]; then
        warn "$dep requires macOS $v: the wheel will be tagged macosx_${v%%.*}_0 instead of $HALTSQL_WHEEL_PLAT"
        TARGET="${v%%.*}.0"
      fi
    done
    MACOSX_DEPLOYMENT_TARGET="$TARGET" "${DELOCATE[@]}" --require-archs "$ARCH" -w "$DIST" -v "$WHEEL"
  else
    cp "$WHEEL" "$DIST/"
  fi
else
  if command -v auditwheel >/dev/null 2>&1; then
    PLAT="${HALTSQL_MANYLINUX:-manylinux_2_28}_${ARCH}"
    log "auditwheel repair --plat $PLAT"
    auditwheel repair --plat "$PLAT" -w "$DIST" "$WHEEL"
  else
    warn "auditwheel not installed: $(basename "$WHEEL") keeps a linux_${ARCH} tag (not uploadable to PyPI). pip install auditwheel and re-run."
    cp "$WHEEL" "$DIST/"
  fi
fi

log "done:"
ls -1 "$DIST"
