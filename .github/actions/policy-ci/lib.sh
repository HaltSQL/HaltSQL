#!/usr/bin/env bash
# Shared helpers for the HaltSQL policy CI action. Portable to bash 3.2 (macOS).
# shellcheck shell=bash

haltsql_log() { printf 'haltsql-ci: %s\n' "$*" >&2; }
haltsql_die() {
  printf '::error::haltsql-ci: %s\n' "$*" >&2
  exit 2
}

# haltsql_is_true VALUE -> success for true/yes/1/on (case-insensitive).
haltsql_is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    true | yes | 1 | on) return 0 ;;
    *) return 1 ;;
  esac
}

# haltsql_expand KIND PATTERNS
#   KIND: policy | suite. PATTERNS: whitespace/newline separated globs, files or
#   directories, relative to the current directory. Prints matching regular files, one per
#   line, sorted and de-duplicated. Supports '**' (any number of directories, including
#   none) without bash 4 globstar. Directories are searched recursively: for policies
#   *.yaml/*.yml/*.json, for suites *.suite.yaml/*.suite.yml/*.suite.json.
haltsql_expand() {
  local kind="$1" patterns="$2" pat f alt noglob=false
  local -a pats=()
  # Split on whitespace WITHOUT pathname expansion, then expand each pattern ourselves.
  case $- in *f*) noglob=true ;; esac
  set -f
  # shellcheck disable=SC2206
  pats=($patterns)
  [ "$noglob" = true ] || set +f
  {
    for pat in ${pats[@]+"${pats[@]}"}; do
      if [ -d "$pat" ]; then
        if [ "$kind" = suite ]; then
          find "$pat" -type f \( -name '*.suite.yaml' -o -name '*.suite.yml' -o -name '*.suite.json' \)
        else
          find "$pat" -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) \
            ! -name '*.suite.*'
        fi
      elif [ -f "$pat" ]; then
        printf '%s\n' "$pat"
      else
        case "$pat" in
          *'**'*)
            # [[ == ]] lets '*' match '/', so '**' matches any depth; also try the
            # pattern with '**/' removed so that zero directories match too.
            alt=$(printf '%s' "$pat" | sed 's#\*\*/##g')
            find . -type f | sed 's#^\./##' | while IFS= read -r f; do
              # shellcheck disable=SC2053
              if [[ $f == $pat ]] || [[ $f == $alt ]]; then printf '%s\n' "$f"; fi
            done
            ;;
          *)
            # Plain glob: expand without word splitting surprises.
            for f in $pat; do
              [ -f "$f" ] && printf '%s\n' "$f"
            done
            ;;
        esac
      fi
    done
  } | sed 's#^\./##' | LC_ALL=C sort -u
}

# haltsql_output NAME VALUE: set a step output (no-op outside GitHub Actions).
haltsql_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  fi
}

haltsql_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# haltsql_verify_sha256 SUMS_FILE FILE NAME: FILE must match the line for NAME in a
# sha256sum-format SUMS_FILE (exactly one line). Prints an error and fails otherwise.
haltsql_verify_sha256() {
  local sums="$1" file="$2" name="$3" expected actual n
  n=$(awk -v f="$name" '$2 == f || $2 == "*" f' "$sums" | wc -l | tr -d ' ')
  if [ "$n" != 1 ]; then
    printf '::error::haltsql-ci: %s must appear exactly once in %s (found %s)\n' "$name" "$sums" "$n" >&2
    return 1
  fi
  expected=$(awk -v f="$name" '$2 == f || $2 == "*" f { print $1 }' "$sums")
  if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
    printf '::error::haltsql-ci: malformed checksum for %s\n' "$name" >&2
    return 1
  fi
  actual=$(haltsql_sha256 "$file")
  if [ "$expected" != "$actual" ]; then
    printf '::error::haltsql-ci: checksum mismatch for %s (expected %s, got %s)\n' "$name" "$expected" "$actual" >&2
    return 1
  fi
}
