# syntax=docker/dockerfile:1.10@sha256:865e5dd094beca432e8c0a1d5e1c465db5f998dca4e439981029b3b81fb39ed5
#
# HaltSQL container image and static release binaries: haltsql-server (entrypoint),
# the haltsql CLI and haltsql-proxy (the PostgreSQL wire-protocol firewall).
#
#   docker build -t haltsql-local:dev .                    # runtime image (distroless)
#   docker build --target scratch -t haltsql-local:scratch .  # same binaries on scratch
#   docker buildx build --target dist --output type=local,dest=dist .  # tarball contents
#
#   docker run --rm -p 8080:8080 --read-only -v $PWD/examples:/etc/haltsql:ro haltsql-local:dev \
#     --policy /etc/haltsql/policies/saas.yaml --allow-unauthenticated
#   docker run --rm -p 6432:6432 --read-only -v $PWD/proxy:/etc/haltsql:ro \
#     --entrypoint /usr/local/bin/haltsql-proxy haltsql-local:dev \
#     run --config /etc/haltsql/proxy.yaml
#
# Stages:
#   builder  Alpine (musl) + opam. Builds haltsql, haltsql-server and haltsql-proxy as
#            fully static executables (HALTSQL_STATIC=1, see bin/link_flags.ml) and
#            checks that they are static and run. libpg_query is vendored
#            (vendor/libpg_query) and compiled by dune with `make`, so the builder
#            needs a C toolchain but no Postgres packages.
#   dist     scratch with only the binaries and licences, for `--output` (release.yml).
#   scratch  the binaries on an empty image, to prove they need no libc at all.
#   runtime  (default) distroless/static: no shell, no libc, no package manager,
#            uid/gid 65532, with /etc/ssl/certs for the OIDC, Vault, AWS and GCP
#            clients. Nothing in the image needs to write to the root filesystem, so
#            it runs with a read-only rootfs (`docker run --read-only`, Kubernetes
#            `readOnlyRootFilesystem: true`); mount a writable volume at
#            /var/log/haltsql only if you enable a file audit sink.
#
# Reproducibility
# ---------------
# * Base images are pinned by digest, and the FROM lines are literal (not ARGs) so
#   Dependabot (docker ecosystem) can propose digest bumps. To re-pin by hand:
#     docker buildx imagetools inspect ocaml/opam:alpine-3.22-ocaml-5.3 | grep -m1 Digest
#     docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot | grep -m1 Digest
# * OCaml dependencies are solved against a fixed opam-repository commit
#   (OPAM_REPOSITORY_COMMIT; the image's own snapshot is months old), so the same
#   source tree always gets the same package versions. Bump it deliberately; it
#   changes the dependency set:
#     git ls-remote https://github.com/ocaml/opam-repository refs/heads/master
#   The release tarballs (.github/workflows/release.yml) are built from the `dist`
#   stage of this file, so they always ship the same dependency versions as the
#   image. Pass --build-arg OPAM_REPOSITORY_COMMIT= to use whatever the image has.
# * Release images are built by .github/workflows/release.yml with SBOM and SLSA
#   provenance attestations, then signed keylessly with cosign.

# Empty base for the BuildKit cache mounts. A cache mount without from= starts
# from "scratch", which would resolve to the stage named scratch below and
# create a dependency cycle.
FROM scratch AS cache-base

FROM ocaml/opam:alpine-3.22-ocaml-5.3@sha256:75fab91b192f782768f92cc037e3413274302b6498f3ea29ed4a096e49ce6f8f AS builder
ARG OPAM_REPOSITORY_COMMIT=76e3d58643dea3b2867c8811b8aacf30a4417c05
USER root
# gmp-dev + gmp-static: zarith (JWT RSA keys) links libgmp; recent Alpine ships
# libgmp.a only in gmp-static, which the fully static link needs. The
# tls/mirage-crypto/digestif C stubs need only the C toolchain.
RUN apk add --no-cache build-base linux-headers pkgconf gmp-dev gmp-static file \
 && ln -f /usr/bin/opam-2.4 /usr/bin/opam
USER opam
WORKDIR /home/opam/src
ENV OPAMYES=1 OPAMCONFIRMLEVEL=unsafe-yes OPAMDEPEXTYES=1

# 1. The pinned opam-repository, and the dependencies (only dune-project is needed to
#    generate the opam files, so this layer is cached until dependencies change).
#    The opam download cache is a BuildKit cache mount so rebuilds after a
#    dune-project change do not re-download every tarball.
RUN set -eux; \
    opam init --reinit -ni > /dev/null; \
    if [ -n "${OPAM_REPOSITORY_COMMIT}" ]; then \
      repo=/home/opam/opam-repository; \
      git -C "$repo" cat-file -e "${OPAM_REPOSITORY_COMMIT}^{commit}" 2>/dev/null \
        || git -C "$repo" fetch -q --depth=1 origin "${OPAM_REPOSITORY_COMMIT}"; \
      git -C "$repo" checkout -q -B master "${OPAM_REPOSITORY_COMMIT}"; \
      git -C "$repo" log -1 --format='opam-repository %H (%cI)'; \
      opam update default; \
    else \
      opam update; \
    fi
COPY --chown=opam:opam dune-project ./
RUN --mount=type=cache,from=cache-base,target=/home/opam/.opam/download-cache,uid=1000,gid=1000,sharing=locked \
    set -eux; \
    opam install dune; \
    opam exec -- dune build haltsql.opam haltsql-server.opam haltsql-proxy.opam; \
    opam install . --deps-only; \
    opam list --installed --columns=name,version > /home/opam/opam-packages.txt

# 2. Sources and a static release build (the release tarballs are this stage's output).
COPY --chown=opam:opam . .
ENV HALTSQL_STATIC=1
RUN --mount=type=cache,from=cache-base,target=/home/opam/.cache/dune,uid=1000,gid=1000,sharing=locked \
    opam exec -- dune build --profile release lib/pgquery/libpg_query.a \
 && opam exec -- dune build --profile release \
      ./bin/haltsql/main.exe ./bin/server/main.exe ./bin/proxy/main.exe \
 && mkdir -p /home/opam/out/bin /home/opam/out/doc \
 && install -m 0755 _build/default/bin/haltsql/main.exe /home/opam/out/bin/haltsql \
 && install -m 0755 _build/default/bin/server/main.exe /home/opam/out/bin/haltsql-server \
 && install -m 0755 _build/default/bin/proxy/main.exe /home/opam/out/bin/haltsql-proxy \
 && cd /home/opam/out/bin \
 && strip haltsql haltsql-server haltsql-proxy \
 && file haltsql haltsql-server haltsql-proxy \
 && for b in haltsql haltsql-server haltsql-proxy; do \
      file "$b" | grep -Eq 'statically linked|static-pie linked' \
        || { echo "$b is not statically linked" >&2; exit 1; }; \
      if ldd "$b" > /tmp/ldd.out 2>&1; then \
        cat /tmp/ldd.out; echo "$b: ldd found dynamic dependencies" >&2; exit 1; \
      fi; \
    done \
 && ./haltsql version \
 && ./haltsql-server --help=plain > /dev/null \
 && ./haltsql-proxy --help=plain > /dev/null \
 && install -m 0644 /home/opam/src/LICENSE /home/opam/src/NOTICE /home/opam/out/doc/ \
 && install -m 0644 /home/opam/src/vendor/libpg_query/LICENSE /home/opam/out/doc/LICENSE.libpg_query \
 && install -m 0644 /home/opam/opam-packages.txt /home/opam/out/doc/opam-packages.txt \
 && mkdir -p /home/opam/out/var-log-haltsql

# Release tarball contents: `docker buildx build --target dist --output ...`.
FROM scratch AS dist
COPY --from=builder /home/opam/out/bin/ /
COPY --from=builder /home/opam/out/doc/LICENSE /home/opam/out/doc/NOTICE /home/opam/out/doc/LICENSE.libpg_query /

# The same binaries on an empty filesystem: if anything were dynamically linked, the
# exec-form RUN below would fail with "no such file or directory".
FROM scratch AS scratch
COPY --from=builder /home/opam/out/bin/ /usr/local/bin/
RUN ["/usr/local/bin/haltsql", "version"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/haltsql"]
CMD ["version"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime
# Build metadata. The release workflow passes these and also sets the full
# org.opencontainers.image.* label set through docker/metadata-action.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z
LABEL org.opencontainers.image.title="haltsql" \
      org.opencontainers.image.description="Policy firewall for LLM-generated PostgreSQL" \
      org.opencontainers.image.url="https://github.com/HaltSQL/HaltSQL" \
      org.opencontainers.image.source="https://github.com/HaltSQL/HaltSQL" \
      org.opencontainers.image.documentation="https://github.com/HaltSQL/HaltSQL/tree/main/docs" \
      org.opencontainers.image.vendor="HaltSQL" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"
# One layer for the binaries, one for docs/licences (LICENSE, NOTICE,
# LICENSE.libpg_query, opam-packages.txt), one for the audit dir.
COPY --from=builder /home/opam/out/bin/haltsql /home/opam/out/bin/haltsql-server /home/opam/out/bin/haltsql-proxy /usr/local/bin/
COPY --from=builder /home/opam/out/doc/ /usr/share/doc/haltsql/
# Default location of a file audit sink. Mount a volume here (emptyDir in
# Kubernetes) when the root filesystem is read-only.
COPY --from=builder --chown=65532:65532 /home/opam/out/var-log-haltsql /var/log/haltsql

# Inside a container the server must listen on all interfaces; flags and the
# config file can still override this (flags > HALTSQL_* env > file).
ENV HALTSQL_LISTEN=0.0.0.0:8080
# 8080: haltsql-server. 6432: haltsql-proxy (when run as the entrypoint).
EXPOSE 8080 6432
USER 65532:65532
STOPSIGNAL SIGTERM

# No HEALTHCHECK: distroless has no shell or curl. Use orchestrator probes:
#   startup/liveness GET /healthz   readiness GET /readyz   (see docs/deployment.md)
ENTRYPOINT ["/usr/local/bin/haltsql-server"]
CMD ["--config", "/etc/haltsql/config.yaml"]
