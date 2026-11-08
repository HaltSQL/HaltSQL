# syntax=docker/dockerfile:1.10@sha256:865e5dd094beca432e8c0a1d5e1c465db5f998dca4e439981029b3b81fb39ed5
#
# HaltSQL container image: haltsql-server (entrypoint), the haltsql CLI and
# haltsql-proxy (the PostgreSQL wire-protocol firewall).
#
#   docker build -t haltsql:dev .
#   docker run --rm -p 8080:8080 --read-only -v $PWD/examples:/etc/haltsql:ro haltsql:dev \
#     --policy /etc/haltsql/policies/saas.yaml --allow-unauthenticated
#   docker run --rm -p 6432:6432 --read-only -v $PWD/proxy:/etc/haltsql:ro \
#     --entrypoint /usr/local/bin/haltsql-proxy haltsql:dev \
#     run --config /etc/haltsql/proxy.yaml
#
# Stage 1 builds fully static binaries against musl (Alpine). libpg_query is
# vendored (vendor/libpg_query) and compiled by dune with `make`, so the
# builder needs a C toolchain but no Postgres packages.
# Stage 2 is distroless/static (no shell, no libc, no package manager), running
# as uid/gid 65532. It ships /etc/ssl/certs, which the OIDC, Vault, AWS and GCP
# clients use. Nothing in the image needs to write to the root filesystem, so
# it runs with a read-only rootfs (`docker run --read-only`, Kubernetes
# `readOnlyRootFilesystem: true`); mount a writable volume at /var/log/haltsql
# only if you enable a file audit sink.
#
# Reproducibility
# ---------------
# * Base images are pinned by digest. Dependabot (docker ecosystem) proposes
#   digest bumps; to re-pin by hand:
#     docker buildx imagetools inspect ocaml/opam:alpine-ocaml-5.2 | grep -m1 Digest
#     docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot | grep -m1 Digest
# * OCaml dependencies are resolved against a fixed opam-repository commit
#   (OPAM_REPOSITORY_COMMIT), so the same source tree always gets the same
#   package versions. The default is the snapshot already baked into the pinned
#   builder image, so no repository download is needed. To move it forward:
#     git ls-remote https://github.com/ocaml/opam-repository refs/heads/master
#   and keep it in sync with OPAM_REPOSITORY_COMMIT in
#   .github/workflows/release.yml (which builds the release tarballs).
#   Pass --build-arg OPAM_REPOSITORY_COMMIT= to use whatever the image has.
# * Release images are built by .github/workflows/release.yml with SBOM and
#   SLSA provenance attestations, then signed keylessly with cosign.

# FROM lines are literal (not ARGs) so Dependabot can bump the digests.
FROM ocaml/opam:alpine-ocaml-5.2@sha256:75918aad2a936b4887b68c1ce983a273140f55f19f7ad7a8ba17f5a2db3e4fce AS builder
ARG OPAM_REPOSITORY_COMMIT=1e8ccc4347bd42cdf513d376cdad11075f385a8c
USER root
# gmp-dev + gmp-static: zarith (JWT RSA keys); Alpine >= 3.21 ships libgmp.a
# only in gmp-static, which the fully static link needs. The tls/mirage-crypto
# C stubs need only the C toolchain.
RUN apk add --no-cache build-base linux-headers pkgconf gmp-dev gmp-static libffi-dev file
USER opam
WORKDIR /home/opam/src

# 1. Dependencies first, for layer caching: only dune-project is needed to
#    generate the opam files. The opam download cache is a BuildKit cache mount
#    so rebuilds after a dune-project change do not re-download every tarball.
COPY --chown=opam:opam dune-project ./
RUN --mount=type=cache,target=/home/opam/.opam/download-cache,uid=1000,gid=1000,sharing=locked \
    set -eux; \
    if [ -n "${OPAM_REPOSITORY_COMMIT}" ]; then \
      repo=/home/opam/opam-repository; \
      git -C "$repo" cat-file -e "${OPAM_REPOSITORY_COMMIT}^{commit}" 2>/dev/null \
        || git -C "$repo" fetch -q --depth=1 origin "${OPAM_REPOSITORY_COMMIT}"; \
      git -C "$repo" checkout -q -B master "${OPAM_REPOSITORY_COMMIT}"; \
      git -C "$repo" log -1 --format='opam-repository %H (%cI)'; \
      opam update -y default; \
    else \
      opam update -y; \
    fi; \
    opam install -y dune; \
    opam exec -- dune build haltsql.opam haltsql-server.opam haltsql-proxy.opam; \
    opam install -y . --deps-only; \
    opam list --installed --columns=name,version > /home/opam/opam-packages.txt

# 2. Sources and a static release build (same flags as the release tarballs).
COPY --chown=opam:opam . .
ENV HALTSQL_STATIC=1
RUN --mount=type=cache,target=/home/opam/.cache/dune,uid=1000,gid=1000,sharing=locked \
    opam exec -- dune build --profile release \
      ./bin/haltsql/main.exe ./bin/server/main.exe ./bin/proxy/main.exe \
 && mkdir -p /home/opam/out/doc \
 && install -m 0755 _build/default/bin/haltsql/main.exe /home/opam/out/haltsql \
 && install -m 0755 _build/default/bin/server/main.exe /home/opam/out/haltsql-server \
 && install -m 0755 _build/default/bin/proxy/main.exe /home/opam/out/haltsql-proxy \
 && install -m 0644 LICENSE NOTICE /home/opam/out/doc/ \
 && install -m 0644 vendor/libpg_query/LICENSE /home/opam/out/doc/LICENSE.libpg_query \
 && install -m 0644 /home/opam/opam-packages.txt /home/opam/out/doc/opam-packages.txt \
 && cd /home/opam/out \
 && strip haltsql haltsql-server haltsql-proxy \
 && file haltsql haltsql-server haltsql-proxy \
 && ! file haltsql haltsql-server haltsql-proxy | grep -q 'dynamically linked' \
 && ./haltsql version \
 && ./haltsql-server --help=plain > /dev/null \
 && ./haltsql-proxy --help=plain > /dev/null \
 && mkdir -p /home/opam/out/var-log-haltsql

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# Build metadata. The release workflow passes these and also sets the full
# org.opencontainers.image.* label set through docker/metadata-action.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z
LABEL org.opencontainers.image.title="haltsql" \
      org.opencontainers.image.description="Policy firewall for LLM-generated PostgreSQL" \
      org.opencontainers.image.url="https://github.com/ardada2468/HaltSQL" \
      org.opencontainers.image.source="https://github.com/ardada2468/HaltSQL" \
      org.opencontainers.image.documentation="https://github.com/ardada2468/HaltSQL/tree/main/docs" \
      org.opencontainers.image.vendor="HaltSQL" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"
# One layer for the binaries, one for docs/licences, one for the audit dir.
COPY --from=builder /home/opam/out/haltsql /home/opam/out/haltsql-server /home/opam/out/haltsql-proxy /usr/local/bin/
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
#   startup/liveness GET /healthz   readiness GET /readyz   (see deploy/README.md)
ENTRYPOINT ["/usr/local/bin/haltsql-server"]
CMD ["--config", "/etc/haltsql/config.yaml"]
