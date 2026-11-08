# syntax=docker/dockerfile:1.6
#
# HaltSQL container image and static release binaries.
#
#   docker build -t haltsql-local:dev .                    # runtime image (distroless)
#   docker build --target scratch -t haltsql-local:scratch .  # same binaries on scratch
#   docker buildx build --target dist --output type=local,dest=dist .  # tarball contents
#
#   docker run --rm -p 8080:8080 -v $PWD/examples:/etc/haltsql:ro haltsql-local:dev \
#     --policy /etc/haltsql/policies/saas.yaml --allow-unauthenticated
#   docker run --rm -p 6432:6432 -v $PWD/proxy:/etc/haltsql:ro \
#     --entrypoint /usr/local/bin/haltsql-proxy haltsql-local:dev \
#     run --config /etc/haltsql/proxy.yaml
#
# Stages:
#   builder  Alpine (musl) + opam. Builds haltsql, haltsql-server and haltsql-proxy as
#            fully static executables (HALTSQL_STATIC=1, see bin/link_flags.ml) and
#            checks that they are static and run. libpg_query is vendored
#            (vendor/libpg_query) and compiled by dune with `make`.
#   dist     scratch with only the binaries and licences, for `--output` (release.yml).
#   scratch  the binaries on an empty image, to prove they need no libc at all.
#   runtime  (default) distroless/static: no shell, no libc, uid 65532, with
#            /etc/ssl/certs for the OIDC, Vault, AWS and GCP clients.
#
# Every input is pinned: the base image tag, and the opam-repository commit the
# dependencies are solved against (the image's own snapshot is months old). Bump
# OPAM_REPOSITORY_COMMIT deliberately; it changes the dependency set.

ARG OCAML_IMAGE=ocaml/opam:alpine-3.22-ocaml-5.3
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${OCAML_IMAGE} AS builder
ARG OPAM_REPOSITORY_COMMIT=76e3d58643dea3b2867c8811b8aacf30a4417c05
USER root
# gmp-dev + gmp-static: zarith (JWT RSA keys) links libgmp, and a -static link needs
# the archive. The tls/mirage-crypto/digestif C stubs need only the C toolchain.
RUN apk add --no-cache build-base linux-headers pkgconf gmp-dev gmp-static file \
 && ln -f /usr/bin/opam-2.4 /usr/bin/opam
USER opam
WORKDIR /home/opam/src
ENV OPAMYES=1 OPAMCONFIRMLEVEL=unsafe-yes OPAMDEPEXTYES=1

# 1. The pinned opam-repository, and the dependencies (only dune-project is needed to
#    generate the opam files, so this layer is cached until dependencies change).
RUN opam init --reinit -ni > /dev/null \
 && git -C /home/opam/opam-repository fetch -q --depth 1 origin "${OPAM_REPOSITORY_COMMIT}" \
 && git -C /home/opam/opam-repository checkout -q FETCH_HEAD \
 && opam update default
COPY --chown=opam:opam dune-project ./
RUN opam install dune \
 && opam exec -- dune build haltsql.opam haltsql-server.opam haltsql-proxy.opam \
 && opam install . --deps-only

# 2. Sources and a static release build.
COPY --chown=opam:opam . .
ENV HALTSQL_STATIC=1
RUN opam exec -- dune build --profile release lib/pgquery/libpg_query.a \
 && opam exec -- dune build --profile release \
      ./bin/haltsql/main.exe ./bin/server/main.exe ./bin/proxy/main.exe \
 && mkdir -p /home/opam/out/bin \
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
 && cp /home/opam/src/LICENSE /home/opam/src/NOTICE /home/opam/out/ \
 && cp /home/opam/src/vendor/libpg_query/LICENSE /home/opam/out/LICENSE.libpg_query \
 && mkdir -p /home/opam/out/var-log-haltsql

# Release tarball contents: `docker buildx build --target dist --output ...`.
FROM scratch AS dist
COPY --from=builder /home/opam/out/bin/ /
COPY --from=builder /home/opam/out/LICENSE /home/opam/out/NOTICE /home/opam/out/LICENSE.libpg_query /

# The same binaries on an empty filesystem: if anything were dynamically linked, the
# exec-form RUN below would fail with "no such file or directory".
FROM scratch AS scratch
COPY --from=builder /home/opam/out/bin/ /usr/local/bin/
RUN ["/usr/local/bin/haltsql", "version"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/haltsql"]
CMD ["version"]

FROM ${RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.title="haltsql" \
      org.opencontainers.image.description="Policy firewall for LLM-generated PostgreSQL" \
      org.opencontainers.image.source="https://github.com/ardada2468/HaltSQL" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /home/opam/out/bin/haltsql /usr/local/bin/haltsql
COPY --from=builder /home/opam/out/bin/haltsql-server /usr/local/bin/haltsql-server
COPY --from=builder /home/opam/out/bin/haltsql-proxy /usr/local/bin/haltsql-proxy
COPY --from=builder --chown=65532:65532 /home/opam/out/var-log-haltsql /var/log/haltsql
COPY --from=builder /home/opam/out/LICENSE /home/opam/out/NOTICE /home/opam/out/LICENSE.libpg_query /usr/share/doc/haltsql/

# Inside a container the server must listen on all interfaces; flags and the
# config file can still override this (flags > HALTSQL_* env > file).
ENV HALTSQL_LISTEN=0.0.0.0:8080
# 8080: haltsql-server. 6432: haltsql-proxy (when run as the entrypoint).
EXPOSE 8080 6432
USER 65532:65532

# No HEALTHCHECK: distroless has no shell or curl. Use orchestrator probes:
#   liveness  GET /healthz   readiness GET /readyz   (see docs/deployment.md)
ENTRYPOINT ["/usr/local/bin/haltsql-server"]
CMD ["--config", "/etc/haltsql/config.yaml"]
