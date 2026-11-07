# syntax=docker/dockerfile:1.6
#
# HaltSQL container image: haltsql-server (entrypoint) and the haltsql CLI.
#
#   docker build -t haltsql:dev .
#   docker run --rm -p 8080:8080 -v $PWD/examples:/etc/haltsql:ro haltsql:dev \
#     --policy /etc/haltsql/policies/saas.yaml --allow-unauthenticated
#
# Stage 1 builds fully static binaries against musl (Alpine). libpg_query is
# vendored (vendor/libpg_query) and compiled by dune with `make`, so the
# builder needs a C toolchain but no Postgres packages.
# Stage 2 is distroless/static (no shell, no libc), running as uid 65532.

ARG OCAML_IMAGE=ocaml/opam:alpine-ocaml-5.2

FROM ${OCAML_IMAGE} AS builder
USER root
RUN apk add --no-cache build-base linux-headers pkgconf gmp-dev libffi-dev file
USER opam
WORKDIR /home/opam/src

# 1. Dependencies first, for layer caching: only dune-project is needed to
#    generate the opam files.
COPY --chown=opam:opam dune-project ./
RUN opam update -y \
 && opam install -y dune \
 && opam exec -- dune build haltsql.opam haltsql-server.opam \
 && opam install -y . --deps-only

# 2. Sources and a static release build.
COPY --chown=opam:opam . .
ENV HALTSQL_STATIC=1
RUN opam exec -- dune build --profile release \
      ./bin/haltsql/main.exe ./bin/server/main.exe \
 && mkdir -p /home/opam/out \
 && install -m 0755 _build/default/bin/haltsql/main.exe /home/opam/out/haltsql \
 && install -m 0755 _build/default/bin/server/main.exe /home/opam/out/haltsql-server \
 && strip /home/opam/out/haltsql /home/opam/out/haltsql-server \
 && file /home/opam/out/haltsql /home/opam/out/haltsql-server \
 && ! file /home/opam/out/haltsql /home/opam/out/haltsql-server | grep -q 'dynamically linked' \
 && /home/opam/out/haltsql version

# A writable, empty directory for the default audit file location.
RUN mkdir -p /home/opam/out/var-log-haltsql

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="haltsql" \
      org.opencontainers.image.description="Policy firewall for LLM-generated PostgreSQL" \
      org.opencontainers.image.source="https://github.com/ardada2468/HaltSQL" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /home/opam/out/haltsql /usr/local/bin/haltsql
COPY --from=builder /home/opam/out/haltsql-server /usr/local/bin/haltsql-server
COPY --from=builder --chown=65532:65532 /home/opam/out/var-log-haltsql /var/log/haltsql
COPY --from=builder /home/opam/src/LICENSE /home/opam/src/NOTICE /usr/share/doc/haltsql/

# Inside a container the server must listen on all interfaces; flags and the
# config file can still override this (flags > HALTSQL_* env > file).
ENV HALTSQL_LISTEN=0.0.0.0:8080
EXPOSE 8080
USER 65532:65532

# No HEALTHCHECK: distroless has no shell or curl. Use orchestrator probes:
#   liveness  GET /healthz   readiness GET /readyz   (see deploy/README.md)
ENTRYPOINT ["/usr/local/bin/haltsql-server"]
CMD ["--config", "/etc/haltsql/config.yaml"]
