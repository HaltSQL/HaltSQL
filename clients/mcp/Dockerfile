# syntax=docker/dockerfile:1.10@sha256:865e5dd094beca432e8c0a1d5e1c465db5f998dca4e439981029b3b81fb39ed5
#
# haltsql-mcp: the MCP server (Python) plus the static haltsql CLI, so it can
# verify queries locally with no central server, or call a haltsql-server sidecar.
# Build from the repository root (it needs clients/python too):
#
#   docker build -f clients/mcp/Dockerfile -t haltsql-mcp:dev .
#   # with a locally built CLI image instead of the release:
#   docker build -t haltsql-local:dev .
#   docker build -f clients/mcp/Dockerfile --build-arg HALTSQL_IMAGE=haltsql-local:dev -t haltsql-mcp:dev .
#
#   # solo/local: a folder with policy.yaml (and optionally haltsql-mcp.yaml)
#   docker run -i --rm --read-only -v "$PWD:/config:ro" haltsql-mcp:dev \
#     postgresql://agent_ro@host.docker.internal:5432/app
#
# See docs/mcp.md#run-it-in-docker. The build context is filtered by
# clients/mcp/Dockerfile.dockerignore (BuildKit), not the root .dockerignore.

# Image that provides /usr/local/bin/haltsql (static, so it runs on any libc).
# The release workflow passes the digest of the image it just built.
ARG HALTSQL_IMAGE=ghcr.io/haltsql/haltsql:0.0.1

FROM ${HALTSQL_IMAGE} AS haltsql

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY clients/python /src/clients/python
COPY clients/mcp /src/clients/mcp
RUN python -m venv /opt/haltsql-mcp \
 && /opt/haltsql-mcp/bin/pip install /src/clients/python '/src/clients/mcp[yaml]' \
 && /opt/haltsql-mcp/bin/haltsql-mcp --help > /dev/null

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS runtime
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z
LABEL org.opencontainers.image.title="haltsql-mcp" \
      org.opencontainers.image.description="Safe drop-in replacement for the Postgres MCP server, guarded by HaltSQL" \
      org.opencontainers.image.url="https://github.com/HaltSQL/HaltSQL" \
      org.opencontainers.image.source="https://github.com/HaltSQL/HaltSQL" \
      org.opencontainers.image.documentation="https://github.com/HaltSQL/HaltSQL/blob/main/docs/mcp.md" \
      org.opencontainers.image.vendor="HaltSQL" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="python:3.13-slim-bookworm"
COPY --from=haltsql /usr/local/bin/haltsql /usr/local/bin/haltsql
COPY --from=haltsql /usr/share/doc/haltsql/ /usr/share/doc/haltsql/
COPY --from=build /opt/haltsql-mcp /opt/haltsql-mcp
COPY clients/mcp/docker/entrypoint.sh /usr/local/bin/haltsql-mcp-entrypoint
RUN ["/usr/local/bin/haltsql", "version"]
# Nothing writes to the root filesystem, so `docker run --read-only` works.
# HALTSQL_MCP_HOST only matters for --transport http: inside a container the
# listener must bind all interfaces. An unauthenticated HTTP listener is still
# refused off loopback, so HTTP needs a tokens file.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/haltsql-mcp/bin:${PATH}" \
    HALTSQL_BIN=/usr/local/bin/haltsql \
    HALTSQL_MCP_HOST=0.0.0.0
WORKDIR /config
EXPOSE 8765
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/haltsql-mcp-entrypoint"]
