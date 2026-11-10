# syntax=docker/dockerfile:1.6
#
# HaltSQL operator image: the controller manager plus the haltsql CLI, which
# the operator runs (`haltsql validate`) to validate HaltSQLPolicies with the
# exact loader rules haltsql-server uses.
#
#   docker build -t haltsql-operator:dev \
#     --build-arg HALTSQL_IMAGE=ghcr.io/haltsql/haltsql:0.0.3 deploy/operator
#
# HALTSQL_IMAGE must be the haltsql image the servers run (or the same
# release), so validation and serving agree. The haltsql binary in it is
# static (musl), so it runs on distroless/static.

ARG HALTSQL_IMAGE=ghcr.io/haltsql/haltsql:latest
ARG GO_IMAGE=golang:1.25

FROM ${HALTSQL_IMAGE} AS haltsql

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/manager ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="haltsql-operator" \
      org.opencontainers.image.description="Kubernetes operator for HaltSQL" \
      org.opencontainers.image.source="https://github.com/HaltSQL/HaltSQL" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /out/manager /manager
COPY --from=haltsql /usr/local/bin/haltsql /usr/local/bin/haltsql
USER 65532:65532
ENTRYPOINT ["/manager"]
