# Derived image for ECS: the official distroless image plus an immutable
# config and policies. ECS has no ConfigMaps, and baking them in means every
# policy change is a new, reviewable image digest.
#
#   docker build -f deploy/cloud/aws/ecs/Dockerfile -t haltsql-config:2026-11-08 deploy/cloud/aws/ecs
#   (put your policies in deploy/cloud/aws/ecs/policies/ first)
#
# Pin the base by digest after verifying its signature (docs/deployment.md).
ARG HALTSQL_IMAGE=ghcr.io/haltsql/haltsql:0.1.0
FROM ${HALTSQL_IMAGE}
COPY config.yaml /etc/haltsql/config.yaml
COPY policies/ /etc/haltsql/policies/
# The base image's ENTRYPOINT (haltsql-server) and CMD
# (--config /etc/haltsql/config.yaml) are kept; it still runs as uid 65532.
