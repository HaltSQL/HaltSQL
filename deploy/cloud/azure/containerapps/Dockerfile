# Bakes the haltsql config and policies into an immutable, versioned image.
# Container Apps has no ConfigMaps; baking is simpler and more auditable than
# pasting multi-line policies into secrets. Secrets (token hashes, TLS keys)
# are NOT baked in: they come from Key Vault through secret volumes.
#
#   az acr build -r <ACR_NAME> -t haltsql-analytics:1.0.0 \
#     --build-arg CONFIG=sidecar.yaml deploy/cloud/azure/containerapps
#
# CONFIG is sidecar.yaml (app.yaml) or shared.yaml (shared-service.yaml).
# Pin the base image by digest in production.
ARG HALTSQL_IMAGE=ghcr.io/haltsql/haltsql:0.1.0
FROM ${HALTSQL_IMAGE}
ARG CONFIG=sidecar.yaml
COPY haltsql/${CONFIG} /etc/haltsql/config.yaml
COPY haltsql/policies/ /etc/haltsql/policies/
# Inherited: ENTRYPOINT haltsql-server, CMD --config /etc/haltsql/config.yaml,
# USER 65532, HALTSQL_LISTEN=0.0.0.0:8080 (flags passed in the app override it).
