# haltsql-server on Azure Container Apps.
#
# The Config document is stored as a Container Apps secret and mounted as a
# single read-only file. Secrets come from Key Vault through Container Apps
# secret references (resolved by the platform with a user-assigned identity)
# and reach haltsql-server as environment variables (${env:NAME} in the
# config). haltsql-server itself never calls Azure APIs.

locals {
  create_environment = var.container_app_environment_id == null
  create_workspace   = local.create_environment && var.environment.log_analytics_workspace_id == null
  environment_id     = local.create_environment ? azurerm_container_app_environment.this[0].id : var.container_app_environment_id

  config_secret = "haltsql-config"
  config_dir    = "/etc/haltsql/config"

  kv_secrets = {
    for env, s in var.key_vault_secrets : env => {
      # Container Apps secret names: lower-case alphanumerics and '-'.
      app_secret_name = "kv-${substr(lower(replace(env, "_", "-")), 0, 60)}"
      vault_name      = element(split("/", s.key_vault_id), length(split("/", s.key_vault_id)) - 1)
      versionless_url = "https://${element(split("/", s.key_vault_id), length(split("/", s.key_vault_id)) - 1)}.${var.key_vault_dns_suffix}/secrets/${s.secret_name}"
      scope           = "${s.key_vault_id}/secrets/${s.secret_name}"
    }
  }
}

resource "azurerm_user_assigned_identity" "this" {
  name                = "${var.name}-id"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Least privilege: read access to each referenced secret, not the vault.
resource "azurerm_role_assignment" "key_vault_secret" {
  for_each = local.kv_secrets

  scope                = each.value.scope
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "acr_pull" {
  count = var.acr_id == null ? 0 : 1

  scope                = var.acr_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_log_analytics_workspace" "this" {
  count = local.create_workspace ? 1 : 0

  name                = "${var.name}-logs"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = var.environment.log_retention_days
  tags                = var.tags
}

resource "azurerm_container_app_environment" "this" {
  count = local.create_environment ? 1 : 0

  name                           = "${var.name}-env"
  resource_group_name            = var.resource_group_name
  location                       = var.location
  logs_destination               = "log-analytics"
  log_analytics_workspace_id     = local.create_workspace ? azurerm_log_analytics_workspace.this[0].id : var.environment.log_analytics_workspace_id
  infrastructure_subnet_id       = var.environment.infrastructure_subnet_id
  internal_load_balancer_enabled = var.environment.infrastructure_subnet_id == null ? null : var.environment.internal_load_balancer_enabled
  zone_redundancy_enabled        = var.environment.zone_redundancy_enabled
  tags                           = var.tags
}

resource "azurerm_container_app" "this" {
  name                         = var.name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = local.environment_id
  revision_mode                = "Single"
  max_inactive_revisions       = 5
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  dynamic "registry" {
    for_each = var.acr_id == null ? [] : [split("/", var.image)[0]]
    content {
      server   = registry.value
      identity = azurerm_user_assigned_identity.this.id
    }
  }

  secret {
    name  = local.config_secret
    value = var.config_yaml
  }

  dynamic "secret" {
    for_each = local.kv_secrets
    content {
      name                = secret.value.app_secret_name
      key_vault_secret_id = secret.value.versionless_url
      identity            = azurerm_user_assigned_identity.this.id
    }
  }

  ingress {
    external_enabled           = var.ingress.external_enabled
    target_port                = var.container_port
    transport                  = "http"
    allow_insecure_connections = false

    dynamic "ip_security_restriction" {
      for_each = var.ingress.allowed_cidrs
      content {
        name             = "allow-${ip_security_restriction.key}"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
      }
    }

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas                     = var.min_replicas
    max_replicas                     = var.max_replicas
    termination_grace_period_seconds = 20

    http_scale_rule {
      name                = "http-concurrency"
      concurrent_requests = tostring(var.concurrent_requests_per_replica)
    }

    volume {
      name         = "config"
      storage_type = "Secret"
    }

    container {
      name   = "haltsql"
      image  = var.image
      cpu    = var.cpu
      memory = var.memory
      args   = ["--config", "${local.config_dir}/config.yaml"]

      env {
        name  = "HALTSQL_LISTEN"
        value = "0.0.0.0:${var.container_port}"
      }

      dynamic "env" {
        for_each = var.environment_variables
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.kv_secrets
        content {
          name        = env.key
          secret_name = env.value.app_secret_name
        }
      }

      # Only the config secret is visible in the container (sub_path), not
      # the Key Vault-backed secrets that share the secret volume.
      volume_mounts {
        name     = "config"
        path     = "${local.config_dir}/config.yaml"
        sub_path = local.config_secret
      }

      startup_probe {
        transport               = "HTTP"
        port                    = var.container_port
        path                    = "/readyz"
        interval_seconds        = 2
        failure_count_threshold = 30
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = var.container_port
        path                    = "/healthz"
        interval_seconds        = 10
        failure_count_threshold = 3
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = var.container_port
        path                    = "/readyz"
        interval_seconds        = 5
        failure_count_threshold = 2
      }
    }
  }

  # Container Apps resolves Key Vault references and pulls from ACR when the
  # revision is created, so the role assignments must exist first.
  depends_on = [
    azurerm_role_assignment.key_vault_secret,
    azurerm_role_assignment.acr_pull,
  ]
}
