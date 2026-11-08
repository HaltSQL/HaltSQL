# Inputs of the haltsql-azure module (haltsql-server on Azure Container Apps).

variable "name" {
  description = "Name of the container app (also prefixes the identity, environment and workspace)."
  type        = string
  default     = "haltsql"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,22}[a-z0-9]$", var.name)) && !strcontains(var.name, "--")
    error_message = "name must be 2-24 lower-case letters, digits or single '-', starting with a letter."
  }
}

variable "resource_group_name" {
  description = "Resource group for every resource the module creates."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

variable "container_app_environment_id" {
  description = "Existing Container Apps environment to deploy into. Null creates one (see environment)."
  type        = string
  default     = null

  validation {
    condition     = var.container_app_environment_id == null || can(regex("(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.App/managedEnvironments/[^/]+$", var.container_app_environment_id))
    error_message = "container_app_environment_id must be a Microsoft.App/managedEnvironments resource id."
  }
}

variable "environment" {
  description = <<-EOT
    The environment created when container_app_environment_id is null.
    With infrastructure_subnet_id the environment is VNet-integrated and,
    by default, only reachable through an internal load balancer.
  EOT
  type = object({
    infrastructure_subnet_id       = optional(string)
    internal_load_balancer_enabled = optional(bool, true)
    zone_redundancy_enabled        = optional(bool, false)
    log_analytics_workspace_id     = optional(string)
    log_retention_days             = optional(number, 90)
  })
  default = {}

  validation {
    condition     = var.environment.log_retention_days >= 30 && var.environment.log_retention_days <= 730
    error_message = "environment.log_retention_days must be between 30 and 730."
  }
  validation {
    condition     = !var.environment.zone_redundancy_enabled || var.environment.infrastructure_subnet_id != null
    error_message = "environment.zone_redundancy_enabled needs infrastructure_subnet_id."
  }
}

# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------

variable "image" {
  description = "haltsql image reference. Pin a digest (repo@sha256:...) for immutable deployments."
  type        = string
  default     = "ghcr.io/haltsql/haltsql:0.1.0"

  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[0-9a-f]{64})?$", var.image)) && can(regex("[:@][^/]+$", var.image))
    error_message = "image must be registry/repository:tag or registry/repository@sha256:<digest> with an explicit registry."
  }
}

variable "acr_id" {
  description = "Azure Container Registry holding the image. The identity gets AcrPull on exactly this registry and pulls with it. Null pulls anonymously (public images)."
  type        = string
  default     = null

  validation {
    condition     = var.acr_id == null || can(regex("(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.ContainerRegistry/registries/[^/]+$", var.acr_id))
    error_message = "acr_id must be a Microsoft.ContainerRegistry/registries resource id."
  }
}

variable "cpu" {
  description = "vCPU per replica (0.25 steps; memory must be 2 GiB per vCPU on the Consumption profile)."
  type        = number
  default     = 0.25

  validation {
    condition     = contains([0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75, 2, 2.5, 3, 3.5, 4], var.cpu)
    error_message = "cpu must be one of 0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75, 2, 2.5, 3, 3.5, 4."
  }
}

variable "memory" {
  description = "Memory per replica, e.g. 0.5Gi."
  type        = string
  default     = "0.5Gi"

  validation {
    condition     = can(regex("^[0-9]+(\\.[0-9]+)?Gi$", var.memory))
    error_message = "memory must look like 0.5Gi or 2Gi."
  }
}

variable "min_replicas" {
  description = "Minimum replicas (keep at least 1: a cold start delays the first verification)."
  type        = number
  default     = 1

  validation {
    condition     = var.min_replicas >= 0 && var.min_replicas <= 300
    error_message = "min_replicas must be 0-300."
  }
}

variable "max_replicas" {
  description = "Maximum replicas."
  type        = number
  default     = 5

  validation {
    condition     = var.max_replicas >= 1 && var.max_replicas <= 300 && var.max_replicas >= var.min_replicas
    error_message = "max_replicas must be 1-300 and at least min_replicas."
  }
}

variable "concurrent_requests_per_replica" {
  description = "HTTP scale rule: concurrent requests per replica before scaling out."
  type        = number
  default     = 100
}

variable "container_port" {
  description = "Port haltsql-server listens on."
  type        = number
  default     = 8080

  validation {
    condition     = var.container_port >= 1024 && var.container_port <= 65535
    error_message = "container_port must be 1024-65535."
  }
}

variable "config_yaml" {
  description = <<-EOT
    The haltsql Config document (kind: Config) as YAML, mounted read-only at
    /etc/haltsql/config/config.yaml from a Container Apps secret. It must not
    contain secrets: reference key_vault_secrets with $${env:NAME}. Policies
    are inline or come from a bundle_source. Do not configure server.tls:
    Container Apps ingress terminates TLS.
  EOT
  type        = string

  validation {
    condition     = can(yamldecode(var.config_yaml)) && try(yamldecode(var.config_yaml).kind, "") == "Config"
    error_message = "config_yaml must be a YAML document with kind: Config."
  }
  validation {
    condition     = !can(yamldecode(var.config_yaml).server.tls)
    error_message = "config_yaml must not set server.tls: Container Apps ingress terminates TLS in front of the app."
  }
}

variable "environment_variables" {
  description = "Plain environment variables (never secrets; use key_vault_secrets)."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k, _ in var.environment_variables : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k)) && k != "HALTSQL_LISTEN"])
    error_message = "environment_variables keys must be variable names; HALTSQL_LISTEN is set by the module."
  }
}

variable "key_vault_secrets" {
  description = <<-EOT
    Environment variables read from Key Vault by Container Apps with the
    module's user-assigned identity, keyed by variable name. The vault must
    use Azure RBAC; the identity gets "Key Vault Secrets User" on each listed
    secret only (not on the vault).
  EOT
  type = map(object({
    key_vault_id = string
    secret_name  = string
  }))
  default = {}

  validation {
    condition = alltrue([for k, v in var.key_vault_secrets :
      can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k)) &&
      can(regex("(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.KeyVault/vaults/[a-zA-Z0-9-]{3,24}$", v.key_vault_id)) &&
      can(regex("^[0-9a-zA-Z-]{1,127}$", v.secret_name))
    ])
    error_message = "key_vault_secrets keys must be variable names, key_vault_id a Microsoft.KeyVault/vaults id and secret_name a Key Vault secret name."
  }
}

variable "key_vault_dns_suffix" {
  description = "Key Vault DNS suffix (vault.azure.net in the public cloud; vault.usgovcloudapi.net, vault.azure.cn in sovereign clouds)."
  type        = string
  default     = "vault.azure.net"
}

# ---------------------------------------------------------------------------
# Ingress
# ---------------------------------------------------------------------------

variable "ingress" {
  description = <<-EOT
    Ingress. Internal by default: only apps in the same environment (and, for
    a VNet-integrated environment, the VNet) can call haltsql-server.
    allowed_cidrs restricts callers further (ip_security_restriction).
  EOT
  type = object({
    external_enabled = optional(bool, false)
    allowed_cidrs    = optional(list(string), [])
  })
  default = {}

  validation {
    condition     = alltrue([for c in var.ingress.allowed_cidrs : can(cidrhost(c, 0)) && c != "0.0.0.0/0"])
    error_message = "ingress.allowed_cidrs must be CIDRs other than 0.0.0.0/0."
  }
  validation {
    condition     = !var.ingress.external_enabled || length(var.ingress.allowed_cidrs) > 0
    error_message = "external ingress needs ingress.allowed_cidrs: haltsql-server must never be open to the internet."
  }
}
