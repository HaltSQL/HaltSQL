variable "subscription_id" {
  description = "Azure subscription id."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "westeurope"
}

variable "name" {
  description = "Name prefix of the deployment."
  type        = string
  default     = "haltsql-example"
}

variable "image" {
  description = "haltsql image (pin a digest in production)."
  type        = string
  default     = "ghcr.io/haltsql/haltsql:0.0.3"
}

variable "agent_token_sha256_secret" {
  description = <<-EOT
    Existing Key Vault secret (RBAC-enabled vault) holding the SHA-256 of the
    agent's bearer token. Null passes agent_token_sha256 as a plain
    environment variable instead (a hash, not the token).
  EOT
  type = object({
    key_vault_id = string
    secret_name  = string
  })
  default = null
}

variable "agent_token_sha256" {
  description = "SHA-256 (64 lower-case hex) of the agent's bearer token, used when agent_token_sha256_secret is null."
  type        = string
  default     = null

  validation {
    condition     = var.agent_token_sha256 == null || can(regex("^[0-9a-f]{64}$", var.agent_token_sha256))
    error_message = "agent_token_sha256 must be 64 lower-case hex characters."
  }
}
