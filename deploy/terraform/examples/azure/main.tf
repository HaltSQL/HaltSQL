# haltsql-server on Azure Container Apps with internal ingress, a new
# environment and Log Analytics workspace, and the token hash read from Key
# Vault with a user-assigned managed identity.

provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "core"
}

resource "azurerm_resource_group" "this" {
  name     = "${var.name}-rg"
  location = var.location
  tags     = { "app.kubernetes.io/part-of" = "haltsql", ManagedBy = "terraform" }
}

module "haltsql" {
  source = "../../modules/haltsql-azure"

  name                = var.name
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  image               = var.image
  config_yaml         = file("${path.module}/haltsql.yaml")

  key_vault_secrets = var.agent_token_sha256_secret == null ? {} : {
    HALTSQL_AGENT_TOKEN_SHA256 = var.agent_token_sha256_secret
  }
  environment_variables = var.agent_token_sha256_secret == null ? {
    HALTSQL_AGENT_TOKEN_SHA256 = var.agent_token_sha256
  } : {}

  min_replicas = 1
  max_replicas = 3
  tags         = azurerm_resource_group.this.tags
}

check "token_hash_source" {
  assert {
    condition     = var.agent_token_sha256_secret != null || var.agent_token_sha256 != null
    error_message = "Set agent_token_sha256_secret or agent_token_sha256."
  }
}
