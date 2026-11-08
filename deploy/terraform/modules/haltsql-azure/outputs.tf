output "container_app_id" {
  description = "Resource id of the container app."
  value       = azurerm_container_app.this.id
}

output "container_app_name" {
  description = "Name of the container app."
  value       = azurerm_container_app.this.name
}

output "environment_id" {
  description = "Container Apps environment id."
  value       = local.environment_id
}

output "fqdn" {
  description = "Ingress FQDN (internal to the environment unless ingress.external_enabled)."
  value       = azurerm_container_app.this.ingress[0].fqdn
}

output "endpoint" {
  description = "HTTPS URL of haltsql-server (TLS is terminated by Container Apps ingress)."
  value       = "https://${azurerm_container_app.this.ingress[0].fqdn}"
}

output "identity_id" {
  description = "Resource id of the user-assigned managed identity."
  value       = azurerm_user_assigned_identity.this.id
}

output "identity_principal_id" {
  description = "Principal id of the managed identity (grant it further roles if needed)."
  value       = azurerm_user_assigned_identity.this.principal_id
}

output "identity_client_id" {
  description = "Client id of the managed identity."
  value       = azurerm_user_assigned_identity.this.client_id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace of the created environment (null when an existing environment is used)."
  value       = local.create_environment ? (local.create_workspace ? azurerm_log_analytics_workspace.this[0].id : var.environment.log_analytics_workspace_id) : null
}
