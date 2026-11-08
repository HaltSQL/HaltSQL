output "endpoint" {
  description = "haltsql-server URL (internal to the Container Apps environment)."
  value       = module.haltsql.endpoint
}

output "container_app_name" {
  description = "Container app name."
  value       = module.haltsql.container_app_name
}

output "resource_group_name" {
  description = "Resource group."
  value       = azurerm_resource_group.this.name
}
