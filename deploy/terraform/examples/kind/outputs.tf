output "namespace" {
  description = "Namespace of the release."
  value       = module.haltsql.namespace
}

output "service_name" {
  description = "haltsql-server Service name."
  value       = module.haltsql.service_name
}

output "service_port" {
  description = "haltsql-server Service port."
  value       = module.haltsql.service_port
}

output "endpoints" {
  description = "In-cluster URLs."
  value       = module.haltsql.endpoints
}
