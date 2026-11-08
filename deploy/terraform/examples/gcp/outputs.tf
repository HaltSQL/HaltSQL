output "endpoint" {
  description = "Service URL (internal ingress: reachable from the project's VPC networks)."
  value       = module.haltsql.uri
}

output "service_account_email" {
  description = "Runtime service account."
  value       = module.haltsql.service_account_email
}
