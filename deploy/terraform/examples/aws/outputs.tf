output "endpoint" {
  description = "haltsql-server through the internal NLB."
  value       = module.haltsql.endpoint
}

output "service_name" {
  description = "ECS service name."
  value       = module.haltsql.service_name
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "log_group_name" {
  description = "CloudWatch log group."
  value       = module.haltsql.log_group_name
}
