output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.this.name
}

output "service_id" {
  description = "ECS service ARN."
  value       = aws_ecs_service.this.id
}

output "task_definition_arn" {
  description = "Task definition ARN (with revision)."
  value       = aws_ecs_task_definition.this.arn
}

output "task_role_arn" {
  description = "IAM role haltsql-server runs as."
  value       = aws_iam_role.task.arn
}

output "execution_role_arn" {
  description = "IAM role ECS uses to start the task."
  value       = aws_iam_role.execution.arn
}

output "security_group_id" {
  description = "Security group of the tasks (allow it as a source in your database or agents' rules)."
  value       = aws_security_group.tasks.id
}

output "log_group_name" {
  description = "CloudWatch log group with the server logs and stdout audit records."
  value       = aws_cloudwatch_log_group.this.name
}

output "alb_target_group_arn" {
  description = "ALB target group to attach to your listener (null when not created)."
  value       = try(aws_lb_target_group.alb[0].arn, null)
}

output "nlb_dns_name" {
  description = "DNS name of the internal NLB (null when not created)."
  value       = try(aws_lb.nlb[0].dns_name, null)
}

output "endpoint" {
  description = "URL of haltsql-server through the internal NLB (null without the NLB)."
  value = try(
    "${var.internal_nlb.certificate_arn != null || var.server_tls ? "https" : "http"}://${aws_lb.nlb[0].dns_name}:${var.internal_nlb.port}",
    null,
  )
}
