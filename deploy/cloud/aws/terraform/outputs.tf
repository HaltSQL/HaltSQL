output "audit_bucket" {
  description = "Bucket name for the s3 sink's `bucket`."
  value       = aws_s3_bucket.audit.bucket
}

output "audit_prefix" {
  description = "Prefix for the s3 sink's `prefix`."
  value       = local.audit_prefix
}

output "audit_kms_key_arn" {
  description = "KMS key encrypting the audit bucket."
  value       = aws_kms_key.audit.arn
}

output "policy_arn" {
  description = "Least-privilege policy for haltsql-server; attach it to an IRSA, EC2 instance-profile or other role."
  value       = aws_iam_policy.haltsql.arn
}

output "irsa_role_arn" {
  description = "Value for the ServiceAccount annotation eks.amazonaws.com/role-arn (null without var.irsa)."
  value       = var.irsa == null ? null : aws_iam_role.irsa[0].arn
}
