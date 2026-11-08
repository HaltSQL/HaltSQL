variable "name" {
  description = "Name prefix for the IAM role, KMS alias and policy."
  type        = string
  default     = "haltsql"
}

variable "audit_bucket_name" {
  description = "Name of the S3 audit bucket to create (Object Lock is enabled at creation and cannot be added later)."
  type        = string
}

variable "audit_prefix" {
  description = "Key prefix haltsql writes under; must match the s3 sink's `prefix`."
  type        = string
  default     = "haltsql/audit/"

  validation {
    condition     = !startswith(var.audit_prefix, "/") && !strcontains(var.audit_prefix, "..")
    error_message = "audit_prefix must not start with / or contain .. (same rule as haltsql's config loader)."
  }
}

variable "object_lock_mode" {
  description = "Bucket default retention mode, a backstop for the per-object retention haltsql sets: GOVERNANCE or COMPLIANCE."
  type        = string
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "object_lock_days" {
  description = "Bucket default retention in days. Keep it equal to the sink's object_lock.retain_days."
  type        = number
  default     = 365
}

variable "transition_to_glacier_ir_days" {
  description = "Move audit objects to S3 Glacier Instant Retrieval after this many days (0 disables the rule)."
  type        = number
  default     = 90
}

variable "secret_arns" {
  description = "Secrets Manager secret ARNs haltsql reads with aws-sm placeholders (empty: no Secrets Manager permission)."
  type        = list(string)
  default     = []
}

variable "secrets_kms_key_arns" {
  description = "Customer-managed KMS keys that encrypt those secrets (kms:Decrypt via Secrets Manager only)."
  type        = list(string)
  default     = []
}

variable "irsa" {
  description = "IRSA trust: the EKS cluster's IAM OIDC provider ARN and issuer host (without https://), and the namespace / service account allowed to assume the role. Null creates no role."
  type = object({
    oidc_provider_arn = string
    oidc_issuer_host  = string
    namespace         = string
    service_account   = string
  })
  default = null
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
