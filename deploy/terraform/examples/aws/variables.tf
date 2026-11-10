variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Name prefix of the deployment."
  type        = string
  default     = "haltsql-example"
}

variable "vpc_id" {
  description = "Existing VPC."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets with a NAT gateway or VPC endpoints (ECR, Secrets Manager, CloudWatch Logs, S3)."
  type        = list(string)
}

variable "caller_cidr_blocks" {
  description = "CIDRs of the agents that call haltsql-server through the internal NLB (e.g. the VPC CIDR)."
  type        = list(string)
}

variable "image" {
  description = "haltsql image (pin a digest in production)."
  type        = string
  default     = "ghcr.io/haltsql/haltsql:0.0.3"
}

variable "agent_token_sha256" {
  description = "SHA-256 (64 lower-case hex) of the agent's bearer token. Stored in Secrets Manager and injected by ECS."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.agent_token_sha256))
    error_message = "agent_token_sha256 must be 64 lower-case hex characters."
  }
}

variable "nlb_deletion_protection" {
  description = "Deletion protection on the internal NLB (turn off for throwaway CI deployments)."
  type        = bool
  default     = true
}
