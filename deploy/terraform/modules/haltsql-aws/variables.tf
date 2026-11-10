# Inputs of the haltsql-aws module (haltsql-server on ECS Fargate).

variable "name" {
  description = "Name of the service. Used for the task family, IAM roles, log group, security group and load balancer resources."
  type        = string
  default     = "haltsql"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,20}[a-z0-9]$", var.name))
    error_message = "name must be 2-22 lower-case letters, digits or '-' (it prefixes load balancer and target group names, which AWS limits to 32 characters)."
  }
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------

variable "cluster_arn" {
  description = "ARN of the ECS cluster to run in."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_-]+$", var.cluster_arn))
    error_message = "cluster_arn must be an ECS cluster ARN."
  }
}

variable "vpc_id" {
  description = "VPC of the tasks."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must look like vpc-0123456789abcdef0."
  }
}

variable "subnet_ids" {
  description = "Private subnets for the tasks (at least two, in different AZs, for availability)."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 1 && alltrue([for s in var.subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", s))])
    error_message = "subnet_ids must be a non-empty list of subnet ids."
  }
}

variable "assign_public_ip" {
  description = "Give tasks a public IP. Off: run in private subnets with a NAT gateway or VPC endpoints."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

variable "image" {
  description = "haltsql image reference. Pin a digest (repo@sha256:...) for immutable, verifiable deployments."
  type        = string
  default     = "ghcr.io/haltsql/haltsql:0.0.1"

  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[0-9a-f]{64})?$", var.image)) && can(regex("[:@][^/]+$", var.image))
    error_message = "image must be registry/repository:tag or registry/repository@sha256:<digest> with an explicit registry."
  }
}

variable "config_init_image" {
  description = "Small image with sh and base64 that writes the config file into the task's ephemeral volume before haltsql-server starts (the haltsql image is distroless). Pin a digest in production."
  type        = string
  default     = "public.ecr.aws/docker/library/busybox:1.37.0"
}

variable "cpu_architecture" {
  description = "X86_64 or ARM64 (the haltsql image is multi-arch)."
  type        = string
  default     = "ARM64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be X86_64 or ARM64."
  }
}

variable "cpu" {
  description = "Task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.cpu)
    error_message = "cpu must be a Fargate CPU size: 256, 512, 1024, 2048, 4096, 8192 or 16384."
  }
}

variable "memory" {
  description = "Task memory in MiB (must be valid for the chosen cpu)."
  type        = number
  default     = 512

  validation {
    condition     = var.memory >= 512 && var.memory <= 122880 && var.memory % 512 == 0
    error_message = "memory must be a multiple of 512 MiB between 512 and 122880."
  }
}

variable "desired_count" {
  description = "Number of tasks."
  type        = number
  default     = 2

  validation {
    condition     = var.desired_count >= 0 && var.desired_count <= 100 && floor(var.desired_count) == var.desired_count
    error_message = "desired_count must be an integer between 0 and 100."
  }
}

variable "container_port" {
  description = "Port haltsql-server listens on inside the task."
  type        = number
  default     = 8080

  validation {
    condition     = var.container_port >= 1024 && var.container_port <= 65535
    error_message = "container_port must be 1024-65535 (the container runs as uid 65532)."
  }
}

variable "health_port" {
  description = "With server.tls and required client certificates, a plain-HTTP port that serves only /healthz and /readyz (--health-listen) for load balancer health checks. Null disables it."
  type        = number
  default     = null

  validation {
    condition     = var.health_port == null || try(var.health_port >= 1024 && var.health_port <= 65535, false)
    error_message = "health_port must be 1024-65535."
  }
}

variable "config_yaml" {
  description = <<-EOT
    The haltsql Config document (kind: Config) as YAML. It is written to
    /etc/haltsql/config/config.yaml. It must not contain secrets: use
    $${env:NAME} placeholders filled from `secrets` (ECS injects them from
    Secrets Manager or SSM). Policies are inline or come from a
    bundle_source. server.listen is overridden by HALTSQL_LISTEN.
  EOT
  type        = string

  validation {
    condition     = can(yamldecode(var.config_yaml)) && try(yamldecode(var.config_yaml).kind, "") == "Config"
    error_message = "config_yaml must be a YAML document with kind: Config."
  }
  validation {
    condition     = length(var.config_yaml) <= 32768
    error_message = "config_yaml must be at most 32 KiB (ECS task definitions are limited to 64 KiB); move large policies into a signed bundle."
  }
}

variable "environment" {
  description = "Plain environment variables for haltsql-server (never secrets; use `secrets`)."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k, _ in var.environment : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k)) && k != "HALTSQL_LISTEN"])
    error_message = "environment keys must be variable names; HALTSQL_LISTEN is set by the module."
  }
}

variable "secrets" {
  description = "Environment variables injected by ECS from Secrets Manager (ARN, optionally ARN:json-key::) or SSM Parameter Store (parameter ARN). The execution role gets read access to exactly these."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([for k, v in var.secrets : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k)) && (
      can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+(:[^:]*:[^:]*:[^:]*)?$", v)) ||
      can(regex("^arn:aws[a-z-]*:ssm:[a-z0-9-]+:[0-9]{12}:parameter/[A-Za-z0-9/_.-]+$", v))
    )])
    error_message = "secrets values must be Secrets Manager secret ARNs (optionally with :json-key:version-stage:version-id) or SSM parameter ARNs."
  }
}

# ---------------------------------------------------------------------------
# Runtime permissions of haltsql-server (task role)
# ---------------------------------------------------------------------------

variable "runtime_secret_arns" {
  description = "Secrets Manager secret ARNs that haltsql-server reads itself through $${aws-sm:...} placeholders (task role: secretsmanager:GetSecretValue on exactly these)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.runtime_secret_arns : can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", a))])
    error_message = "runtime_secret_arns must be Secrets Manager secret ARNs."
  }
}

variable "s3_bundle_objects" {
  description = "S3 objects holding signed policy bundles (bundle_source.s3). The task role gets s3:GetObject on exactly these keys and their detached signatures (key.sig)."
  type = list(object({
    bucket = string
    key    = string
  }))
  default = []

  validation {
    condition     = alltrue([for o in var.s3_bundle_objects : can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", o.bucket)) && length(o.key) > 0 && !startswith(o.key, "/") && !strcontains(o.key, "*")])
    error_message = "s3_bundle_objects need a valid bucket name and an exact key (no leading '/', no wildcards)."
  }
}

variable "s3_audit_destinations" {
  description = "S3 audit sinks (audit.sinks type s3). The task role gets s3:PutObject (and s3:PutObjectRetention when object_lock is true) under bucket/prefix."
  type = list(object({
    bucket      = string
    prefix      = optional(string, "haltsql/audit/")
    object_lock = optional(bool, false)
  }))
  default = []

  validation {
    condition     = alltrue([for d in var.s3_audit_destinations : can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", d.bucket)) && !strcontains(d.prefix, "*")])
    error_message = "s3_audit_destinations need a valid bucket name and a prefix without wildcards."
  }
}

variable "kms_key_arns" {
  description = "Customer-managed KMS keys protecting the secrets, bundles or audit objects above (kms:Decrypt, plus kms:GenerateDataKey for audit writes)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.kms_key_arns : can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$", a))])
    error_message = "kms_key_arns must be KMS key ARNs."
  }
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the container logs (audit records on stdout land here too)."
  type        = number
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch Logs retention value."
  }
}

variable "log_kms_key_arn" {
  description = "KMS key to encrypt the log group (recommended: audit records go to stdout)."
  type        = string
  default     = null
}

# ---------------------------------------------------------------------------
# Network access
# ---------------------------------------------------------------------------

variable "ingress_cidr_blocks" {
  description = "CIDR blocks allowed to reach haltsql-server (tasks, or the internal NLB when enabled). Never 0.0.0.0/0."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.ingress_cidr_blocks : can(cidrhost(c, 0)) && c != "0.0.0.0/0"])
    error_message = "ingress_cidr_blocks must be valid IPv4 CIDRs and must not be 0.0.0.0/0."
  }
}

variable "ingress_security_group_ids" {
  description = "Security groups allowed to reach haltsql-server (e.g. the agents' tasks, or your ALB)."
  type        = list(string)
  default     = []
}

variable "egress_cidr_blocks" {
  description = "Where tasks may connect on 443 (image pulls, Secrets Manager, S3, OIDC JWKS, bundle registries). Narrow this to your VPC endpoints' CIDR or use egress_prefix_list_ids where possible."
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = alltrue([for c in var.egress_cidr_blocks : can(cidrhost(c, 0))])
    error_message = "egress_cidr_blocks must be valid IPv4 CIDRs."
  }
}

variable "egress_prefix_list_ids" {
  description = "Managed prefix lists tasks may connect to on 443 (e.g. the S3 gateway endpoint prefix list)."
  type        = list(string)
  default     = []
}

variable "server_tls" {
  description = "Set to true when config_yaml configures server.tls, so target groups and health checks use HTTPS (or the plain-HTTP health_port when set)."
  type        = bool
  default     = false
}

variable "alb_target_group" {
  description = "Create an IP target group for an existing Application Load Balancer (attach it to your listener; allow the ALB's security group through ingress_security_group_ids)."
  type = object({
    enabled              = optional(bool, false)
    deregistration_delay = optional(number, 20)
  })
  default = {}

  validation {
    condition     = var.alb_target_group.deregistration_delay >= 0 && var.alb_target_group.deregistration_delay <= 3600
    error_message = "alb_target_group.deregistration_delay must be 0-3600 seconds."
  }
}

variable "internal_nlb" {
  description = "Create an internal Network Load Balancer in front of the tasks. With certificate_arn the listener terminates TLS; otherwise it passes TCP through (use server.tls for end-to-end encryption)."
  type = object({
    enabled             = optional(bool, false)
    subnet_ids          = optional(list(string))
    port                = optional(number, 8080)
    certificate_arn     = optional(string)
    ssl_policy          = optional(string, "ELBSecurityPolicy-TLS13-1-2-2021-06")
    cross_zone          = optional(bool, true)
    deletion_protection = optional(bool, true)
    access_logs_bucket  = optional(string)
    access_logs_prefix  = optional(string, "haltsql-nlb")
  })
  default = {}

  validation {
    condition     = var.internal_nlb.port >= 1 && var.internal_nlb.port <= 65535
    error_message = "internal_nlb.port must be a TCP port."
  }
}

variable "wait_for_steady_state" {
  description = "Wait for the service to reach a steady state on apply."
  type        = bool
  default     = true
}
