# Inputs of the haltsql-gcp module (haltsql-server on Cloud Run).

variable "project_id" {
  description = "Project to deploy into."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project id."
  }
}

variable "region" {
  description = "Cloud Run region, e.g. europe-west1."
  type        = string
}

variable "name" {
  description = "Name of the Cloud Run service (also used for the service account and config secret)."
  type        = string
  default     = "haltsql"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,22}[a-z0-9]$", var.name))
    error_message = "name must be 6-24 lower-case letters, digits or '-', starting with a letter (it is also the service account id)."
  }
}

variable "labels" {
  description = "Labels for every resource."
  type        = map(string)
  default     = {}
}

variable "deletion_protection" {
  description = "Protect the Cloud Run service against terraform destroy."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------

variable "image" {
  description = "haltsql image. Cloud Run pulls from Artifact Registry (or a remote repository proxying ghcr.io); pin a digest for immutable deployments."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[0-9a-f]{64})?$", var.image)) && can(regex("[:@][^/]+$", var.image))
    error_message = "image must be registry/repository:tag or registry/repository@sha256:<digest> with an explicit registry."
  }
}

variable "cpu" {
  description = "CPU limit per instance (e.g. \"1\", \"2\")."
  type        = string
  default     = "1"

  validation {
    condition     = contains(["1", "2", "4", "6", "8"], var.cpu) || can(regex("^[0-9]+m$", var.cpu))
    error_message = "cpu must be 1, 2, 4, 6, 8 or a millicpu value like 500m."
  }
}

variable "memory" {
  description = "Memory limit per instance (e.g. 512Mi)."
  type        = string
  default     = "512Mi"

  validation {
    condition     = can(regex("^[0-9]+(Mi|Gi)$", var.memory))
    error_message = "memory must look like 512Mi or 2Gi."
  }
}

variable "min_instances" {
  description = "Minimum instances (at least 1 avoids cold starts on the verification path)."
  type        = number
  default     = 1

  validation {
    condition     = var.min_instances >= 0 && var.min_instances <= 1000
    error_message = "min_instances must be 0-1000."
  }
}

variable "max_instances" {
  description = "Maximum instances."
  type        = number
  default     = 10

  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 1000 && var.max_instances >= var.min_instances
    error_message = "max_instances must be 1-1000 and at least min_instances."
  }
}

variable "concurrency" {
  description = "Maximum concurrent requests per instance."
  type        = number
  default     = 80

  validation {
    condition     = var.concurrency >= 1 && var.concurrency <= 1000
    error_message = "concurrency must be 1-1000."
  }
}

variable "container_port" {
  description = "Port haltsql-server listens on."
  type        = number
  default     = 8080

  validation {
    condition     = var.container_port >= 1024 && var.container_port <= 65535
    error_message = "container_port must be 1024-65535."
  }
}

variable "config_yaml" {
  description = <<-EOT
    The haltsql Config document (kind: Config) as YAML. It is stored in a
    Secret Manager secret and mounted read-only at /etc/haltsql/config.yaml
    (each change creates a new secret version and a new revision). It must
    not contain secrets: use secret_env ($${env:NAME}) or $${gcp-sm:...}
    placeholders with runtime_secret_ids. Do not set server.tls: Cloud Run
    terminates TLS.
  EOT
  type        = string

  validation {
    condition     = can(yamldecode(var.config_yaml)) && try(yamldecode(var.config_yaml).kind, "") == "Config"
    error_message = "config_yaml must be a YAML document with kind: Config."
  }
  validation {
    condition     = !can(yamldecode(var.config_yaml).server.tls)
    error_message = "config_yaml must not set server.tls: Cloud Run terminates TLS in front of the service."
  }
}

variable "config_secret_replica_locations" {
  description = "Secret Manager locations for the config secret (user-managed replication). Empty uses automatic replication."
  type        = list(string)
  default     = []
}

variable "config_secret_kms_key" {
  description = "Cloud KMS key for the config secret (CMEK, automatic replication only). The Secret Manager service agent needs Encrypter/Decrypter on it."
  type        = string
  default     = null
}

variable "environment" {
  description = "Plain environment variables (never secrets; use secret_env)."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k, _ in var.environment : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k)) && !contains(["HALTSQL_LISTEN", "PORT"], k)])
    error_message = "environment keys must be variable names; HALTSQL_LISTEN and PORT are reserved."
  }
}

variable "secret_env" {
  description = "Environment variables from Secret Manager, keyed by variable name. secret is a secret id in project_id or projects/P/secrets/S. Pin version in production."
  type = map(object({
    secret  = string
    version = optional(string, "latest")
  }))
  default = {}

  validation {
    condition = alltrue([for k, v in var.secret_env :
      can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k)) &&
      can(regex("^(projects/[a-z0-9-]+/secrets/)?[A-Za-z0-9_-]{1,255}$", v.secret)) &&
      can(regex("^(latest|[0-9]+)$", v.version))
    ])
    error_message = "secret_env keys must be variable names, secret a secret id (or projects/P/secrets/S) and version latest or a number."
  }
}

variable "runtime_secret_ids" {
  description = "Secrets haltsql-server reads itself through $${gcp-sm:...} placeholders (secret ids in project_id, or projects/P/secrets/S). The service account gets secretAccessor on exactly these."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for s in var.runtime_secret_ids : can(regex("^(projects/[a-z0-9-]+/secrets/)?[A-Za-z0-9_-]{1,255}$", s))])
    error_message = "runtime_secret_ids must be secret ids or projects/P/secrets/S."
  }
}

variable "audit_gcs_buckets" {
  description = "Buckets of GCS audit sinks (audit.sinks type gcs). The service account gets roles/storage.objectCreator on each (create only: no read, overwrite or delete)."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------
# Network and access
# ---------------------------------------------------------------------------

variable "ingress" {
  description = "INGRESS_TRAFFIC_INTERNAL_ONLY (default: VPC and same-project callers), INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER or INGRESS_TRAFFIC_ALL."
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  validation {
    condition     = contains(["INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER", "INGRESS_TRAFFIC_ALL"], var.ingress)
    error_message = "ingress must be INGRESS_TRAFFIC_INTERNAL_ONLY, INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER or INGRESS_TRAFFIC_ALL."
  }
}

variable "invoker_members" {
  description = "IAM members allowed to call the service (roles/run.invoker), e.g. serviceAccount:agent@P.iam.gserviceaccount.com. allUsers and allAuthenticatedUsers are rejected."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for m in var.invoker_members : !contains(["allUsers", "allAuthenticatedUsers"], m) && can(regex("^(serviceAccount|user|group|domain|principal|principalSet):.+$", m))])
    error_message = "invoker_members must be IAM members; allUsers and allAuthenticatedUsers are not allowed."
  }
}

variable "vpc_access" {
  description = <<-EOT
    Optional VPC egress, for private bundle registries, OIDC issuers or
    secret endpoints: either a Serverless VPC Access connector, or Direct VPC
    egress (network and subnetwork). egress is PRIVATE_RANGES_ONLY or
    ALL_TRAFFIC.
  EOT
  type = object({
    connector  = optional(string)
    network    = optional(string)
    subnetwork = optional(string)
    tags       = optional(list(string), [])
    egress     = optional(string, "PRIVATE_RANGES_ONLY")
  })
  default = null

  validation {
    condition     = var.vpc_access == null || ((try(var.vpc_access.connector, null) != null) != (try(var.vpc_access.network, null) != null || try(var.vpc_access.subnetwork, null) != null))
    error_message = "vpc_access needs either connector or network/subnetwork (Direct VPC egress), not both."
  }
  validation {
    condition     = var.vpc_access == null || contains(["PRIVATE_RANGES_ONLY", "ALL_TRAFFIC"], try(var.vpc_access.egress, ""))
    error_message = "vpc_access.egress must be PRIVATE_RANGES_ONLY or ALL_TRAFFIC."
  }
}

variable "invoker_iam_disabled" {
  description = <<-EOT
    Disable the Cloud Run invoker IAM check, leaving authentication to
    haltsql-server's own tokens/OIDC. Only acceptable with internal ingress.
    With the check on (default), callers send a Google ID token in
    X-Serverless-Authorization and the haltsql bearer token in Authorization.
  EOT
  type        = bool
  default     = false

  validation {
    condition     = !var.invoker_iam_disabled || var.ingress != "INGRESS_TRAFFIC_ALL"
    error_message = "invoker_iam_disabled is only allowed with internal ingress."
  }
}
