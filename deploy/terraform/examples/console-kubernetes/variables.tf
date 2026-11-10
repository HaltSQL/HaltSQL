variable "kubeconfig_path" {
  description = "Path of the kubeconfig for the cluster (EKS, GKE, AKS, kind)."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Kubeconfig context of the cluster."
  type        = string
}

variable "namespace" {
  description = "Namespace of the haltsql release; the console is installed next to it."
  type        = string
  default     = "haltsql"
}

variable "release_name" {
  description = "Helm release name of the console."
  type        = string
  default     = "haltsql-console"
}

variable "image_digest" {
  description = "Pinned sha256 digest of ghcr.io/haltsql/haltsql-console (verify its cosign signature first). Empty uses the chart appVersion tag."
  type        = string
  default     = ""

  validation {
    condition     = var.image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be empty or sha256:<64 hex>."
  }
}

variable "verifier_release" {
  description = "Helm release name of the haltsql chart the console watches (its Service, ConfigMaps and Deployment)."
  type        = string
  default     = "haltsql"
}

variable "admin_token_secret" {
  description = "Existing Secret in the namespace with key HALTSQL_ADMIN_TOKEN: the token whose name the verifiers list in server.admin.callers. Created by External Secrets, the CSI driver or kubectl, never by Terraform state."
  type        = string
  default     = "haltsql-console-env"
}

variable "values_files" {
  description = "Extra values files applied after the example's values, e.g. deploy/cloud/aws/console/eks.values.yaml."
  type        = list(string)
  default     = []
}

variable "storage_class" {
  description = "StorageClass of the state_dir volume (gp3, premium-rwo, managed-csi-premium); null uses the cluster default."
  type        = string
  default     = null
}

variable "automation_tokens" {
  description = "Console automation tokens: name, SHA-256 of the token (never the token) and role (dev, analyst, owner, audit, admin)."
  type = list(object({
    name   = string
    sha256 = string
    role   = string
  }))
  default = []

  validation {
    condition     = alltrue([for t in var.automation_tokens : can(regex("^[0-9a-f]{64}$", t.sha256))])
    error_message = "automation_tokens[*].sha256 must be 64 lower-case hex characters."
  }
  validation {
    condition     = alltrue([for t in var.automation_tokens : contains(["dev", "analyst", "owner", "audit", "admin"], t.role)])
    error_message = "automation_tokens[*].role must be one of dev, analyst, owner, audit, admin."
  }
}
