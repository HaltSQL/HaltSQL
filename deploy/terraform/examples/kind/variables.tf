variable "kubeconfig_path" {
  description = "Path of the kubeconfig for the kind cluster."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Kubeconfig context of the kind cluster."
  type        = string
  default     = "kind-haltsql-terraform"
}

variable "namespace" {
  description = "Namespace to install into."
  type        = string
  default     = "haltsql-tf-e2e"
}

variable "image_repository" {
  description = "Repository of the locally built image loaded into kind."
  type        = string
  default     = "haltsql-local"
}

variable "image_tag" {
  description = "Tag of the locally built image loaded into kind."
  type        = string
  default     = "e2e"
}

variable "token_sha256" {
  description = "SHA-256 (64 lower-case hex) of the bearer token the test uses. The token itself never reaches Terraform."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.token_sha256))
    error_message = "token_sha256 must be 64 lower-case hex characters."
  }
}
