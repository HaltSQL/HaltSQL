variable "project_id" {
  description = "Google Cloud project."
  type        = string
}

variable "region" {
  description = "Cloud Run region."
  type        = string
  default     = "europe-west1"
}

variable "name" {
  description = "Name of the service."
  type        = string
  default     = "haltsql-example"
}

variable "image" {
  description = "haltsql image in Artifact Registry (or a remote repository proxying ghcr.io). Pin a digest in production."
  type        = string
}

variable "agent_token_sha256" {
  description = "SHA-256 (64 lower-case hex) of the agent's bearer token. Stored in Secret Manager and injected by Cloud Run."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.agent_token_sha256))
    error_message = "agent_token_sha256 must be 64 lower-case hex characters."
  }
}

variable "invoker_members" {
  description = "Who may call the service (roles/run.invoker), e.g. the agents' service accounts."
  type        = list(string)
  default     = []
}

variable "deletion_protection" {
  description = "Protect the service against destroy (turn off for throwaway CI deployments)."
  type        = bool
  default     = true
}
