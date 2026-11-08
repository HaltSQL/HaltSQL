# haltsql-server on Cloud Run with internal-only ingress, a dedicated
# service account and the token hash injected from Secret Manager.

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "apis" {
  for_each = toset(["run.googleapis.com", "secretmanager.googleapis.com", "iam.googleapis.com"])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_secret_manager_secret" "agent_token_sha256" {
  project   = var.project_id
  secret_id = "${var.name}-agent-token-sha256"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "agent_token_sha256" {
  secret      = google_secret_manager_secret.agent_token_sha256.id
  secret_data = var.agent_token_sha256
}

module "haltsql" {
  source = "../../modules/haltsql-gcp"

  project_id          = var.project_id
  region              = var.region
  name                = var.name
  image               = var.image
  config_yaml         = file("${path.module}/haltsql.yaml")
  deletion_protection = var.deletion_protection

  secret_env = {
    HALTSQL_AGENT_TOKEN_SHA256 = {
      secret  = google_secret_manager_secret.agent_token_sha256.secret_id
      version = google_secret_manager_secret_version.agent_token_sha256.version
    }
  }

  min_instances   = 1
  max_instances   = 3
  invoker_members = var.invoker_members

  depends_on = [google_project_service.apis]
}
