# haltsql-server on Cloud Run (v2 API).
#
# A dedicated service account with no project-level roles runs the service.
# It can read exactly the secrets it is given; the Config document itself is
# a Secret Manager secret mounted as /etc/haltsql/config.yaml, the path the
# image's default command reads.

locals {
  config_mount = "/etc/haltsql"
  config_file  = "config.yaml"

  # Secret ids normalised to projects/P/secrets/S for IAM bindings.
  env_secret_names = { for k, v in var.secret_env : k => (startswith(v.secret, "projects/") ? v.secret : "projects/${var.project_id}/secrets/${v.secret}") }
  accessor_secrets = toset(concat(
    values(local.env_secret_names),
    [for s in var.runtime_secret_ids : startswith(s, "projects/") ? s : "projects/${var.project_id}/secrets/${s}"],
  ))
}

resource "google_service_account" "this" {
  project      = var.project_id
  account_id   = var.name
  display_name = "haltsql-server (${var.name})"
  description  = "Runtime identity of the ${var.name} Cloud Run service. No project-level roles."
}

# ---------------------------------------------------------------------------
# Config document
# ---------------------------------------------------------------------------

resource "google_secret_manager_secret" "config" {
  project   = var.project_id
  secret_id = "${var.name}-config"
  labels    = var.labels

  replication {
    dynamic "auto" {
      for_each = length(var.config_secret_replica_locations) == 0 ? [1] : []
      content {
        dynamic "customer_managed_encryption" {
          for_each = var.config_secret_kms_key == null ? [] : [var.config_secret_kms_key]
          content {
            kms_key_name = customer_managed_encryption.value
          }
        }
      }
    }
    dynamic "user_managed" {
      for_each = length(var.config_secret_replica_locations) == 0 ? [] : [1]
      content {
        dynamic "replicas" {
          for_each = var.config_secret_replica_locations
          content {
            location = replicas.value
            dynamic "customer_managed_encryption" {
              for_each = var.config_secret_kms_key == null ? [] : [var.config_secret_kms_key]
              content {
                kms_key_name = customer_managed_encryption.value
              }
            }
          }
        }
      }
    }
  }
}

resource "google_secret_manager_secret_version" "config" {
  secret      = google_secret_manager_secret.config.id
  secret_data = var.config_yaml
}

resource "google_secret_manager_secret_iam_member" "config" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.config.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.this.member
}

# ---------------------------------------------------------------------------
# Least-privilege runtime access
# ---------------------------------------------------------------------------

resource "google_secret_manager_secret_iam_member" "accessor" {
  for_each = local.accessor_secrets

  project   = split("/", each.value)[1]
  secret_id = split("/", each.value)[3]
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.this.member
}

resource "google_storage_bucket_iam_member" "audit" {
  for_each = toset(var.audit_gcs_buckets)

  bucket = each.value
  role   = "roles/storage.objectCreator"
  member = google_service_account.this.member
}

# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

resource "google_cloud_run_v2_service" "this" {
  project              = var.project_id
  location             = var.region
  name                 = var.name
  ingress              = var.ingress
  deletion_protection  = var.deletion_protection
  invoker_iam_disabled = var.invoker_iam_disabled
  labels               = var.labels

  template {
    service_account                  = google_service_account.this.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = var.concurrency
    timeout                          = "30s"
    labels                           = var.labels

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    dynamic "vpc_access" {
      for_each = var.vpc_access == null ? [] : [var.vpc_access]
      content {
        connector = vpc_access.value.connector
        egress    = vpc_access.value.egress

        dynamic "network_interfaces" {
          for_each = vpc_access.value.connector == null ? [1] : []
          content {
            network    = vpc_access.value.network
            subnetwork = vpc_access.value.subnetwork
            tags       = vpc_access.value.tags
          }
        }
      }
    }

    volumes {
      name = "config"
      secret {
        secret       = google_secret_manager_secret.config.secret_id
        default_mode = 292 # 0444
        items {
          version = google_secret_manager_secret_version.config.version
          path    = local.config_file
          mode    = 292
        }
      }
    }

    containers {
      name  = "haltsql"
      image = var.image
      args  = ["--config", "${local.config_mount}/${local.config_file}"]

      ports {
        name           = "http1"
        container_port = var.container_port
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "HALTSQL_LISTEN"
        value = "0.0.0.0:${var.container_port}"
      }

      dynamic "env" {
        for_each = var.environment
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = local.env_secret_names[env.key]
              version = env.value.version
            }
          }
        }
      }

      volume_mounts {
        name       = "config"
        mount_path = local.config_mount
      }

      startup_probe {
        http_get {
          path = "/readyz"
          port = var.container_port
        }
        period_seconds    = 2
        timeout_seconds   = 2
        failure_threshold = 30
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = var.container_port
        }
        period_seconds    = 10
        timeout_seconds   = 2
        failure_threshold = 3
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.config,
    google_secret_manager_secret_iam_member.accessor,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  for_each = toset(var.invoker_members)

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = each.value
}
