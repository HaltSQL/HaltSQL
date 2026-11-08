output "service_name" {
  description = "Cloud Run service name."
  value       = google_cloud_run_v2_service.this.name
}

output "service_id" {
  description = "Cloud Run service id."
  value       = google_cloud_run_v2_service.this.id
}

output "uri" {
  description = "Service URL (callers need roles/run.invoker and an ID token; ingress is internal by default)."
  value       = google_cloud_run_v2_service.this.uri
}

output "endpoint" {
  description = "Same as uri."
  value       = google_cloud_run_v2_service.this.uri
}

output "service_account_email" {
  description = "Runtime service account."
  value       = google_service_account.this.email
}

output "config_secret_id" {
  description = "Secret Manager secret holding the Config document."
  value       = google_secret_manager_secret.config.id
}

output "latest_revision" {
  description = "Latest ready revision."
  value       = google_cloud_run_v2_service.this.latest_ready_revision
}
