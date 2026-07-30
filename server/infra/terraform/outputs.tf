output "cloud_run_service_url" {
  description = "Public URL of the Cloud Run service"
  value       = google_cloud_run_v2_service.control_plane.uri
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository path"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.server.repository_id}"
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL connection name"
  value       = google_sql_database_instance.main.connection_name
}

output "database_url_secret_id" {
  description = "Secret Manager secret ID that stores DATABASE_URL"
  value       = google_secret_manager_secret.database_url.secret_id
}

output "db_password_secret_id" {
  description = "Secret Manager secret ID that stores the generated DB password"
  value       = google_secret_manager_secret.db_password.secret_id
}

output "github_client_secret_secret_id" {
  description = "Secret Manager secret ID that stores GitHub OAuth client secret"
  value       = google_secret_manager_secret.github_client_secret.secret_id
}

output "github_app_private_key_secret_id" {
  description = "Secret Manager secret ID that stores GitHub App private key"
  value       = google_secret_manager_secret.github_app_private_key.secret_id
}

output "github_app_webhook_secret_secret_id" {
  description = "Secret Manager secret ID that stores GitHub App webhook secret"
  value       = google_secret_manager_secret.github_app_webhook_secret.secret_id
}
