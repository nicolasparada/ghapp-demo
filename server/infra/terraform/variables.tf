variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for Artifact Registry, Cloud Run, and Cloud SQL"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run service name"
  type        = string
  default     = "ghapp-control-plane"
}

variable "artifact_repository_id" {
  description = "Artifact Registry Docker repository ID"
  type        = string
  default     = "control-plane"
}

variable "container_image" {
  description = "Container image URI to deploy"
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "sql_instance_name" {
  description = "Cloud SQL instance name"
  type        = string
  default     = "ghapp-demo-pg"
}

variable "sql_database_version" {
  description = "Cloud SQL PostgreSQL version"
  type        = string
  default     = "POSTGRES_18"
}

variable "sql_database_name" {
  description = "Cloud SQL database name"
  type        = string
  default     = "ghapp_demo"
}

variable "sql_database_user" {
  description = "Cloud SQL database user"
  type        = string
  default     = "ghapp_demo"
}

variable "db_secret_id" {
  description = "Secret Manager secret ID where Terraform stores the generated DB password"
  type        = string
  default     = "ghapp-control-plane-db-password"
}

variable "database_url_secret_id" {
  description = "Secret Manager secret ID where Terraform stores the generated DATABASE_URL"
  type        = string
  default     = "ghapp-control-plane-database-url"
}

variable "db_credentials_version" {
  description = "Bump to rotate generated DB credentials and secret versions"
  type        = number
  default     = 1
}

variable "app_secrets_version" {
  description = "Bump to rotate application secret versions in Secret Manager"
  type        = number
  default     = 1
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-1-3840"
}

variable "sql_deletion_protection" {
  description = "Whether to enable Cloud SQL deletion protection"
  type        = bool
  default     = false
}

variable "base_url" {
  description = "Public HTTPS base URL for the control-plane. Use a custom domain if known, otherwise bootstrap then update"
  type        = string
  default     = "https://example.invalid"
}

variable "oidc_issuer" {
  description = "OIDC issuer for GitHub Actions"
  type        = string
  default     = "https://token.actions.githubusercontent.com"
}

variable "oidc_audience" {
  description = "Expected OIDC audience for GitHub Actions. If empty, base_url is used"
  type        = string
  default     = ""
}

variable "github_client_id" {
  description = "GitHub OAuth App client ID"
  type        = string
}

variable "github_client_secret" {
  description = "GitHub OAuth App client secret (stored in Secret Manager via write-only secret version)"
  type        = string
  sensitive   = true
}

variable "github_client_secret_secret_id" {
  description = "Secret Manager secret ID for GitHub OAuth client secret"
  type        = string
  default     = "ghapp-control-plane-github-client-secret"
}

variable "github_app_id" {
  description = "GitHub App ID"
  type        = string
}

variable "github_app_private_key" {
  description = "GitHub App private key PEM (supports escaped newlines, stored in Secret Manager via write-only secret version)"
  type        = string
  sensitive   = true
}

variable "github_app_private_key_secret_id" {
  description = "Secret Manager secret ID for GitHub App private key"
  type        = string
  default     = "ghapp-control-plane-github-app-private-key"
}

variable "github_app_webhook_secret" {
  description = "GitHub App webhook secret (stored in Secret Manager via write-only secret version)"
  type        = string
  sensitive   = true
}

variable "github_app_webhook_secret_secret_id" {
  description = "Secret Manager secret ID for GitHub App webhook secret"
  type        = string
  default     = "ghapp-control-plane-github-app-webhook-secret"
}

variable "iam_db_login_user_email" {
  description = "Human IAM user email allowed to authenticate to Cloud SQL Postgres"
  type        = string
  default     = "parada.nicolas@outlook.com"
}

variable "allow_unauthenticated" {
  description = "Allow unauthenticated access to Cloud Run"
  type        = bool
  default     = true
}

variable "min_instance_count" {
  description = "Cloud Run minimum instances"
  type        = number
  default     = 0
}

variable "max_instance_count" {
  description = "Cloud Run maximum instances"
  type        = number
  default     = 1
}

variable "container_cpu" {
  description = "Cloud Run container CPU limit"
  type        = string
  default     = "1"
}

variable "container_memory" {
  description = "Cloud Run container memory limit"
  type        = string
  default     = "512Mi"
}
