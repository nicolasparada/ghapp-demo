variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for Artifact Registry, Cloud Run, and Cloud SQL"
  type        = string
  default     = "us-central1"
}

variable "container_image" {
  description = "Container image URI to deploy"
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "base_url" {
  description = "Public HTTPS base URL for the control-plane"
  type        = string
  default     = "https://example.invalid"
}

variable "github_client_id" {
  description = "GitHub OAuth App client ID (optional during bootstrap)"
  type        = string
  default     = ""
}

variable "github_client_secret" {
  description = "GitHub OAuth App client secret (optional during bootstrap; stored in Secret Manager when provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_app_id" {
  description = "GitHub App ID (optional during bootstrap)"
  type        = string
  default     = ""
}

variable "github_app_install_url" {
  description = "GitHub App installation URL shown in the control-plane UI"
  type        = string
  default     = "https://github.com/apps/ghapp-demo-app/installations/new"
}

variable "github_app_private_key" {
  description = "GitHub App private key PEM (optional during bootstrap; stored in Secret Manager when provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_app_webhook_secret" {
  description = "GitHub App webhook secret (optional during bootstrap; stored in Secret Manager when provided)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "app_secrets_version" {
  description = "Bump to rotate application secret versions in Secret Manager"
  type        = number
  default     = 1
}
