locals {
  service_name            = "ghapp-control-plane"
  artifact_repository_id  = "control-plane"
  sql_instance_name       = "ghapp-demo-pg"
  sql_database_version    = "POSTGRES_18"
  sql_edition             = "ENTERPRISE"
  db_tier                 = "db-custom-1-3840"
  sql_data_api_access     = "ALLOW_DATA_API"
  sql_backup_enabled      = false
  sql_deletion_protection = false

  sql_database_name = "ghapp_demo"
  sql_database_user = "ghapp_demo"

  db_secret_id                     = "ghapp-control-plane-db-password"
  database_url_secret_id           = "ghapp-control-plane-database-url"
  github_client_secret_secret_id   = "ghapp-control-plane-github-client-secret"
  github_app_private_key_secret_id = "ghapp-control-plane-github-app-private-key"
  token_encryption_key_secret_id   = "ghapp-control-plane-token-encryption-key"
  db_credentials_version           = 1
  token_encryption_key_version     = 1

  iam_db_login_users = toset([
    "parada.nicolas@outlook.com",
  ])
  should_grant_human_db_project_roles = length(local.iam_db_login_users) > 0

  allow_unauthenticated = true
  min_instance_count    = 0
  max_instance_count    = 1
  container_cpu         = "1"
  container_memory      = "512Mi"

  oidc_issuer             = "https://token.actions.githubusercontent.com"
  oidc_audience_effective = var.base_url

  sql_connection_name = google_sql_database_instance.main.connection_name
  database_url        = "postgres://${local.sql_database_user}:${urlencode(ephemeral.random_password.db_password.result)}@/${local.sql_database_name}?host=/cloudsql/${local.sql_connection_name}&sslmode=disable"

  has_github_client_secret   = trimspace(var.github_client_secret) != ""
  has_github_app_private_key = trimspace(var.github_app_private_key) != ""
}

moved {
  from = google_sql_user.iam_human_user[0]
  to   = google_sql_user.iam_human_user["parada.nicolas@outlook.com"]
}

moved {
  from = google_project_iam_member.iam_human_cloudsql_client[0]
  to   = google_project_iam_member.iam_human_cloudsql_client["parada.nicolas@outlook.com"]
}

moved {
  from = google_project_iam_member.iam_human_cloudsql_instance_user[0]
  to   = google_project_iam_member.iam_human_cloudsql_instance_user["parada.nicolas@outlook.com"]
}

moved {
  from = google_project_iam_member.iam_human_cloudsql_studio_user[0]
  to   = google_project_iam_member.iam_human_cloudsql_studio_user["parada.nicolas@outlook.com"]
}

resource "google_project_service" "cloudresourcemanager" {
  project            = var.project_id
  service            = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifactregistry" {
  project            = var.project_id
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "run" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false

  depends_on = [google_project_service.cloudresourcemanager]
}

resource "google_project_service" "iam" {
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false

  depends_on = [google_project_service.cloudresourcemanager]
}

resource "google_project_service" "sqladmin" {
  project            = var.project_id
  service            = "sqladmin.googleapis.com"
  disable_on_destroy = false

  depends_on = [google_project_service.cloudresourcemanager]
}

resource "google_project_service" "secretmanager" {
  project            = var.project_id
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false

  depends_on = [google_project_service.cloudresourcemanager]
}

resource "google_artifact_registry_repository" "server" {
  location      = var.region
  repository_id = local.artifact_repository_id
  format        = "DOCKER"

  depends_on = [
    google_project_service.cloudresourcemanager,
    google_project_service.artifactregistry,
  ]
}

resource "google_sql_database_instance" "main" {
  name             = local.sql_instance_name
  region           = var.region
  database_version = local.sql_database_version

  deletion_protection = local.sql_deletion_protection

  settings {
    tier            = local.db_tier
    edition         = local.sql_edition
    data_api_access = local.sql_data_api_access

    ip_configuration {
      ipv4_enabled = true
    }

    backup_configuration {
      enabled = local.sql_backup_enabled
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
  }

  depends_on = [google_project_service.sqladmin]
}

resource "google_sql_database" "main" {
  name     = local.sql_database_name
  instance = google_sql_database_instance.main.name
}

ephemeral "random_password" "token_encryption_key" {
  length  = 32
  special = false
}

ephemeral "random_password" "db_password" {
  length           = 40
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "google_sql_user" "app" {
  name     = local.sql_database_user
  instance = google_sql_database_instance.main.name

  password_wo         = ephemeral.random_password.db_password.result
  password_wo_version = local.db_credentials_version
}

resource "google_sql_user" "iam_human_user" {
  for_each = local.iam_db_login_users

  name     = each.value
  instance = google_sql_database_instance.main.name
  type     = "CLOUD_IAM_USER"
}

resource "google_service_account" "control_plane" {
  account_id   = "ghapp-control-plane"
  display_name = "ghapp-demo control-plane"

  depends_on = [google_project_service.iam]
}

resource "google_project_iam_member" "control_plane_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = local.db_secret_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "db_password" {
  secret = google_secret_manager_secret.db_password.id

  secret_data_wo         = ephemeral.random_password.db_password.result
  secret_data_wo_version = local.db_credentials_version
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = local.database_url_secret_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.database_url.id

  secret_data_wo         = local.database_url
  secret_data_wo_version = local.db_credentials_version
}

resource "google_secret_manager_secret" "github_client_secret" {
  count = local.has_github_client_secret ? 1 : 0

  secret_id = local.github_client_secret_secret_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "github_client_secret" {
  count = local.has_github_client_secret ? 1 : 0

  secret = google_secret_manager_secret.github_client_secret[0].id

  secret_data_wo         = var.github_client_secret
  secret_data_wo_version = var.app_secrets_version
}

resource "google_secret_manager_secret" "github_app_private_key" {
  count = local.has_github_app_private_key ? 1 : 0

  secret_id = local.github_app_private_key_secret_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "github_app_private_key" {
  count = local.has_github_app_private_key ? 1 : 0

  secret = google_secret_manager_secret.github_app_private_key[0].id

  secret_data_wo         = var.github_app_private_key
  secret_data_wo_version = var.app_secrets_version
}



resource "google_secret_manager_secret" "token_encryption_key" {
  secret_id = local.token_encryption_key_secret_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_version" "token_encryption_key" {
  secret = google_secret_manager_secret.token_encryption_key.id

  # Application expects TOKEN_ENCRYPTION_KEY to be base64 that decodes to 32 bytes.
  secret_data_wo         = base64encode(ephemeral.random_password.token_encryption_key.result)
  secret_data_wo_version = local.token_encryption_key_version
}

resource "google_secret_manager_secret_iam_member" "control_plane_token_encryption_key_accessor" {
  secret_id = google_secret_manager_secret.token_encryption_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_secret_manager_secret_iam_member" "control_plane_database_url_accessor" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_secret_manager_secret_iam_member" "control_plane_github_client_secret_accessor" {
  count = local.has_github_client_secret ? 1 : 0

  secret_id = google_secret_manager_secret.github_client_secret[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_secret_manager_secret_iam_member" "control_plane_github_app_private_key_accessor" {
  count = local.has_github_app_private_key ? 1 : 0

  secret_id = google_secret_manager_secret.github_app_private_key[0].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control_plane.email}"
}



resource "google_project_iam_member" "iam_human_cloudsql_client" {
  for_each = local.should_grant_human_db_project_roles ? local.iam_db_login_users : toset([])

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "user:${each.value}"
}

resource "google_project_iam_member" "iam_human_cloudsql_instance_user" {
  for_each = local.should_grant_human_db_project_roles ? local.iam_db_login_users : toset([])

  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "user:${each.value}"
}

resource "google_project_iam_member" "iam_human_cloudsql_studio_user" {
  for_each = local.should_grant_human_db_project_roles ? local.iam_db_login_users : toset([])

  project = var.project_id
  role    = "roles/cloudsql.studioUser"
  member  = "user:${each.value}"
}

resource "google_cloud_run_v2_service" "control_plane" {
  name     = local.service_name
  location = var.region

  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.control_plane.email

    scaling {
      min_instance_count = local.min_instance_count
      max_instance_count = local.max_instance_count
    }

    containers {
      image = var.container_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = local.container_cpu
          memory = local.container_memory
        }
      }



      env {
        name  = "BASE_URL"
        value = var.base_url
      }

      env {
        name = "DATABASE_URL"

        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "OIDC_ISSUER"
        value = local.oidc_issuer
      }

      env {
        name  = "OIDC_AUDIENCE"
        value = local.oidc_audience_effective
      }

      env {
        name  = "GITHUB_CLIENT_ID"
        value = var.github_client_id
      }

      dynamic "env" {
        for_each = local.has_github_client_secret ? [1] : []

        content {
          name = "GITHUB_CLIENT_SECRET"

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.github_client_secret[0].secret_id
              version = "latest"
            }
          }
        }
      }

      env {
        name  = "GITHUB_APP_ID"
        value = var.github_app_id
      }

      env {
        name  = "GITHUB_APP_SLUG"
        value = var.github_app_slug
      }

      dynamic "env" {
        for_each = local.has_github_app_private_key ? [1] : []

        content {
          name = "GITHUB_APP_PRIVATE_KEY"

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.github_app_private_key[0].secret_id
              version = "latest"
            }
          }
        }
      }

      env {
        name = "TOKEN_ENCRYPTION_KEY"

        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.token_encryption_key.secret_id
            version = "latest"
          }
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }
    }

    volumes {
      name = "cloudsql"

      cloud_sql_instance {
        instances = [local.sql_connection_name]
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.run,
    google_sql_database.main,
    google_sql_user.app,
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_version.github_client_secret,
    google_secret_manager_secret_version.github_app_private_key,
    google_secret_manager_secret_version.token_encryption_key,
    google_secret_manager_secret_iam_member.control_plane_database_url_accessor,
    google_secret_manager_secret_iam_member.control_plane_github_client_secret_accessor,
    google_secret_manager_secret_iam_member.control_plane_github_app_private_key_accessor,
    google_secret_manager_secret_iam_member.control_plane_token_encryption_key_accessor,
    google_project_iam_member.control_plane_cloudsql_client,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  count = local.allow_unauthenticated ? 1 : 0

  name     = google_cloud_run_v2_service.control_plane.name
  location = google_cloud_run_v2_service.control_plane.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
