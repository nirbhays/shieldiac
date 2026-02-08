resource "google_cloud_run_v2_service" "backend" {
  name     = "shieldiac-backend-${var.environment}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = var.backend_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "1Gi"
        }
      }

      env {
        name  = "SHIELDIAC_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "SHIELDIAC_DATABASE_URL"
        value = "postgresql+asyncpg://postgres:${var.db_password}@/shieldiac?host=/cloudsql/${var.project_id}:${var.region}:shieldiac-db"
      }
      env {
        name  = "SHIELDIAC_REDIS_URL"
        value = "redis://${var.redis_host}:6379"
      }
      env {
        name = "SHIELDIAC_OPENAI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.openai_key.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 5
        period_seconds        = 5
      }

      liveness_probe {
        http_get {
          path = "/health"
        }
        period_seconds = 30
      }
    }

    service_account = google_service_account.backend.email
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.backend.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_secret_manager_secret" "openai_key" {
  secret_id = "shieldiac-openai-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "openai_key" {
  secret      = google_secret_manager_secret.openai_key.id
  secret_data = var.openai_api_key
}
