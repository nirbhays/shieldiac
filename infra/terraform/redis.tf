resource "google_redis_instance" "cache" {
  name           = "shieldiac-redis-${var.environment}"
  tier           = "BASIC"
  memory_size_gb = 1
  region         = var.region
  redis_version  = "REDIS_7_0"

  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  labels = {
    app         = "shieldiac"
    environment = var.environment
  }
}
