variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment (staging/production)"
  type        = string
  default     = "production"
}

variable "domain" {
  description = "Domain for the application"
  type        = string
  default     = "shieldiac.dev"
}

variable "backend_image" {
  description = "Backend Docker image URL"
  type        = string
}

variable "db_password" {
  description = "PostgreSQL password"
  type        = string
  sensitive   = true
}

variable "redis_host" {
  description = "Redis host"
  type        = string
}

variable "openai_api_key" {
  description = "OpenAI API key"
  type        = string
  sensitive   = true
}
