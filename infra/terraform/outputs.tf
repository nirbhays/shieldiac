output "backend_url" {
  description = "Backend Cloud Run service URL"
  value       = google_cloud_run_v2_service.backend.uri
}

output "backend_service_account" {
  description = "Backend service account email"
  value       = google_service_account.backend.email
}
