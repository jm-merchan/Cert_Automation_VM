output "dashboard_id" {
  description = "Datadog dashboard ID"
  value       = datadog_dashboard_json.vault_secret_activity.id
}

output "dashboard_url" {
  description = "Datadog dashboard URL"
  value       = format("%sdashboard/%s", replace(var.datadog_api_url, "api.", "app."), datadog_dashboard_json.vault_secret_activity.id)
}

# output "monitor_ids" {
#   description = "Datadog monitor IDs"
#   value = {
#     vault_secret_not_read             = datadog_monitor.vault_secret_not_read.id
#     vault_secret_not_updated          = datadog_monitor.vault_secret_not_updated.id
#     vault_secret_not_updated_internal = {
#       for path, monitor in datadog_monitor.vault_secret_not_updated_internal :
#       path => monitor.id
#     }
#   }
# }
