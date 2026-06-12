variable "datadog_api_key" {
  description = "Datadog API key"
  sensitive   = true
  type        = string
}

variable "datadog_app_key" {
  description = "Datadog APP key"
  sensitive   = true
  type        = string
}

variable "datadog_api_url" {
  default     = "https://api.datadoghq.com/"
  description = "Datadog API URL for your site"
  type        = string
}

variable "dashboard_title" {
  default     = "Vault Secret Activity"
  description = "Dashboard title"
  type        = string
}

# variable "evaluation_window_days" {
#   default     = 30
#   description = "Days to evaluate for inactivity monitors (legacy, used only if evaluation_window_hours is not set)."
#   type        = number
# }
#
# variable "evaluation_window_hours" {
#   default     = 1
#   description = "Hours to evaluate for inactivity monitors. Valid range: 1 to 48. Overrides evaluation_window_days."
#   type        = number
#
#   validation {
#     condition     = var.evaluation_window_hours >= 1 && var.evaluation_window_hours <= 48
#     error_message = "evaluation_window_hours must be between 1 and 48."
#   }
# }
#
# variable "monitor_tags" {
#   default     = ["source:vault", "team:security"]
#   description = "Tags added to Datadog monitors"
#   type        = list(string)
# }

variable "vault_mount_prefix" {
  default     = "secrets"
  description = "KV mount prefix used in Vault paths"
  type        = string
}

# variable "secret_inventory_paths" {
#   description = "Full Vault secret data paths to evaluate for update inactivity (example: secrets/data/team/app/secret)"
#   type        = list(string)
#
#   validation {
#     condition     = length(var.secret_inventory_paths) > 0
#     error_message = "secret_inventory_paths must include at least one secret path."
#   }
# }
