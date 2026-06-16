variable "cors_allowed_origins" {
  description = "Browser origins allowed to call Vault directly for this demo."
  type        = list(string)
  default     = ["http://localhost:8788"]
}

variable "demo_recipient" {
  description = "Recipient name stored in the demo secret payload."
  type        = string
  default     = "demo-recipient"
}

variable "demo_secret_message" {
  description = "Demo value wrapped by the sender and unwrapped by the receiver."
  type        = string
  default     = "secret-wrapping-demo-value"
  sensitive   = true
}

variable "demo_secret_path" {
  description = "Path of the demo secret inside the KV v2 mount."
  type        = string
  default     = "handoff"
}

variable "enable_cors" {
  description = "Whether Terraform should configure Vault CORS for the local frontend origin."
  type        = bool
  default     = false
}

variable "kv_mount_path" {
  description = "Vault KV v2 mount path used by the wrapping demo."
  type        = string
  default     = "secret-wrapping"
}

variable "sender_policy_name" {
  description = "Vault policy name for an operator or automation process that creates wrapped responses."
  type        = string
  default     = "secret-wrapping-sender"
}

variable "vault_namespace" {
  description = "Vault namespace where the wrapping demo resources are created. Use admin for HCP Vault Dedicated."
  type        = string
  default     = "admin"
}

variable "wrap_ttl" {
  description = "Suggested wrapping token TTL for the sender command examples."
  type        = string
  default     = "5m"
}