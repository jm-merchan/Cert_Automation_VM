variable "base_namespace" {
  description = "Parent namespace where child namespaces are created"
  type        = string
  default     = "admin"
}

variable "namespace_prefix" {
  description = "Prefix for generated namespaces"
  type        = string
  default     = "team"
}

variable "namespace_count" {
  description = "How many namespaces to create"
  type        = number
  default     = 5
}

variable "secrets_per_namespace" {
  description = "How many secrets to create in each namespace"
  type        = number
  default     = 10
}

variable "updated_secrets_per_namespace" {
  description = "How many of the secrets per namespace should be marked as updated"
  type        = number
  default     = 5

  validation {
    condition     = var.updated_secrets_per_namespace <= var.secrets_per_namespace
    error_message = "updated_secrets_per_namespace must be less than or equal to secrets_per_namespace."
  }
}

variable "userpass_users_per_namespace" {
  description = "How many userpass users to create in each namespace"
  type        = number
  default     = 2
}

variable "kv_mount_path" {
  description = "KV mount path inside each generated namespace"
  type        = string
  default     = "secrets"
}

variable "userpass_mount_path" {
  description = "Userpass auth mount path inside each generated namespace"
  type        = string
  default     = "userpass"
}

variable "userpass_password_prefix" {
  description = "Prefix used to build demo userpass passwords"
  type        = string
  default     = "ChangeMe"
}
