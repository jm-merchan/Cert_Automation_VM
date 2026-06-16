variable "auth_mount_path" {
  description = "Vault auth mount path for the GitHub Actions JWT backend."
  type        = string
  default     = "jwt-github"
}

variable "bound_audience" {
  description = "Expected audience claim for GitHub Actions OIDC tokens."
  type        = string
  default     = "vault-github-actions"
}

variable "demo_secret_message" {
  description = "Demo value written to Vault and read by the GitHub Actions workflow."
  type        = string
  default     = "hello-from-vault"
  sensitive   = true
}

variable "demo_secret_path" {
  description = "Path of the demo secret inside the KV v2 mount."
  type        = string
  default     = "demo"
}

variable "github_actions_role_name" {
  description = "Vault JWT role name used by GitHub Actions."
  type        = string
  default     = "github-actions-demo"
}

variable "github_owner" {
  description = "GitHub organization or user that owns the repository allowed to authenticate."
  type        = string
}

variable "github_ref" {
  description = "Git ref allowed to authenticate, for example refs/heads/main. Glob patterns are supported."
  type        = string
  default     = "refs/heads/main"
}

variable "github_repo" {
  description = "GitHub repository name allowed to authenticate."
  type        = string
}

variable "kv_mount_path" {
  description = "Vault KV v2 mount path used by the workflow demo."
  type        = string
  default     = "github-actions"
}

variable "policy_name" {
  description = "Vault policy name attached to the GitHub Actions role."
  type        = string
  default     = "github-actions-demo"
}

variable "token_max_ttl" {
  description = "Maximum TTL for Vault tokens issued to GitHub Actions."
  type        = number
  default     = 600
}

variable "token_ttl" {
  description = "TTL for Vault tokens issued to GitHub Actions."
  type        = number
  default     = 300
}

variable "vault_namespace" {
  description = "Vault namespace where the auth method, policy, and KV mount are created. Use admin for HCP Vault Dedicated."
  type        = string
  default     = "admin"
}