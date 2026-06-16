output "auth_mount_path" {
  description = "Vault auth mount path configured for GitHub Actions OIDC."
  value       = vault_jwt_auth_backend.github.path
}

output "bound_audience" {
  description = "OIDC audience expected by the Vault JWT role."
  value       = var.bound_audience
}

output "demo_secret_path" {
  description = "Vault API path read by the GitHub Actions workflow."
  value       = "${vault_mount.github_actions.path}/data/${vault_kv_secret_v2.demo.name}"
}

output "github_actions_role_name" {
  description = "Vault JWT role name used by the GitHub Actions workflow."
  value       = vault_jwt_auth_backend_role.github_actions.role_name
}

output "vault_addr" {
  description = "Vault address to configure as a GitHub Actions repository variable."
  value       = data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url
}