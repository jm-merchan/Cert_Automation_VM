# Windows Server Outputs
output "admin_token" {
  description = "HCP Vault Cluster Admin Token"
  value       = hcp_vault_cluster_admin_token.admin_token.token
  sensitive   = true
}

output "hcp_vault_cluster_url" {
  description = "URL of the HCP Vault Cluster"
  value       = hcp_vault_cluster.example.vault_public_endpoint_url
}