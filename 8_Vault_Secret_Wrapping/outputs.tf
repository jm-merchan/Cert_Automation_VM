output "demo_secret_api_path" {
  description = "Vault API path to wrap for the demo secret."
  value       = "${vault_mount.wrapping_demo.path}/data/${vault_kv_secret_v2.demo.name}"
}

output "frontend_origin" {
  description = "Local frontend origin allowed by Vault CORS."
  value       = var.cors_allowed_origins[0]
}

output "sender_policy_name" {
  description = "Policy that allows reading the demo secret so the sender can create wrapped responses."
  value       = vault_policy.wrapping_sender.name
}

output "vault_addr" {
  description = "Vault address used by the frontend."
  value       = data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url
}

output "vault_namespace" {
  description = "Vault namespace used by the frontend."
  value       = var.vault_namespace
}

output "wrap_command" {
  description = "Vault CLI command that creates a wrapping token for the demo secret."
  value       = "VAULT_ADDR=${data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url} VAULT_NAMESPACE=${var.vault_namespace} vault kv get -wrap-ttl=${var.wrap_ttl} -format=json ${vault_mount.wrapping_demo.path}/${vault_kv_secret_v2.demo.name}"
}