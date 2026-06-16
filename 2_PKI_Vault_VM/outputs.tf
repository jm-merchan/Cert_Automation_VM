output "tls_private_key_pem" {
  description = "PEM-encoded RSA 4096 private key"
  value       = tls_private_key.rsa_4096_key.private_key_pem
  sensitive   = true
}

output "create_local_key" {
  description = "Retrieve key from state"
  value       = <<-EOT
  eval $(terraform output -raw tls_private_key_pem > aws.pem && chmod 600 aws.pem)
EOT

}

# EC2 instance-related outputs are kept commented in ec2_instances_disabled.tf
# alongside the disabled EC2 resources and dependent Route53 records.

# HCP Vault Information
output "__hcp_vault_cluster_url" {
  description = "URL of the HCP Vault Cluster"
  value       = data.hcp_vault_cluster.example.vault_public_endpoint_url
}

output "__export_vault_add" {
  description = "Export command for setting VAULT_ADDR environment variable"
  value       = "export VAULT_ADDR=${data.hcp_vault_cluster.example.vault_public_endpoint_url}"
}

output "vault_ca_chain_url" {
  description = "Vault PKI CA chain download URL (use with: curl -o vault-ca-chain.pem <url>)"
  value       = "${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/admin/pki_int/ca_chain"
}

output "__get_vault_ca" {
  description = "Command to retrieve and display the Vault PKI CA chain"
  value       = "wget  ${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/admin/pki_int/ca_chain"
}

output "__admin_token" {
  description = "HCP Vault Cluster Admin Token"
  value       = hcp_vault_cluster_admin_token.admin_token.token
  sensitive   = true
}

output "__export_vault_token" {
  description = "Export command for setting VAULT_TOKEN environment variable"
  value       = "export VAULT_TOKEN=${hcp_vault_cluster_admin_token.admin_token.token}"
  sensitive   = true
}

output "__export_namespace" {
  description = "Export command for setting VAULT_NAMESPACE environment variable"
  value       = "export VAULT_NAMESPACE=admin"

}