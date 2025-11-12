# Windows Server Outputs
output "windows_rdp_connection" {
  description = "RDP connection string for Windows Server"
  value       = "mstsc /v:${aws_eip.windows.public_ip}"
}

# Ubuntu Server Outputs
output "ubuntu_ssh_connection" {
  description = "SSH connection command for Ubuntu Server"
  value       = "ssh -i aws_key.pem ubuntu@${aws_eip.ubuntu.public_ip}"
}


output "ubuntu_nginx_url" {
  description = "HTTPS URL for Ubuntu Nginx server"
  value       = "https://${aws_route53_record.ubuntu.fqdn}"
}

# HCP Vault Information
output "hcp_vault_cluster_url" {
  description = "URL of the HCP Vault Cluster"
  value       = data.hcp_vault_cluster.example.vault_public_endpoint_url
}

output "admin_token" {
  description = "HCP Vault Cluster Admin Token"
  value       = hcp_vault_cluster_admin_token.admin_token.token
  sensitive   = true
}


output "windows_admin_password" {
  description = "Decrypted Administrator password for the Windows instance (null if not yet available)"
  # Avoid failing when password_data is empty by using try(); returns null until AWS provides password data
  value     = rsadecrypt(aws_instance.windows.password_data, file(var.rsa_key))
  sensitive = true
}
