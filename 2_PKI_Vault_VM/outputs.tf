# Windows Server Outputs
output "windows_rdp_connection" {
  description = "RDP connection string for Windows Server"
  value       = "mstsc /v:${aws_eip.windows.public_ip}"
}

# Ubuntu Server Outputs
output "ubuntu_ssh_connection" {
  description = "SSH connection command for Ubuntu Server"
  value       = "ssh -i aws.pem ubuntu@${aws_eip.ubuntu.public_ip}"
}


output "ubuntu_nginx_url" {
  description = "HTTPS URL for Ubuntu Nginx server"
  value       = "https://${aws_route53_record.ubuntu.fqdn}"
}

# Ubuntu ACME Server Outputs
output "ubuntu_acme_ssh_connection" {
  description = "SSH connection command for Ubuntu ACME Server"
  value       = "ssh -i aws.pem ubuntu@${aws_eip.ubuntu_acme.public_ip}"
}

output "ubuntu_acme_url" {
  description = "HTTPS URL for Ubuntu ACME server"
  value       = "https://${aws_route53_record.ubuntu_acme.fqdn}"
}

output "ubuntu_acme_public_ip" {
  description = "Public IP of Ubuntu ACME instance"
  value       = aws_eip.ubuntu_acme.public_ip
}

# HCP Vault Information
output "hcp_vault_cluster_url" {
  description = "URL of the HCP Vault Cluster"
  value       = data.hcp_vault_cluster.example.vault_public_endpoint_url
}

output "vault_acme_directory_url" {
  description = "Vault PKI ACME directory URL for ACME clients"
  value       = "${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/pki_int/acme/directory"
}
# ACME EAB Credentials
output "acme_eab_key_id" {
  description = "ACME External Account Binding (EAB) Key ID for Certbot"
  value       = vault_generic_endpoint.acme_eab.write_data["id"]
  sensitive   = true
}

output "acme_eab_hmac_key" {
  description = "ACME External Account Binding (EAB) HMAC Key for Certbot"
  value       = vault_generic_endpoint.acme_eab.write_data["key"]
  sensitive   = true
}

output "certbot_command" {
  description = "Complete Certbot command with EAB credentials"
  value       = "sudo certbot --nginx --config-dir /etc/ssl/certbot --server ${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/pki_int/acme/directory --domain acme.${var.hosted_dns_zone} --eab-kid ${vault_generic_endpoint.acme_eab.write_data["id"]} --eab-hmac-key ${vault_generic_endpoint.acme_eab.write_data["key"]} --non-interactive --agree-tos --email admin@${var.hosted_dns_zone}"
  sensitive   = true
}

output "admin_token" {
  description = "HCP Vault Cluster Admin Token"
  value       = hcp_vault_cluster_admin_token.admin_token.token
  sensitive   = true
}


# Private Key Output (for recovering aws.pem)
output "tls_private_key_pem" {
  description = "Private key in PEM format (save to aws.pem)"
  value       = tls_private_key.rsa_4096_key.private_key_pem
  sensitive   = true
}

output "windows_admin_password" {
  description = "Decrypted Administrator password for the Windows instance (null if not yet available)"
  # Avoid failing when password_data is empty by using try(); returns null until AWS provides password data
  value     = rsadecrypt(aws_instance.windows.password_data, tls_private_key.rsa_4096_key.private_key_pem)
  sensitive = true
}
