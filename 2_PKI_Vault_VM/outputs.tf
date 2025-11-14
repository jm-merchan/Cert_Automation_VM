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

## Windows Server (vault agent)
output "windows_rdp_vault_agent" {
  description = "Creates an .rdp file for the Windows Server and prints the admin password (raw)"
  value       = <<-RDP
cat > ~/rdp/windows.rdp <<EOF
full address:s:${aws_route53_record.windows.fqdn}:3389
username:s:Administrator
EOF
open -a "Microsoft Remote Desktop" ~/rdp/windows.rdp
terraform output -raw _1_windows_admin_password
RDP
}

output "_1_windows_admin_password" {
  description = "Decrypted Administrator password for the Windows instance (null if not yet available)"
  # Avoid failing when password_data is empty by using try(); returns null until AWS provides password data
  value     = rsadecrypt(aws_instance.windows.password_data, tls_private_key.rsa_4096_key.private_key_pem)
  sensitive = true
}

output "_1_connect_windows_rdp_vault_agent" {
  description = "Helper to eval the RDP creation and launch command for the Windows Server"
  value       = "eval $(terraform output -raw windows_rdp_vault_agent)"
}

## Ubuntu Server (vault agent)
output "ubuntu_ssh_connection_vault_agent" {
  description = "SSH connection command for Ubuntu Server"
  value       = "ssh -i aws.pem ubuntu@${aws_instance.ubuntu.public_ip}"
}

output "_2_connect_ubuntu_ssh_connection_vault_agent" {
  description = "Helper to eval the SSH connect command for the Ubuntu Server"
  value       = "eval $(terraform output -raw ubuntu_ssh_connection_vault_agent)"
}

output "_2_ubuntu_vault_agent_url" {
  description = "HTTPS URL for Ubuntu Nginx server"
  value       = "https://${aws_route53_record.ubuntu.fqdn}"
}

# Ubuntu ACME Server Outputs
output "ubuntu_acme_ssh_connection" {
  description = "SSH connection command for Ubuntu ACME Server"
  value       = "ssh -i aws.pem ubuntu@${aws_instance.ubuntu_acme.public_ip}"
}

output "_3_connect_ubuntu_acme_ssh_connection" {
  description = "Helper to eval the SSH connect command for the Ubuntu ACME Server"
  value       = "eval $(terraform output -raw ubuntu_acme_ssh_connection)"
}

output "_3_ubuntu_acme_url" {
  description = "HTTPS URL for Ubuntu ACME server"
  value       = "https://${aws_route53_record.ubuntu_acme.fqdn}"
}



output "_4_windows_acme_url" {
  description = "HTTPS URL for Windows ACME server"
  value       = "https://${aws_route53_record.windows_acme.fqdn}"
}


output "_4_windows_acme_admin_password" {
  description = "Decrypted Administrator password for Windows ACME instance"
  value       = rsadecrypt(aws_instance.windows_acme.password_data, tls_private_key.rsa_4096_key.private_key_pem)
  sensitive   = true
}

output "_4_windows_acme_rdp_connection" {
  description = "Creates an .rdp file for the Windows ACME server and prints the admin password (raw)"
  value       = <<-RDP
cat > ~/rdp/windows-acme.rdp <<EOF
full address:s:${aws_route53_record.windows_acme.fqdn}:3389
username:s:Administrator
EOF
open -a "Microsoft Remote Desktop" ~/rdp/windows-acme.rdp
terraform output -raw windows_acme_admin_password
RDP
}

output "_4_connect_windows_acme" {
  description = "Helper to eval the RDP creation and launch command for the Windows ACME Server"
  value       = "eval $(terraform output -raw _4_windows_acme_rdp_connection)"
}

# Ubuntu ACME DNS Server Outputs
output "_5_ubuntu_acme_dns_ssh_connection" {
  description = "SSH connection command for Ubuntu ACME DNS Server"
  value       = "ssh -i aws.pem ubuntu@${aws_instance.ubuntu_acme_dns.public_ip}"
}

output "_5_connect_ubuntu_acme_dns" {
  description = "Helper to eval the SSH connect command for the Ubuntu ACME DNS Server"
  value       = "eval $(terraform output -raw _5_ubuntu_acme_dns_ssh_connection)"
}

output "_5_ubuntu_acme_dns_url" {
  description = "HTTPS URL for Ubuntu ACME DNS server"
  value       = "https://${aws_route53_record.ubuntu_acme_dns.fqdn}"
}


# Windows ACME DNS Server Outputs
output "_6_windows_acme_dns_rdp_connection" {
  description = "Creates an .rdp file for the Windows ACME DNS server and prints the admin password (raw)"
  value       = <<-RDP
cat > ~/rdp/windows-acme-dns.rdp <<EOF
full address:s:${aws_route53_record.windows_acme_dns.fqdn}:3389
username:s:Administrator
EOF
open -a "Microsoft Remote Desktop" ~/rdp/windows-acme-dns.rdp
terraform output -raw windows_acme_dns_admin_password
RDP
}

output "_6_connect_windows_acme_dns" {
  description = "Helper to eval the RDP creation and launch command for the Windows ACME DNS Server"
  value       = "eval $(terraform output -raw _6_windows_acme_dns_rdp_connection)"
}

output "_6_windows_acme_dns_url" {
  description = "HTTPS URL for Windows ACME DNS server"
  value       = "https://${aws_route53_record.windows_acme_dns.fqdn}"
}

output "_6_windows_acme_dns_public_ip" {
  description = "Public IP of Windows ACME DNS instance"
  value       = aws_instance.windows_acme_dns.public_ip
}

output "_6_windows_acme_dns_admin_password" {
  description = "Decrypted Administrator password for Windows ACME DNS instance"
  value       = rsadecrypt(aws_instance.windows_acme_dns.password_data, tls_private_key.rsa_4096_key.private_key_pem)
  sensitive   = true
}

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