/*
EC2 instances are intentionally disabled for this module.

This file keeps the VM resources, their dependent Route53 records, and their
related outputs in one place while preventing Terraform from creating EC2
instances or evaluating outputs that depend on them.

# Windows Server 2022 Instance
resource "aws_instance" "windows" {
  ami                    = data.aws_ami.windows_2022.id
  instance_type          = var.windows_instance_type
  subnet_id              = aws_subnet.public.id
  key_name               = aws_key_pair.main.key_name
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name
  get_password_data      = true
  vpc_security_group_ids = [aws_security_group.windows.id]

  root_block_device {
    volume_size = var.windows_disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/windows_userdata.ps1.tpl", {
    project_name          = var.project_name
    instance_name         = "${var.project_name}-windows-2022"
    timezone              = var.windows_timezone
    hcp_vault_cluster_url = data.hcp_vault_cluster.example.vault_public_endpoint_url
    dns_hostname          = "windows"
    hosted_zone           = var.hosted_dns_zone
  })

  tags = {
    Name = "${var.project_name}-windows-2022"
    OS   = "Windows Server 2022"
  }
}

# Ubuntu Server Instance
resource "aws_instance" "ubuntu" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.ubuntu_instance_type
  subnet_id            = aws_subnet.public.id
  key_name             = aws_key_pair.main.key_name
  iam_instance_profile = aws_iam_instance_profile.instance_profile.name

  vpc_security_group_ids = [aws_security_group.ubuntu.id]

  root_block_device {
    volume_size = var.ubuntu_disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/ubuntu_userdata.sh.tpl", {
    project_name          = var.project_name
    instance_name         = "${var.project_name}-ubuntu"
    dns_hostname          = "ubuntu"
    timezone              = var.ubuntu_timezone
    hcp_vault_cluster_url = data.hcp_vault_cluster.example.vault_public_endpoint_url

    hosted_zone = var.hosted_dns_zone
  })

  tags = {
    Name = "${var.project_name}-ubuntu"
    OS   = "Ubuntu 22.04 LTS"
  }
}

# Ubuntu ACME Server Instance
resource "aws_instance" "ubuntu_acme" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.ubuntu_instance_type
  subnet_id            = aws_subnet.public.id
  key_name             = aws_key_pair.main.key_name
  iam_instance_profile = aws_iam_instance_profile.instance_profile.name

  vpc_security_group_ids = [aws_security_group.ubuntu.id]

  root_block_device {
    volume_size = var.ubuntu_disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/ubuntu_acme_userdata.sh.tpl", {
    project_name          = var.project_name
    instance_name         = "${var.project_name}-ubuntu-acme"
    dns_hostname          = "acme"
    timezone              = var.ubuntu_timezone
    hcp_vault_cluster_url = data.hcp_vault_cluster.example.vault_public_endpoint_url
    hosted_zone           = var.hosted_dns_zone
    eab_kid               = vault_generic_endpoint.acme_eab.write_data["id"]
    eab_hmac_key          = vault_generic_endpoint.acme_eab.write_data["key"]
  })

  tags = {
    Name    = "${var.project_name}-ubuntu-acme"
    OS      = "Ubuntu 22.04 LTS"
    Purpose = "ACME Client Testing"
  }
}

# Windows Server 2022 ACME Instance
resource "aws_instance" "windows_acme" {
  ami                    = data.aws_ami.windows_2022.id
  instance_type          = var.windows_instance_type
  subnet_id              = aws_subnet.public.id
  key_name               = aws_key_pair.main.key_name
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name
  get_password_data      = true
  vpc_security_group_ids = [aws_security_group.windows.id]

  root_block_device {
    volume_size = var.windows_disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/windows_acme_userdata.ps1.tpl", {
    project_name          = var.project_name
    instance_name         = "${var.project_name}-windows-acme-2022"
    timezone              = var.windows_timezone
    hcp_vault_cluster_url = data.hcp_vault_cluster.example.vault_public_endpoint_url
    dns_hostname          = "windows-acme"
    hosted_zone           = var.hosted_dns_zone
    eab_kid               = vault_generic_endpoint.acme_eab_windows.write_data["id"]
    eab_hmac_key          = vault_generic_endpoint.acme_eab_windows.write_data["key"]
  })

  tags = {
    Name    = "${var.project_name}-windows-acme-2022"
    OS      = "Windows Server 2022"
    Purpose = "ACME Client Testing"
  }
}

# Route53 A Record for Windows Server
resource "aws_route53_record" "windows" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "windows.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.windows.public_ip]
}

# Route53 A Record for Ubuntu Server
resource "aws_route53_record" "ubuntu" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "ubuntu.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.ubuntu.public_ip]
}

# Route53 A Record for Ubuntu ACME Server
resource "aws_route53_record" "ubuntu_acme" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "acme.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.ubuntu_acme.public_ip]
}

# Route53 A Record for Windows ACME Server
resource "aws_route53_record" "windows_acme" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "windows-acme.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.windows_acme.public_ip]
}

# Ubuntu ACME DNS Server Instance (DNS-01 validation)
resource "aws_instance" "ubuntu_acme_dns" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.ubuntu_instance_type
  subnet_id            = aws_subnet.public.id
  key_name             = aws_key_pair.main.key_name
  iam_instance_profile = aws_iam_instance_profile.instance_profile.name

  vpc_security_group_ids = [aws_security_group.ubuntu.id]

  root_block_device {
    volume_size = var.ubuntu_disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/ubuntu_acme_dns_userdata.sh.tpl", {
    project_name          = var.project_name
    instance_name         = "${var.project_name}-ubuntu-acme-dns"
    dns_hostname          = "acme-dns"
    timezone              = var.ubuntu_timezone
    hcp_vault_cluster_url = data.hcp_vault_cluster.example.vault_public_endpoint_url
    hosted_zone           = var.hosted_dns_zone
    eab_kid               = vault_generic_endpoint.acme_eab_ubuntu_dns.write_data["id"]
    eab_hmac_key          = vault_generic_endpoint.acme_eab_ubuntu_dns.write_data["key"]
  })

  tags = {
    Name    = "${var.project_name}-ubuntu-acme-dns"
    OS      = "Ubuntu 22.04 LTS"
    Purpose = "ACME Client Testing - DNS-01"
  }
}

# Windows Server 2022 ACME DNS Instance (DNS-01 validation)
resource "aws_instance" "windows_acme_dns" {
  ami                    = data.aws_ami.windows_2022.id
  instance_type          = var.windows_instance_type
  subnet_id              = aws_subnet.public.id
  key_name               = aws_key_pair.main.key_name
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name
  get_password_data      = true
  vpc_security_group_ids = [aws_security_group.windows.id]

  root_block_device {
    volume_size = var.windows_disk_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/windows_acme_dns_userdata.ps1.tpl", {
    project_name          = var.project_name
    instance_name         = "${var.project_name}-windows-acme-dns-2022"
    timezone              = var.windows_timezone
    hcp_vault_cluster_url = data.hcp_vault_cluster.example.vault_public_endpoint_url
    dns_hostname          = "windows-acme-dns"
    hosted_zone           = var.hosted_dns_zone
    eab_kid               = vault_generic_endpoint.acme_eab_windows_dns.write_data["id"]
    eab_hmac_key          = vault_generic_endpoint.acme_eab_windows_dns.write_data["key"]
  })

  tags = {
    Name    = "${var.project_name}-windows-acme-dns-2022"
    OS      = "Windows Server 2022"
    Purpose = "ACME Client Testing - DNS-01"
  }
}

# Route53 A Record for Ubuntu ACME DNS Server
resource "aws_route53_record" "ubuntu_acme_dns" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "acme-dns.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.ubuntu_acme_dns.public_ip]

  depends_on = [aws_instance.ubuntu_acme_dns]
}

# Route53 A Record for Windows ACME DNS Server
resource "aws_route53_record" "windows_acme_dns" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "windows-acme-dns.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.windows_acme_dns.public_ip]

  depends_on = [aws_instance.windows_acme_dns]
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
*/