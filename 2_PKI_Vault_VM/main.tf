# Get the latest Windows Server 2022 AMI
data "aws_ami" "windows_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get the latest Ubuntu 22.04 LTS AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get the hosted zone
data "aws_route53_zone" "main" {
  name         = var.hosted_dns_zone
  private_zone = false
}

# Create VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Create Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

# Create Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Associate Route Table with Subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group for Windows Server
resource "aws_security_group" "windows" {
  name        = "${var.project_name}-windows-sg"
  description = "Security group for Windows Server 2022"
  vpc_id      = aws_vpc.main.id

  # RDP access
  ingress {
    description = "RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # WinRM HTTP
  ingress {
    description = "WinRM HTTP"
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # WinRM HTTPS
  ingress {
    description = "WinRM HTTPS"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTPS
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTP
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-windows-sg"
  }
}

# Security Group for Ubuntu Server
resource "aws_security_group" "ubuntu" {
  name        = "${var.project_name}-ubuntu-sg"
  description = "Security group for Ubuntu Server"
  vpc_id      = aws_vpc.main.id

  # SSH access
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTP
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-ubuntu-sg"
  }
}

resource "tls_private_key" "rsa_4096_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2_key" {
  key_name   = "ec2-key"
  public_key = tls_private_key.rsa_4096_key.public_key_openssh
}

# Create Key Pair for SSH (Ubuntu)
resource "aws_key_pair" "main" {
  key_name   = "${var.project_name}-key"
  public_key = tls_private_key.rsa_4096_key.public_key_openssh

  tags = {
    Name = "cert-automation-key"
  }
}

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

# Elastic IPs
resource "aws_eip" "windows" {
  instance = aws_instance.windows.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-windows-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_eip" "ubuntu" {
  instance = aws_instance.ubuntu.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-ubuntu-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_eip" "ubuntu_acme" {
  instance = aws_instance.ubuntu_acme.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-ubuntu-acme-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_eip" "windows_acme" {
  instance = aws_instance.windows_acme.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-windows-acme-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

# Route53 A Record for Windows Server
resource "aws_route53_record" "windows" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "windows.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.windows.public_ip]

  depends_on = [aws_eip.windows]
}

# Route53 A Record for Ubuntu Server
resource "aws_route53_record" "ubuntu" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "ubuntu.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.ubuntu.public_ip]

  depends_on = [aws_eip.ubuntu]
}

# Route53 A Record for Ubuntu ACME Server
resource "aws_route53_record" "ubuntu_acme" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "acme.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.ubuntu_acme.public_ip]

  depends_on = [aws_eip.ubuntu_acme]
}

# Route53 A Record for Windows ACME Server
resource "aws_route53_record" "windows_acme" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "windows-acme.${var.hosted_dns_zone}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.windows_acme.public_ip]

  depends_on = [aws_eip.windows_acme]
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

