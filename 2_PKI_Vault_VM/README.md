# 2_PKI_Vault_VM

This Terraform module deploys Windows and Ubuntu EC2 instances, configures Vault PKI with ACME support, and automates certificate issuance using DNS-01 validation via Route53 and HTTP-01.

## What it does

- Creates VPC, subnet, internet gateway, and route table for networking
- Provisions Windows Server 2022 and Ubuntu 22.04 LTS EC2 instances
- Configures security groups for RDP, SSH, HTTP, and HTTPS access
- Sets up Route53 DNS records for all instances
- Configures Vault PKI with root and intermediate CAs
- Enables ACME on intermediate CA with External Account Binding (EAB)
- Generates ACME certificates using DNS-01 challenge with Route53
- Generate ACME certificates using HTTP-01
- Stores certificates and keys in AWS Secrets Manager
- Uses user data scripts for instance bootstrapping and certificate installation

## Resources Created

### Networking
- `aws_vpc.main`: VPC with DNS support
- `aws_internet_gateway.main`: IGW for internet access
- `aws_subnet.public`: Public subnet
- `aws_route_table.public`: Route table with IGW route
- `aws_security_group.windows/ubuntu`: Security groups for instances

### EC2 Instances
- `aws_instance.windows`: Windows Server 2022
- `aws_instance.ubuntu`: Ubuntu 22.04 LTS
- `aws_instance.ubuntu_acme`: Ubuntu with ACME client (HTTP-01)
- `aws_instance.windows_acme`: Windows with ACME client (HTTP-01)
- `aws_instance.ubuntu_acme_dns`: Ubuntu with ACME client (DNS-01)
- `aws_instance.windows_acme_dns`: Windows with ACME client (DNS-01)

### DNS and IPs
- `aws_eip.*`: Elastic IPs for all instances
- `aws_route53_record.*`: A records for instance hostnames

### Vault PKI
- `vault_mount.pki`: Root PKI mount
- `vault_mount.pki_int`: Intermediate PKI mount
- `vault_pki_secret_backend_root_cert.root_2023`: Root CA certificate
- `vault_pki_secret_backend_intermediate_cert_request.csr-request`: Intermediate CSR
- `vault_pki_secret_backend_config_acme.intermediate_acme`: ACME configuration
- `vault_generic_endpoint.acme_eab_*`: EAB credentials for ACME clients

### IAM and Auth
- `aws_iam_role.vault_target_iam_role`: EC2 role for Vault auth
- `aws_iam_policy.route53_acme`: Policy for Route53 DNS challenges
- `vault_auth_backend.aws`: Vault AWS auth backend
- `vault_aws_auth_backend_role.role`: Auth role for EC2 instances

### ACME and Certificates
- `acme_registration.registration`: ACME account registration
- `acme_certificate.certificate`: Certificate request with DNS-01 challenge
- `aws_secretsmanager_secret.*`: Secrets for certificate storage

## Variables

- `aws_region`: AWS region (default: eu-west-1)
- `project_name`: Project name for resource naming (default: cert-automation)
- `vpc_cidr`: VPC CIDR block (default: 10.0.0.0/16)
- `public_subnet_cidr`: Subnet CIDR (default: 10.0.1.0/24)
- `availability_zone`: AZ (default: us-east-1a)
- `allowed_cidr_blocks`: CIDR blocks for access (default: ["0.0.0.0/0"])
- `windows_instance_type`: Windows instance type (default: t3.medium)
- `ubuntu_instance_type`: Ubuntu instance type (default: t3.small)
- `windows_disk_size`: Windows disk size in GB (default: 50)
- `ubuntu_disk_size`: Ubuntu disk size in GB (default: 20)
- `windows_timezone`: Windows timezone (default: Eastern Standard Time)
- `ubuntu_timezone`: Ubuntu timezone (default: America/New_York)
- `hosted_dns_zone`: Route53 hosted zone name (default: example.com)

## Outputs

- Instance connection commands (RDP/SSH)
- Public IPs and URLs
- Vault ACME directory URL
- EAB credentials for ACME clients
- Certificate storage locations

## Usage

```sh
terraform init
terraform apply -var-file="variables.tfvars"
```

Edit `variables.tfvars` to set your domain, instance configurations, and security settings.

## Prerequisites

- HCP Vault cluster (from module 1)
- AWS account with EC2, Route53, IAM, Secrets Manager permissions
- Route53 hosted zone for DNS challenges
- Terraform >= 1.3
- RSA key pair for EC2 instance access

### Generate RSA Key Pair

Before deploying, create an RSA key pair that will be used for EC2 instance access:

```sh
ssh-keygen -t rsa -b 4096 -f ~/.ssh/aws_key
```

This creates:
- `~/.ssh/aws_key` - Private key (PEM format) for Windows password retrieval and Ubuntu SSH access
- `~/.ssh/aws_key.pub` - Public key that will be added to EC2 instances

The private key will be used to:
- Retrieve Windows administrator passwords via `aws ec2 get-password-data`
- SSH into Ubuntu instances

## Host Characteristics

This module creates several EC2 instances, each with specific configurations based on their user data templates:

### Windows Server (windows)
- **OS**: Windows Server 2022
- **Web Server**: IIS with HTTPS binding
- **Certificate Management**: Vault Agent with auto-auth (AWS IAM)
- **Certificate Source**: Vault PKI via templates (no ACME client)
- **Features**: 
  - Vault Agent configured for AWS IAM authentication
  - Certificate templates that request from Vault PKI
  - Automatic certificate renewal via Vault Agent
  - IIS configured with SSL certificate binding
  - Firewall rules for HTTP/HTTPS
  - WinRM enabled for remote management

### Ubuntu Server (ubuntu)
- **OS**: Ubuntu 22.04 LTS
- **Web Server**: Nginx with HTTPS
- **Certificate Management**: Vault Agent with auto-auth (AWS IAM)
- **Certificate Source**: Vault PKI via templates (no ACME client)
- **Features**:
  - Vault Agent configured for AWS IAM authentication
  - Certificate templates that request from Vault PKI
  - Automatic certificate renewal via Vault Agent
  - Nginx configured with SSL certificates
  - Systemd service for Vault Agent
  - Security updates enabled

### Ubuntu ACME HTTP-01 (ubuntu_acme)
- **OS**: Ubuntu 22.04 LTS
- **Web Server**: Nginx with HTTPS
- **ACME Client**: Certbot with Nginx plugin
- **Validation Method**: HTTP-01 challenge
- **Certificate Source**: Vault PKI ACME server
- **Features**:
  - Certbot installed with EAB credentials
  - HTTP-01 validation (requires public HTTP access)
  - Automatic certificate installation in Nginx
  - Vault CA certificate added to system trust store
  - Manual renewal script available

### Windows ACME HTTP-01 (windows_acme)
- **OS**: Windows Server 2022
- **Web Server**: IIS with HTTPS binding
- **ACME Client**: win-acme
- **Validation Method**: HTTP-01 challenge
- **Certificate Source**: Vault PKI ACME server
- **Features**:
  - win-acme installed with EAB credentials
  - HTTP-01 validation (requires public HTTP access)
  - Automatic PFX conversion for IIS
  - Certificate binding to IIS SSL bindings
  - Scheduled task for renewal
  - Vault CA imported to Windows certificate store

### Ubuntu ACME DNS-01 (ubuntu_acme_dns)
- **OS**: Ubuntu 22.04 LTS
- **Web Server**: Nginx with HTTPS
- **ACME Client**: Certbot with Route53 DNS plugin
- **Validation Method**: DNS-01 challenge via Route53
- **Certificate Source**: Vault PKI ACME server
- **Features**:
  - Certbot with dns-route53 plugin
  - DNS-01 validation (no public HTTP access required)
  - Route53 TXT record creation for domain validation
  - Automatic certificate installation in Nginx
  - Vault CA certificate added to system trust store
  - Manual renewal script available

### Windows ACME DNS-01 (windows_acme_dns)
- **OS**: Windows Server 2022
- **Web Server**: IIS with HTTPS binding
- **ACME Client**: Certbot (Python) with Route53 DNS plugin
- **Validation Method**: DNS-01 challenge via Route53
- **Certificate Source**: Vault PKI ACME server
- **Features**:
  - Python and Certbot installed with dns-route53 plugin
  - DNS-01 validation (no public HTTP access required)
  - Route53 TXT record creation for domain validation
  - PFX conversion using Python cryptography library
  - Certificate binding to IIS SSL bindings
  - Scheduled task for renewal
  - Vault CA imported to Windows certificate store