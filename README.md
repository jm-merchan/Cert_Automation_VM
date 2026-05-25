# Certificate Automation VM Infrastructure

This repository contains Terraform configurations to provision a complete certificate automation environment using AWS, HashiCorp Vault, ACME protocol, Auth0 OIDC, and KV static secrets.

## Repository Structure

- **[1_Create_HCP_Vault_Cluster](1_Create_HCP_Vault_Cluster/README.md)**: Provisions an HCP Vault cluster and network (HVN) in AWS. This module creates the foundational Vault infrastructure required for PKI operations.

- **[2_PKI_Vault_VM](2_PKI_Vault_VM/README.md)**: Deploys Windows and Ubuntu EC2 instances with Vault PKI configuration, ACME automation, and certificate management. Includes networking, security groups, DNS setup, and multiple host types for different certificate scenarios.

- **[3_Static_Secrets_users](3_Static_Secrets_users/SECRETS_CONFIG.md)**: Configures Vault OIDC authentication via Auth0, user identity groups and policies, and a KV v2 secrets engine where each user gets an isolated path scoped to their identity.

## Architecture Overview

The infrastructure consists of:
- HCP Vault cluster for centralized secret management and PKI
- AWS VPC with public subnet and internet access
- Multiple EC2 instances (Windows Server 2022 and Ubuntu 22.04) with different certificate management approaches:
  - **Vault Agent** (AWS IAM auto-auth): automatic certificate fetch and renewal via Vault PKI templates
  - **ACME HTTP-01**: Certbot / win-acme with HTTP challenge against Vault's ACME endpoint
  - **ACME DNS-01**: Certbot with Route53 plugin for DNS challenge against Vault's ACME endpoint
- Route53 DNS for domain validation and records
- Vault PKI with root and intermediate CAs and ACME support (EAB) for automated certificate issuance
- AWS Secrets Manager for certificate storage
- Auth0 OIDC integration with Vault for human user authentication
- KV v2 secrets engine with per-user isolated paths enforced via Vault identity templates

## Module Details

### 1 — Create HCP Vault Cluster

| Resource | Description |
|---|---|
| `hcp_hvn.example` | HVN with CIDR `172.24.16.0/20` |
| `hcp_vault_cluster.example` | Vault cluster (standard tier, public endpoint) |
| `hcp_vault_cluster_admin_token.admin_token` | Admin token for initial configuration |

**Outputs**: `admin_token` (sensitive), `hcp_vault_cluster_url`

### 2 — PKI Vault VM

Six EC2 instances covering all certificate automation patterns:

| Instance | OS | Method | Validation |
|---|---|---|---|
| `windows` | Windows Server 2022 | Vault Agent | AWS IAM |
| `ubuntu` | Ubuntu 22.04 | Vault Agent | AWS IAM |
| `ubuntu_acme` | Ubuntu 22.04 | Certbot | HTTP-01 |
| `windows_acme` | Windows Server 2022 | win-acme | HTTP-01 |
| `ubuntu_acme_dns` | Ubuntu 22.04 | Certbot + Route53 | DNS-01 |
| `windows_acme_dns` | Windows Server 2022 | Certbot + Route53 | DNS-01 |

**Verify certificate validity** with `openssl`:
```sh
openssl s_client -connect <hostname>:443 -servername <hostname> </dev/null 2>/dev/null \
  | openssl x509 -noout -dates
```
> Add `-CAfile vault-ca-chain.pem` (from `vault_ca_chain_url` output) if the Vault CA is not publicly trusted.

### 3 — Static Secrets & Users

| Component | Description |
|---|---|
| `vault_jwt_auth_backend.oidc` | OIDC auth method backed by Auth0 |
| `vault_identity_group` | `user` and `admin` identity groups |
| `vault_policy.user` | Per-user KV access via identity template |
| `vault_policy.super-root` | Admin policy |
| `vault_mount.secrets` (KV v2) | Secrets engine at `secrets/` |

Each authenticated user can only access `secrets/data/<their-alias>/*`. See [SECRETS_CONFIG.md](3_Static_Secrets_users/SECRETS_CONFIG.md) for details.

## Prerequisites

- AWS account with EC2, Route53, IAM, and Secrets Manager permissions
- HCP account for Vault cluster
- Auth0 account with a configured application (for module 3)
- Terraform >= 1.3
- RSA key pair for EC2 instance access (Windows password retrieval and Ubuntu SSH)

## Quick Start

1. Generate RSA key pair (see [2_PKI_Vault_VM/README.md](2_PKI_Vault_VM/README.md) for details):
   ```sh
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/aws_key
   ```
2. Configure AWS credentials
3. Deploy HCP Vault cluster:
   ```sh
   cd 1_Create_HCP_Vault_Cluster
   terraform init && terraform apply -var-file="variables.tfvars"
   ```
4. Deploy PKI and VMs:
   ```sh
   cd ../2_PKI_Vault_VM
   terraform init && terraform apply -var-file="variables.tfvars"
   ```
5. Deploy OIDC auth and static secrets:
   ```sh
   cd ../3_Static_Secrets_users
   terraform init && terraform apply -var-file="variables.tfvars"
   ```

See the individual module READMEs for variable configuration details.

## Cleanup

Destroy resources in reverse order:
1. Static secrets and users (`3_Static_Secrets_users`)
2. PKI and VMs (`2_PKI_Vault_VM`)
3. HCP Vault cluster (`1_Create_HCP_Vault_Cluster`)
