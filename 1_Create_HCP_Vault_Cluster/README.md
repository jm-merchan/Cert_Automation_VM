# 1_Create_HCP_Vault_Cluster

This Terraform module provisions a HashiCorp Cloud Platform (HCP) Vault cluster and associated network resources in AWS.

## What it does

- Creates an HCP HashiCorp Virtual Network (HVN) in the specified AWS region
- Provisions an HCP Vault cluster with standard tier and public endpoint enabled
- Generates an admin token for the Vault cluster

## Resources Created

- `hcp_hvn.example`: HVN with CIDR block 172.24.16.0/20
- `hcp_vault_cluster.example`: Vault cluster with public endpoint
- `hcp_vault_cluster_admin_token.admin_token`: Admin token for Vault access

## Variables

- `aws_region`: AWS region for HVN and Vault cluster (default: eu-west-1)

## Outputs

- `admin_token`: Vault cluster admin token (sensitive)
- `hcp_vault_cluster_url`: Public endpoint URL of the Vault cluster

## Usage

```sh
terraform init
terraform apply -var-file="hcp_vault_cluster.tfvars"
```

Edit `hcp_vault_cluster.tfvars` to set your desired AWS region.

## Prerequisites

- HCP account with permissions to create Vault clusters
- AWS account (for HVN placement)
- Terraform >= 1.3

## Notes

- The Vault cluster is created with `prevent_destroy = false` for easy cleanup
- Public endpoint is enabled for external access
- Admin token is required for subsequent Vault configurations