# Certificate Automation VM Infrastructure

This repository contains Terraform configurations to provision a complete certificate automation environment using AWS, HashiCorp Vault, and ACME protocol.

## Repository Structure

- **[1_Create_HCP_Vault_Cluster](1_Create_HCP_Vault_Cluster/README.md)**: Provisions an HCP Vault cluster and network (HVN) in AWS. This module creates the foundational Vault infrastructure required for PKI operations.

- **[2_PKI_Vault_VM](2_PKI_Vault_VM/README.md)**: Deploys Windows and Ubuntu EC2 instances with Vault PKI configuration, ACME automation, and certificate management. Includes networking, security groups, DNS setup, and multiple host types for different certificate scenarios.

## Architecture Overview

The infrastructure consists of:
- HCP Vault cluster for centralized secret management and PKI
- AWS VPC with public subnet and internet access
- Multiple EC2 instances (Windows Server 2022 and Ubuntu 22.04) with different certificate management approaches
- Route53 DNS for domain validation and records
- Vault PKI with ACME support for automated certificate issuance
- AWS Secrets Manager for certificate storage

## Prerequisites

- AWS account with appropriate permissions
- HCP account for Vault cluster
- Terraform >= 1.3
- RSA key pair for EC2 instance access (used for both Windows password retrieval and Ubuntu SSH access)

## Quick Start

1. Generate RSA key pair (see 2_PKI_Vault_VM/README.md for details)
2. Configure AWS credentials
3. Deploy HCP Vault cluster first
4. Deploy PKI and VMs

See the individual module READMEs for detailed instructions.

## Cleanup

Destroy resources in reverse order:
1. PKI and VMs
2. HCP Vault cluster
