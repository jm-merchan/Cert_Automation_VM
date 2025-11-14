################################################################################
# terraform.tf
#
# Specifies required providers, versions, and configures AWS and HCP providers.
# - Sets up provider blocks for AWS and HCP
# - Provisions HCP HVN and Vault Cluster resources
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.20.0"
    }
    hcp = {
      source  = "hashicorp/hcp"
      version = "0.110.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "hcp" {

}


resource "hcp_hvn" "example" {
  hvn_id         = "hvn-cert-automation"
  cloud_provider = "aws"
  region         = var.aws_region
  cidr_block     = "172.24.16.0/20"
}

resource "hcp_vault_cluster" "example" {
  cluster_id = "vault-cluster"
  hvn_id     = hcp_hvn.example.hvn_id
  tier       = "standard_large"
  public_endpoint = true
  /*
  metrics_config {
    datadog_api_key = "test_datadog"
    datadog_region  = "us1"
  }
  audit_log_config {
    datadog_api_key = "test_datadog"
    datadog_region  = "us1"
  }
  */
  lifecycle {
    prevent_destroy = false
  }
}

resource "hcp_vault_cluster_admin_token" "admin_token" {
  cluster_id = "vault-cluster"
}