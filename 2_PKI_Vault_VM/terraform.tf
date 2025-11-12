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
    vault = {
      source  = "hashicorp/vault"
      version = "5.4.0"
    }
    tls = {
      source = "hashicorp/tls"
      version = "4.1.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "hcp" {

}

resource "hcp_vault_cluster_admin_token" "admin_token" {
  cluster_id = "vault-cluster"
}

data "hcp_vault_cluster" "example" {
  cluster_id = "vault-cluster"
}

provider "vault" {
  address = data.hcp_vault_cluster.example.vault_public_endpoint_url
  token   = hcp_vault_cluster_admin_token.admin_token.token
}