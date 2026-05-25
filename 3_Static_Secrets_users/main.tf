terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = "~> 1.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

data "terraform_remote_state" "clusters" {
  backend = "local"
  config = {
    path = "${path.module}/../1_Create_HCP_Vault_Cluster/terraform.tfstate"
  }
}



provider "auth0" {
  # Uses AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET env vars
}

provider "vault" {
  address = data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url
  token   = data.terraform_remote_state.clusters.outputs.admin_token
  namespace = "admin"
}
