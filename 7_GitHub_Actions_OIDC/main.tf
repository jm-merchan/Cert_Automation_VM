data "terraform_remote_state" "clusters" {
  backend = "local"

  config = {
    path = "${path.module}/../1_Create_HCP_Vault_Cluster/terraform.tfstate"
  }
}

provider "vault" {
  address   = data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url
  token     = data.terraform_remote_state.clusters.outputs.admin_token
  namespace = var.vault_namespace
}

resource "vault_jwt_auth_backend" "github" {
  description        = "GitHub Actions OIDC authentication"
  path               = var.auth_mount_path
  type               = "jwt"
  oidc_discovery_url = "https://token.actions.githubusercontent.com"
  bound_issuer       = "https://token.actions.githubusercontent.com"
}

resource "vault_policy" "github_actions" {
  name = var.policy_name

  policy = templatefile("${path.module}/policy/github-actions.hcl", {
    kv_mount_path = var.kv_mount_path
    secret_path   = var.demo_secret_path
  })
}

resource "vault_jwt_auth_backend_role" "github_actions" {
  backend         = vault_jwt_auth_backend.github.path
  role_name       = var.github_actions_role_name
  role_type       = "jwt"
  user_claim      = "sub"
  bound_audiences = [var.bound_audience]
  token_policies  = [vault_policy.github_actions.name]
  token_ttl       = var.token_ttl
  token_max_ttl   = var.token_max_ttl

  bound_claims_type = "glob"
  bound_claims = {
    sub = "repo:${var.github_owner}/${var.github_repo}:ref:${var.github_ref}"
  }
}

resource "vault_mount" "github_actions" {
  path        = var.kv_mount_path
  type        = "kv"
  description = "KV v2 secrets consumed by GitHub Actions through OIDC"

  options = {
    version = "2"
  }
}

resource "vault_kv_secret_v2" "demo" {
  mount = vault_mount.github_actions.path
  name  = var.demo_secret_path

  data_json = jsonencode({
    message = var.demo_secret_message
  })
}