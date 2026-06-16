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

resource "vault_generic_endpoint" "cors" {
  count = var.enable_cors ? 1 : 0

  path = "sys/config/cors"

  data_json = jsonencode({
    allowed_headers = [
      "X-Requested-With",
      "X-Vault-Namespace",
      "X-Vault-Request",
      "X-Vault-Token",
      "Content-Type",
    ]
    allowed_origins = var.cors_allowed_origins
    enabled         = true
  })
}

resource "vault_mount" "wrapping_demo" {
  path        = var.kv_mount_path
  type        = "kv"
  description = "KV v2 mount for the secret wrapping browser demo"

  options = {
    version = "2"
  }
}

resource "vault_kv_secret_v2" "demo" {
  mount = vault_mount.wrapping_demo.path
  name  = var.demo_secret_path

  data_json = jsonencode({
    recipient = var.demo_recipient
    message   = var.demo_secret_message
    purpose   = "Vault response wrapping demo"
  })
}

resource "vault_policy" "wrapping_sender" {
  name = var.sender_policy_name

  policy = templatefile("${path.module}/policy/wrapping-sender.hcl", {
    kv_mount_path = vault_mount.wrapping_demo.path
    secret_path   = vault_kv_secret_v2.demo.name
  })
}