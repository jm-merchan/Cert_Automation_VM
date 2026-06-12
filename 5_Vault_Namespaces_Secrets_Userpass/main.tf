terraform {
  required_providers {
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

provider "vault" {
  address   = data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url
  token     = data.terraform_remote_state.clusters.outputs.admin_token
  namespace = var.base_namespace
}

resource "vault_namespace" "namespaces" {
  for_each = toset(local.namespace_names)

  path      = each.value
}

resource "vault_mount" "kv_v2" {
  for_each = toset(local.namespace_names)

  namespace   = local.namespace_relative_paths[each.value]
  path        = var.kv_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = format("KV v2 for namespace %s", each.value)

  depends_on = [vault_namespace.namespaces]
}

resource "vault_kv_secret_v2" "secrets" {
  for_each = local.secret_items

  namespace = local.namespace_relative_paths[each.value.namespace]
  mount     = vault_mount.kv_v2[each.value.namespace].path
  name      = each.value.secret_name

  data_json = jsonencode({
    namespace      = each.value.namespace
    secret_name    = each.value.secret_name
    value          = each.value.is_updated ? "updated-value" : "initial-value"
    updated        = each.value.is_updated
    version_marker = each.value.is_updated ? "v2" : "v1"
  })

  depends_on = [vault_mount.kv_v2]
}

resource "vault_generic_endpoint" "secret_custom_metadata" {
  for_each = local.secret_items

  namespace = local.namespace_relative_paths[each.value.namespace]
  path      = format("%s/metadata/%s", vault_mount.kv_v2[each.value.namespace].path, each.value.secret_name)

  data_json = jsonencode({
    custom_metadata = {
      owner = each.value.owner
      email = each.value.email
      app   = each.value.app
    }
  })

  disable_read = true

  depends_on = [vault_kv_secret_v2.secrets]
}

resource "vault_auth_backend" "userpass" {
  for_each = toset(local.namespace_names)

  namespace   = local.namespace_relative_paths[each.value]
  type        = "userpass"
  path        = var.userpass_mount_path
  description = format("Userpass auth backend for namespace %s", each.value)

  depends_on = [vault_namespace.namespaces]
}

resource "vault_generic_endpoint" "userpass_users" {
  for_each = local.user_items

  namespace = local.namespace_relative_paths[each.value.namespace]
  path      = format("auth/%s/users/%s", vault_auth_backend.userpass[each.value.namespace].path, each.value.username)

  data_json = jsonencode({
    password = format("%s-%s-%s", var.userpass_password_prefix, each.value.namespace, each.value.username)
    policies = "default"
  })

  depends_on = [vault_auth_backend.userpass]
}
