output "namespaces_created" {
  description = "Generated namespace names"
  value       = local.namespace_names
}

output "totals" {
  description = "Summary of generated objects"
  value = {
    namespaces                  = var.namespace_count
    secrets_per_namespace       = var.secrets_per_namespace
    updated_secrets_per_ns      = var.updated_secrets_per_namespace
    total_secrets               = var.namespace_count * var.secrets_per_namespace
    userpass_users_per_ns       = var.userpass_users_per_namespace
    total_userpass_users        = var.namespace_count * var.userpass_users_per_namespace
  }
}

output "example_secret_paths" {
  description = "Example Vault secret paths (namespace + kv path)"
  value = [
    for k, item in local.secret_items :
    format("%s/%s/%s/%s", var.base_namespace, local.namespace_relative_paths[item.namespace], var.kv_mount_path, item.secret_name)
  ]
}
