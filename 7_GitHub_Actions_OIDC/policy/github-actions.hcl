path "${kv_mount_path}/data/${secret_path}" {
  capabilities = ["read"]
}

path "${kv_mount_path}/metadata/${secret_path}" {
  capabilities = ["read", "list"]
}