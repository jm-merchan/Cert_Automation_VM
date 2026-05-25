# Create KV v2 secrets engine for user secrets
resource "vault_mount" "secrets" {
  path        = "secrets"
  type        = "kv"
  options     = { version = "2" }
  description = "KV v2 secrets engine for user personal secrets"
}

# Create example secret for each user
resource "vault_kv_secret_v2" "user_example" {
  for_each = var.auth0_users

  mount = vault_mount.secrets.path
  name  = "${each.value.email}/example"
  
  data_json = jsonencode({
    example = "this is an example of a secret"
  })
}
