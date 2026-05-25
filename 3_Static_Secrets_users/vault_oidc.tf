# User Policy for Auth0
resource "vault_policy" "user" {
  name   = "user"
  policy = templatefile("policy/user-policy.hcl", {
    mount_accessor = vault_jwt_auth_backend.oidc.accessor
  })
}

# Admin Policy for Auth0
resource "vault_policy" "super-root" {
  name   = "admin"
  policy = file("policy/super-root.hcl")
}


# Create Auth method
resource "vault_jwt_auth_backend" "oidc" {
  description        = "Integration with Auth0"
  path               = "oidc"
  type               = "oidc"
  oidc_discovery_url = "https://${data.auth0_tenant.tenant.domain}/"
  oidc_client_id     = data.auth0_client.vault.id
  oidc_client_secret = data.auth0_client.vault.client_secret
  bound_issuer       = "https://${data.auth0_tenant.tenant.domain}/"
  tune {
    listing_visibility = "unauth"
    default_lease_ttl  = "12h"
    max_lease_ttl      = "24h"
  }
  default_role = "default"
}

################User######################
# Create Role for user role in Auth0
resource "vault_jwt_auth_backend_role" "user" {
  backend        = vault_jwt_auth_backend.oidc.path
  role_name      = "user"
  token_policies = ["default"]

  user_claim   = "https://example.com/email"
  groups_claim = "https://example.com/roles"
  role_type    = "oidc"
  allowed_redirect_uris = [
    "${data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url}/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8250/oidc/callback"
  ]
}

# Create an Identity Group in Vault and map policy to user group
resource "vault_identity_group" "user" {
  name = "user"
  type = "external"
  # external_policies = true
  metadata = {
    responsability = "user"
  }
}

resource "vault_identity_group_policies" "user" {
  policies = [
    "default",
    "user",
  ]
  # exclusive = true
  group_id = vault_identity_group.user.id
}

resource "vault_identity_group_alias" "group-alias-user" {
  name           = "user"
  mount_accessor = vault_jwt_auth_backend.oidc.accessor
  canonical_id   = vault_identity_group.user.id
}

################Admin######################
# Create Role for audit role in Auth0
resource "vault_jwt_auth_backend_role" "admin" {
  backend        = vault_jwt_auth_backend.oidc.path
  role_name      = "admin"
  token_policies = ["default"]
  user_claim     = "https://example.com/email"
  groups_claim   = "https://example.com/roles"
  role_type      = "oidc"
  allowed_redirect_uris = [
    "${data.terraform_remote_state.clusters.outputs.hcp_vault_cluster_url}/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8250/oidc/callback"
  ]
}

# Create an Identity Group in Vault and map policy to admin group
resource "vault_identity_group" "admin" {
  name              = "admin"
  type              = "external"
  external_policies = true
  metadata = {
    responsability = "admin"
  }
}

resource "vault_identity_group_policies" "admin" {
  policies = [
    "admin"
  ]
  exclusive = true
  group_id  = vault_identity_group.admin.id
}

resource "vault_identity_group_alias" "group-alias-admin" {
  name           = "admin"
  mount_accessor = vault_jwt_auth_backend.oidc.accessor
  canonical_id   = vault_identity_group.admin.id
}