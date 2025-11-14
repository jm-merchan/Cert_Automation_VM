################################################################################
# vault_aws_auth.tf
#
# Configures Vault AWS Auth backend, roles, and policies for EC2 authentication.
# - Enables AWS Auth method in Vault
# - Sets up IAM role binding and Vault policy for PKI issuance
################################################################################

resource "vault_auth_backend" "aws" {
  type = "aws"
}

resource "vault_aws_auth_backend_client" "client" {
  backend    = vault_auth_backend.aws.path
  access_key = aws_iam_access_key.vault_mount_user.id
  secret_key = aws_iam_access_key.vault_mount_user.secret
}

resource "vault_aws_auth_backend_config_identity" "identity_config" {
  backend   = vault_auth_backend.aws.path
  iam_alias = "role_id"
  iam_metadata = [
    "account_id",
    "auth_type",
    "canonical_arn",
    "client_arn",
  "client_user_id"]
}

resource "vault_aws_auth_backend_role" "role" {
  backend                  = vault_auth_backend.aws.path
  role                     = "vault-role-for-aws-ec2role"
  auth_type                = "iam"
  bound_iam_principal_arns = [aws_iam_role.vault_target_iam_role.arn]
  token_ttl                = 60
  token_max_ttl            = 120
  token_policies           = [vault_policy.pki_int_policy.name]
}



resource "vault_policy" "pki_int_policy" {
  name = "pki_int"

  policy = <<EOT
# Allow issuing certificates from intermediate CA
path "pki_int/issue/*" {
  capabilities = ["create", "update"]
}

# Allow signing certificates
path "pki_int/sign/*" {
  capabilities = ["create", "update"]
}

# Allow reading certificate roles
path "pki_int/roles/*" {
  capabilities = ["read", "list"]
}

# Allow revoking certificates
path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

# Allow listing certificates
path "pki_int/certs" {
  capabilities = ["list"]
}

# Allow reading PKI configuration
path "pki_int/*" {
  capabilities = ["read", "list"]
}
EOT
}