resource "vault_mount" "pki" {
  path        = "pki"
  type        = "pki"
  description = "${var.hosted_dns_zone} PKI mount"

  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 315360000
}

resource "vault_pki_secret_backend_root_cert" "root_2023" {
  backend     = vault_mount.pki.path
  type        = "internal"
  common_name = var.hosted_dns_zone
  ttl         = 315360000
  issuer_name = "root-2023"
}

resource "vault_pki_secret_backend_issuer" "root_2023" {
  backend                        = vault_mount.pki.path
  issuer_ref                     = vault_pki_secret_backend_root_cert.root_2023.issuer_id
  issuer_name                    = vault_pki_secret_backend_root_cert.root_2023.issuer_name
  revocation_signature_algorithm = "SHA256WithRSA"
}

resource "vault_pki_secret_backend_role" "role" {
  backend          = vault_mount.pki.path
  name             = "2023-servers"
  ttl              = 86400
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = [var.hosted_dns_zone, "example.com", "test.com"]
  allow_subdomains = true
  allow_any_name   = true
  no_store         = false  # Required for ACME - certificates must be stored
}

# Configure cluster paths for root CA (required for ACME)
resource "vault_pki_secret_backend_config_cluster" "root_cluster" {
  backend    = vault_mount.pki.path
  path       = "${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/pki"
  aia_path   = "${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/pki"
}

resource "vault_pki_secret_backend_config_urls" "config-urls" {
  backend                 = vault_mount.pki.path
  issuing_certificates    = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/der"]
  crl_distribution_points = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/crl/der"]
  ocsp_servers            = ["{{cluster_path}}/ocsp"]
  enable_templating       = true
  
  depends_on = [vault_pki_secret_backend_config_cluster.root_cluster]
}

resource "vault_mount" "pki_int" {
  path        = "pki_int"
  type        = "pki"
  description = "${var.hosted_dns_zone} Intermediate PKI mount"

  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 157680000
}

resource "vault_pki_secret_backend_intermediate_cert_request" "csr-request" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = "${var.hosted_dns_zone} Intermediate Authority"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "intermediate" {
  backend     = vault_mount.pki.path
  common_name = "new_intermediate"
  csr         = vault_pki_secret_backend_intermediate_cert_request.csr-request.csr
  format      = "pem_bundle"
  ttl         = 15480000
  issuer_ref  = vault_pki_secret_backend_root_cert.root_2023.issuer_id
}

resource "vault_pki_secret_backend_intermediate_set_signed" "intermediate" {
  backend     = vault_mount.pki_int.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.intermediate.certificate
}

resource "vault_pki_secret_backend_issuer" "intermediate" {
  backend                        = vault_mount.pki_int.path
  issuer_ref                     = vault_pki_secret_backend_intermediate_set_signed.intermediate.imported_issuers[0]
  issuer_name                    = "intermediate-2023"
  revocation_signature_algorithm = "SHA256WithRSA"
}

resource "vault_pki_secret_backend_role" "intermediate_role" {
  backend          = vault_mount.pki_int.path
  issuer_ref       = vault_pki_secret_backend_issuer.intermediate.issuer_ref
  name             = "jose-merchan-sbx-hashidemos-io"
  ttl              = 86400
  max_ttl          = 2592000
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = [var.hosted_dns_zone, "example.com", "test.com"]
  allow_subdomains = true
  no_store         = false  # Required for ACME - certificates must be stored
}

resource "vault_pki_secret_backend_cert" "example-dot-com" {
  issuer_ref  = vault_pki_secret_backend_issuer.intermediate.issuer_ref
  backend     = vault_pki_secret_backend_role.intermediate_role.backend
  name        = vault_pki_secret_backend_role.intermediate_role.name
  common_name = "test.${var.hosted_dns_zone}"
  ttl         = 3600
  revoke      = true
}

# Configure cluster paths for intermediate CA (required for ACME)
resource "vault_pki_secret_backend_config_cluster" "intermediate_cluster" {
  backend    = vault_mount.pki_int.path
  path       = "${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/pki_int"
  aia_path   = "${data.hcp_vault_cluster.example.vault_public_endpoint_url}/v1/pki_int"
}

resource "vault_pki_secret_backend_config_urls" "config-urls_int" {
  backend                 = vault_mount.pki_int.path
  issuing_certificates    = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/der"]
  crl_distribution_points = ["{{cluster_aia_path}}/issuer/{{issuer_id}}/crl/der"]
  ocsp_servers            = ["{{cluster_path}}/ocsp"]
  enable_templating       = true
  
  depends_on = [vault_pki_secret_backend_config_cluster.intermediate_cluster]
}

# Enable OCSP responder for root CA
resource "vault_pki_secret_backend_config_issuers" "root_issuers" {
  backend                       = vault_mount.pki.path
  default                       = vault_pki_secret_backend_issuer.root_2023.issuer_id
  default_follows_latest_issuer = true
}

# Enable OCSP responder for intermediate CA
resource "vault_pki_secret_backend_config_issuers" "intermediate_issuers" {
  backend                       = vault_mount.pki_int.path
  default                       = vault_pki_secret_backend_issuer.intermediate.issuer_id
  default_follows_latest_issuer = true
}

# Configure ACME on intermediate CA
# Step 1: Tune the mount to enable ACME required headers
resource "vault_generic_endpoint" "pki_int_tune" {
  path                 = "sys/mounts/pki_int/tune"
  ignore_absent_fields = true
  disable_read         = true
  disable_delete       = true

  data_json = jsonencode({
    passthrough_request_headers = ["If-Modified-Since"]
    allowed_response_headers = [
      "Last-Modified",
      "Location",
      "Replay-Nonce",
      "Link"
    ]
  })

  depends_on = [vault_mount.pki_int]
}

# Step 2: Enable ACME functionality on intermediate CA
# Note: HCP Vault has VAULT_DISABLE_PUBLIC_ACME enabled, requiring EAB
resource "vault_pki_secret_backend_config_acme" "intermediate_acme" {
  backend                  = vault_mount.pki_int.path
  enabled                  = true
  allowed_issuers          = ["*"]
  allowed_roles            = ["*"]
  default_directory_policy = "sign-verbatim"
  eab_policy               = "always-required"  # Required for HCP Vault
  
  depends_on = [
    vault_generic_endpoint.pki_int_tune,
    vault_pki_secret_backend_config_cluster.intermediate_cluster
  ]
}