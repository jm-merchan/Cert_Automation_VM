# Vault namespaces + secrets + userpass (demo)

This Terraform stack creates:

- 5 namespaces (configurable)
- 10 KV v2 secrets in each namespace (configurable)
- 5 of those secrets marked as updated in each namespace (configurable)
- 2 userpass users in each namespace (configurable)
- KV v2 custom metadata on every secret: `owner`, `email`, `app`

## Notes

- The stack uses the remote state from `../1_Create_HCP_Vault_Cluster/terraform.tfstate` to get Vault address and admin token.
- Child namespaces are created under `base_namespace` (default: `admin`).
- Secret updates are represented by data values (`updated=true`, `version_marker=v2`) on the first N secrets per namespace.
- Secret metadata values are generated automatically with demo values per secret.

## Usage

```bash
terraform init
terraform plan -var-file=terraform.tfvars.example
terraform apply -var-file=terraform.tfvars.example
```
