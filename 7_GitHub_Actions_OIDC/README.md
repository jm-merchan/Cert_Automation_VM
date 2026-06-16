# Vault and GitHub Actions OIDC

This module enables GitHub Actions to authenticate to Vault through GitHub's OIDC provider without storing a long-lived Vault token in GitHub.

It creates:

- A Vault JWT auth method at `jwt-github`.
- A Vault role bound to one GitHub repository and ref.
- A minimal Vault policy that can read one demo KV v2 secret.
- A KV v2 mount at `github-actions` with a demo secret.
- A sample repository under `github-actions-demo-repo` with a workflow that reads the secret.

## Deploy

Copy the example variables file and set your GitHub owner and repository name:

```sh
cp terraform.tfvars.example variables.tfvars
terraform init
terraform apply -var-file="variables.tfvars"
```

The module reads the Vault address and admin token from `../1_Create_HCP_Vault_Cluster/terraform.tfstate`.

## GitHub Repository Setup

Create a GitHub repository that matches `github_owner` and `github_repo`, then copy or push the contents of `github-actions-demo-repo` into it.

Configure these repository variables in GitHub Actions:

| Variable | Value |
|---|---|
| `VAULT_AUTH_PATH` | Terraform output `auth_mount_path` |
| `VAULT_ADDR` | Terraform output `vault_addr` |
| `VAULT_JWT_AUDIENCE` | Terraform output `bound_audience` |
| `VAULT_NAMESPACE` | `vault_namespace` value, default `admin` |
| `VAULT_ROLE` | Terraform output `github_actions_role_name` |

No Vault token should be stored in GitHub. The workflow requests an OIDC token from GitHub and exchanges it for a short-lived Vault token.

## Security Notes

- Keep `github_ref` as narrow as possible.
- Use `refs/heads/main` for one branch or a controlled glob such as `refs/tags/v*` for release tags.
- Add more claims only if the workflow needs broader matching, for example `environment` or `workflow_ref`.
- Replace the demo policy with application-specific paths before using this pattern for production workloads.