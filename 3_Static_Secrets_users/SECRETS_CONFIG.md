# User Secrets Configuration

## Overview
This configuration creates a KV v2 secrets engine where each user gets their own isolated path based on their alias name (typically their email from Auth0).

## What's Configured

### KV v2 Secrets Engine
- **Path**: `secrets`
- **Type**: KV version 2
- **Access Pattern**: Each user gets their own path at `secrets/data/<user-alias>/`

### User Policy Updates
The user policy has been updated to allow each user to:
- **Create, Read, Update, Delete** secrets under their own path: `secrets/data/{{identity.entity.aliases.<mount_accessor>.name}}/*`
- **List** their own secrets
- **Read metadata** for their secrets
- **Undelete** soft-deleted secrets
- **Destroy** specific secret versions

### How It Works
When a user authenticates via OIDC (Auth0):
1. Vault creates an identity entity for the user
2. The entity has an alias that matches their Auth0 identifier (typically email)
3. The policy uses Vault's templating syntax `{{identity.entity.aliases.<mount_accessor>.name}}` to dynamically resolve to the user's alias
4. Each user can only access secrets under their own path

### Example Usage
If a user with email `john.doe@example.com` logs in:
- They can create secrets at: `secrets/data/john.doe@example.com/my-secret`
- They can read: `secrets/data/john.doe@example.com/*`
- They CANNOT access: `secrets/data/jane.smith@example.com/*` (another user's path)

## Deployment
Run terraform apply to create the secrets engine and update the user policy:

```bash
terraform init
terraform plan
terraform apply
```

## Testing
After deployment, users can:
1. Log in to Vault UI using OIDC
2. Navigate to the `secrets` engine
3. Create secrets under their own alias path
4. Verify they cannot access other users' paths
