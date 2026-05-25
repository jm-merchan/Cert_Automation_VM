# User-specific secrets access in KV v2
# Each user can manage secrets under their own path based on their alias name
# {{identity.entity.aliases.<mount_accessor>.name}} will resolve to the user's alias name

# Allow users to read secrets engine configuration
path "sys/mounts/secrets" {
  capabilities = ["read"]
}

# Allow UI to access mount information for all mounts
path "sys/internal/ui/mounts" {
  capabilities = ["read"]
}

# Allow UI to access mount information for secrets engine
path "sys/internal/ui/mounts/secrets" {
  capabilities = ["read"]
}

/*
# Allow users to list all user folders in the secrets engine (for UI navigation)
path "secrets/metadata/" {
  capabilities = ["list"]
}
*/

# Allow users to list their own secret path
path "secrets/metadata/{{identity.entity.aliases.${mount_accessor}.name}}" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow users to read metadata for their own secrets
path "secrets/metadata/{{identity.entity.aliases.${mount_accessor}.name}}/*" {
  capabilities = ["create", "read", "update", "delete", "list", "patch"]
}

# Allow users to read their own secrets
path "secrets/data/{{identity.entity.aliases.${mount_accessor}.name}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Protect example secret from deletion (can only read and update)
path "secrets/data/{{identity.entity.aliases.${mount_accessor}.name}}/example" {
  capabilities = ["read", "update"]
}

# Protect example secret metadata from deletion
path "secrets/metadata/{{identity.entity.aliases.${mount_accessor}.name}}/example" {
  capabilities = ["read", "update"]
}

# Allow users to delete their own secret metadata (for permanent deletion)
# But not the example secret
path "secrets/delete/{{identity.entity.aliases.${mount_accessor}.name}}/*" {
  capabilities = ["update"]
}

path "secrets/delete/{{identity.entity.aliases.${mount_accessor}.name}}/example" {
  capabilities = ["deny"]
}

# Allow users to undelete their own secrets
path "secrets/undelete/{{identity.entity.aliases.${mount_accessor}.name}}/*" {
  capabilities = ["update"]
}

# Allow users to destroy secret versions
# But not the example secret
path "secrets/destroy/{{identity.entity.aliases.${mount_accessor}.name}}/*" {
  capabilities = ["update"]
}

path "secrets/destroy/{{identity.entity.aliases.${mount_accessor}.name}}/example" {
  capabilities = ["deny"]
}

# Response wrapping for secure secret sharing
# Allow users to wrap responses
path "sys/wrapping/wrap" {
  capabilities = ["create", "update"]
}

# Allow users to unwrap responses
path "sys/wrapping/unwrap" {
  capabilities = ["create", "update"]
}

# Allow users to lookup wrapping token info
path "sys/wrapping/lookup" {
  capabilities = ["create", "update"]
}