locals {
  app_catalog = [
    "payments-api",
    "orders-api",
    "inventory-api",
    "billing-api",
    "analytics-api"
  ]

  namespace_names = [
    for i in range(var.namespace_count) :
    format("%s-%02d", var.namespace_prefix, i + 1)
  ]

  namespace_relative_paths = {
    for ns in local.namespace_names :
    ns => ns
  }

  secret_names = [
    for i in range(var.secrets_per_namespace) :
    format("secret-%02d", i + 1)
  ]

  user_names = [
    for i in range(var.userpass_users_per_namespace) :
    format("user%02d", i + 1)
  ]

  secret_items = {
    for item in flatten([
      for ns in local.namespace_names : [
        for idx, secret_name in local.secret_names : {
          key         = format("%s/%s", ns, secret_name)
          namespace   = ns
          secret_name = secret_name
          is_updated  = idx < var.updated_secrets_per_namespace
          owner       = format("owner-%s-%02d", ns, idx + 1)
          email       = format("%s.secret%02d@vault-demo.local", replace(ns, "_", "-"), idx + 1)
          app         = local.app_catalog[idx % length(local.app_catalog)]
        }
      ]
    ]) :
    item.key => item
  }

  user_items = {
    for item in flatten([
      for ns in local.namespace_names : [
        for username in local.user_names : {
          key       = format("%s/%s", ns, username)
          namespace = ns
          username  = username
        }
      ]
    ]) :
    item.key => item
  }
}
