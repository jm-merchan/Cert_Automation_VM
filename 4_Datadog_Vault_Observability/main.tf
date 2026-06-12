resource "datadog_dashboard_json" "vault_secret_activity" {
  dashboard = local.dashboard_json
}

# resource "datadog_monitor" "vault_secret_not_read" {
#   name = format("Vault secret sin lectura en %dh", local.evaluation_window_hours)
#   type = "log alert"
#
#   query = format(
#     "logs(\"%s\").index(\"*\").rollup(\"count\").by(\"@request.path\").last(\"%dh\") < 1",
#     local.read_query,
#     local.evaluation_window_hours
#   )
#
#   message = join("\n", [
#     "Secreto sin accesos de lectura en la ventana configurada.",
#     "Revisa si el secreto sigue en uso o si requiere limpieza/rotacion.",
#     "@slack-security-alerts"
#   ])
#
#   include_tags = true
#   tags         = concat(var.monitor_tags, ["monitor:vault-secret-not-read"])
# }
#
# resource "datadog_monitor" "vault_secret_not_updated_internal" {
#   for_each = toset(var.secret_inventory_paths)
#
#   name = format("[internal] Vault secret sin actualizacion en %dh - %s", local.evaluation_window_hours, each.value)
#   type = "log alert"
#
#   query = format(
#     "logs(\"@type:response (@request.operation:update OR @request.operation:patch) @request.path:%s\").index(\"*\").rollup(\"count\").last(\"%dh\") < 1",
#     each.value,
#     local.evaluation_window_hours
#   )
#
#   message = join("\n", [
#     "Internal monitor por secreto (fuente para monitor composite).",
#     format("Path: %s", each.value)
#   ])
#
#   include_tags = true
#   tags         = concat(var.monitor_tags, ["monitor:vault-secret-not-updated", "scope:internal"])
# }
#
# resource "datadog_monitor" "vault_secret_not_updated" {
#   name = format("Vault secret sin actualizacion en %dh", local.evaluation_window_hours)
#   type = "composite"
#
#   query = join(" || ", [
#     for path in sort(var.secret_inventory_paths) :
#     datadog_monitor.vault_secret_not_updated_internal[path].id
#   ])
#
#   message = join("\n", [
#     "Al menos un secreto no tuvo update/patch en la ventana configurada.",
#     "Revisa los monitores internos [internal] para identificar el path especifico.",
#     "@slack-security-alerts"
#   ])
#
#   include_tags = true
#   tags         = concat(var.monitor_tags, ["monitor:vault-secret-not-updated", "scope:composite"])
# }
