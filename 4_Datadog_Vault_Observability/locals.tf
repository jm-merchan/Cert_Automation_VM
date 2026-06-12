locals {
  # Datadog log alert queries only accept last("1h".."48h").
  # evaluation_window_hours variable controls the monitor window directly (1-48h).
  # evaluation_window_hours = var.evaluation_window_hours

  # Match both common mount spellings (secret/secrets) and optional leading slash
  # to avoid missing paths due to audit log formatting differences.
  secret_leaf_path_filter = "(@request.path:secret/data/* OR @request.path:/secret/data/* OR @request.path:secrets/data/* OR @request.path:/secrets/data/* OR @request.path:secret/data/*/* OR @request.path:/secret/data/*/* OR @request.path:secrets/data/*/* OR @request.path:/secrets/data/*/*)"
  secret_full_path_filter = "(@request.path:secret/data/* OR @request.path:/secret/data/* OR @request.path:secrets/data/* OR @request.path:/secrets/data/*)"

  read_query = join(" ", [
    "@type:response",
    "@request.operation:read",
    local.secret_leaf_path_filter
  ])

  create_query = join(" ", [
    "@type:response",
    "@request.operation:create",
    local.secret_full_path_filter
  ])

  user_reads_query = join(" ", [
    "@usr.id:*",
    local.read_query
  ])

  update_query = join(" ", [
    "@type:response",
    "(@request.operation:update OR @request.operation:patch)",
    local.secret_leaf_path_filter
  ])

  write_query = join(" ", [
    "@type:response",
    "(@request.operation:create OR @request.operation:update OR @request.operation:patch)",
    local.secret_leaf_path_filter
  ])

  # Datadog wildcard matching on path can behave as single-segment in some cases,
  # so we explicitly include multiple depths and mount variants.
  # secret_monitor_path_filter = join(" ", [
  #   "(",
  #   "@request.path:secret/data/*",
  #   "OR",
  #   "@request.path:/secret/data/*",
  #   "OR",
  #   "@request.path:secret/data/*/*",
  #   "OR",
  #   "@request.path:/secret/data/*/*",
  #   "OR",
  #   "@request.path:secret/data/*/*/*",
  #   "OR",
  #   "@request.path:/secret/data/*/*/*",
  #   "OR",
  #   "@request.path:secret/data/*/*/*/*",
  #   "OR",
  #   "@request.path:/secret/data/*/*/*/*",
  #   "OR",
  #   "@request.path:secret/data/*/*/*/*/*",
  #   "OR",
  #   "@request.path:/secret/data/*/*/*/*/*",
  #   "OR",
  #   "@request.path:secrets/data/*",
  #   "OR",
  #   "@request.path:/secrets/data/*",
  #   "OR",
  #   "@request.path:secrets/data/*/*",
  #   "OR",
  #   "@request.path:/secrets/data/*/*",
  #   "OR",
  #   "@request.path:secrets/data/*/*/*",
  #   "OR",
  #   "@request.path:/secrets/data/*/*/*",
  #   "OR",
  #   "@request.path:secrets/data/*/*/*/*",
  #   "OR",
  #   "@request.path:/secrets/data/*/*/*/*",
  #   "OR",
  #   "@request.path:secrets/data/*/*/*/*/*",
  #   "OR",
  #   "@request.path:/secrets/data/*/*/*/*/*",
  #   ")"
  # ])

  # monitor_all_secret_writes_query = join(" ", [
  #   "@type:response",
  #   "(@request.operation:create OR @request.operation:update OR @request.operation:patch)",
  #   local.secret_monitor_path_filter
  # ])

  auth_login_query = "@type:response @request.operation:update (@http.url_details.path:auth/*)"

  dashboard_json = jsonencode({
    title       = var.dashboard_title
    layout_type = "ordered"
    widgets = [
      {
        definition = {
          title       = "Total autenticaciones"
          title_size  = "16"
          title_align = "left"
          type        = "query_value"
          autoscale   = true
          precision   = 0
          requests = [
            {
              formulas = [
                {
                  formula = "q_total_auth"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_total_auth"
                  search = {
                    query = local.auth_login_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = []
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title          = "Numero de peticiones de autenticacion por identidad"
          requests = [
            {
              queries = [
                {
                  data_source = "logs"
                  name        = "q_auth_identities"
                  search = {
                    query = local.auth_login_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "count"
                  }
                  group_by = [
                    {
                      facet = "@usr.id"
                      limit = 200
                      sort = {
                        aggregation = "count"
                        order       = "desc"
                      }                    },
                    {
                      facet = "@request.namespace.path"
                      limit = 50
                      sort = {
                        aggregation = "count"
                        order       = "desc"
                      }                    }
                  ]
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          title      = "Total secretos creados"
          title_size = "16"
          title_align = "left"
          type       = "query_value"
          autoscale  = true
          precision  = 0
          requests = [
            {
              formulas = [
                {
                  formula = "q_total_created"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_total_created"
                  search = {
                    query = local.create_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = []
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          title      = "Total secretos actualizados"
          title_size = "16"
          title_align = "left"
          type       = "query_value"
          autoscale  = true
          precision  = 0
          requests = [
            {
              formulas = [
                {
                  formula = "q_total_updated"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_total_updated"
                  search = {
                    query = local.update_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = []
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          title      = "Total lecturas de secretos"
          title_size = "16"
          title_align = "left"
          type       = "query_value"
          autoscale  = true
          precision  = 0
          requests = [
            {
              formulas = [
                {
                  formula = "q_total_read"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_total_read"
                  search = {
                    query = local.read_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "count"
                  }
                  group_by = []
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          title      = "Total secretos leidos (unicos)"
          title_size = "16"
          title_align = "left"
          type       = "query_value"
          autoscale  = true
          precision  = 0
          requests = [
            {
              formulas = [
                {
                  formula = "q_total_read_unique"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_total_read_unique"
                  search = {
                    query = local.read_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.path"
                  }
                  group_by = []
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title          = "Lista: Secretos creados (namespace + path)"
          requests = [
            {
              queries = [
                {
                  data_source = "logs"
                  name        = "q_created_paths"
                  search = {
                    query = join(" ", [
                      local.create_query,
                      "@usr.id:*"
                    ])
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = [
                    {
                      facet = "@request.namespace.path"
                      limit = 50
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    },
                    {
                      facet = "@request.path"
                      limit = 50
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    }
                  ]
                }
              ]
              response_format = "scalar"
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title = "Tabla: Reads por secreto (Top 25 namespace + path)"
          requests = [
            {
              formulas = [
                {
                  formula           = "q_reads_table"
                  cell_display_mode = "bar"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_reads_table"
                  search = {
                    query = local.read_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = [
                    {
                      facet = "@request.namespace.path"
                      limit = 25
                    },
                    {
                      facet = "@request.path"
                      limit = 25
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    }
                  ]
                }
              ]
              response_format = "scalar"
              sort = {
                count = 25
                order_by = [
                  {
                    type  = "formula"
                    index = 0
                    order = "desc"
                  }
                ]
              }
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title = "Tabla: Updates por secreto (Top 25 namespace + path)"
          requests = [
            {
              formulas = [
                {
                  formula           = "q_updates_table"
                  cell_display_mode = "bar"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_updates_table"
                  search = {
                    query = local.update_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = [
                    {
                      facet = "@request.namespace.path"
                      limit = 25
                    },
                    {
                      facet = "@request.path"
                      limit = 25
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    }
                  ]
                }
              ]
              response_format = "scalar"
              sort = {
                count = 25
                order_by = [
                  {
                    type  = "formula"
                    index = 0
                    order = "desc"
                  }
                ]
              }
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title          = "Tabla: User IDs por numero de reads (con namespace)"
          requests = [
            {
              formulas = [
                {
                  formula           = "q_user_reads"
                  cell_display_mode = "bar"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_user_reads"
                  search = {
                    query = local.user_reads_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = [
                    {
                      facet = "@request.namespace.path"
                      limit = 25
                    },
                    {
                      facet = "@usr.id"
                      limit = 25
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    }
                  ]
                }
              ]
              response_format = "scalar"
              sort = {
                count = 25
                order_by = [
                  {
                    type  = "formula"
                    index = 0
                    order = "desc"
                  }
                ]
              }
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title          = "Tabla: User ID x Secret Path (reads, con namespace)"
          requests = [
            {
              formulas = [
                {
                  formula           = "q_user_path_reads"
                  cell_display_mode = "bar"
                }
              ]
              queries = [
                {
                  data_source = "logs"
                  name        = "q_user_path_reads"
                  search = {
                    query = local.user_reads_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = [
                    {
                      facet = "@request.namespace.path"
                      limit = 25
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    },
                    {
                      facet = "@usr.id"
                      limit = 25
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    },
                    {
                      facet = "@request.path"
                      limit = 15
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    }
                  ]
                }
              ]
              response_format = "scalar"
              sort = {
                count = 25
                order_by = [
                  {
                    type  = "formula"
                    index = 0
                    order = "desc"
                  }
                ]
              }
            }
          ]
        }
      },
      {
        definition = {
          type           = "query_table"
          has_search_bar = "auto"
          title          = "Tabla: Namespace + Secret Path"
          time = {
            live_span = "3mo"
          }
          requests = [
            {
              queries = [
                {
                  data_source = "logs"
                  name        = "q_secret_paths"
                  search = {
                    query = local.write_query
                  }
                  indexes = ["*"]
                  compute = {
                    aggregation = "cardinality"
                    metric      = "@request.id"
                  }
                  group_by = [
                    {
                      facet = "@request.namespace.path"
                      limit = 50
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    },
                    {
                      facet = "@request.path"
                      limit = 50
                      sort = {
                        aggregation = "cardinality"
                        metric      = "@request.id"
                        order       = "desc"
                      }
                    }
                  ]
                }
              ]
              response_format = "scalar"
              sort = {
                count = 50
                order_by = [
                  {
                    type  = "formula"
                    index = 0
                    order = "desc"
                  }
                ]
              }
            }
          ]
        }
      }
    ]
  })
}
