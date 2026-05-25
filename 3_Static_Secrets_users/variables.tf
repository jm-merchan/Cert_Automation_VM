variable "auth0_password" {
  type = string
}

variable "auth0_username" {
  type    = string
  default = "admin"
}

variable "auth0_name" {
  type    = string
  default = "admin"
}

variable "auth0_email" {
  type    = string
  default = "admin@vaultproject.io"
}

variable "auth0_users" {
  description = "Map of Auth0 users to create"
  type = map(object({
    name  = string
    email = string
    role  = string
  }))
  default = {}
}
