terraform {
  backend "local" {}
}

variable "name" {
  type    = string
  default = "default"
}

resource "null_resource" "this" {
  triggers = {
    name = var.name
  }
}

output "id" {
  value = null_resource.this.id
}
