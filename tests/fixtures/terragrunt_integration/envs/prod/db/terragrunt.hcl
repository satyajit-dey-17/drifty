include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../modules/null_resource"
}

inputs = {
  name = "prod-db"
}
