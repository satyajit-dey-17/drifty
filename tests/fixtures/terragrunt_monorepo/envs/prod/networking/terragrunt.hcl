include "root" {
  path = find_in_parent_folders()
}

terraform {
  source = "git::https://example.com/modules/networking.git//."
}

inputs = {
  vpc_cidr    = "10.0.0.0/16"
  environment = "prod"
}
