include "root" {
  path = find_in_parent_folders()
}

terraform {
  source = "git::https://example.com/modules/compute.git//."
}

inputs = {
  instance_type = "t3.medium"
  environment   = "prod"
}
