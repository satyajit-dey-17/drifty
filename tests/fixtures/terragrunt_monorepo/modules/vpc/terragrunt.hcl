# Shared module config — only generate block, NOT a runnable unit
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<INNER
provider "aws" {
  region = "us-east-1"
}
INNER
}
