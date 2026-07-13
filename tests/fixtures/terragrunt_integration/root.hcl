remote_state {
  backend = "local"
  config = {
    path = "${get_repo_root()}/.terragrunt-state/${path_relative_to_include()}/terraform.tfstate"
  }
}
