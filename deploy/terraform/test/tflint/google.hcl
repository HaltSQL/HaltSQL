# tflint configuration used by deploy/terraform/test/static-checks.sh.
config {
  call_module_type = "local"
  force            = false
}

plugin "terraform" {
  enabled = true
  preset  = "all"
  version = "0.15.0"
  source  = "github.com/terraform-linters/tflint-ruleset-terraform"
}

plugin "google" {
  enabled = true
  version = "0.40.0"
  source  = "github.com/terraform-linters/tflint-ruleset-google"
}
