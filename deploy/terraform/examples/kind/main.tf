# haltsql-server on a local kind cluster, through the haltsql-kubernetes
# module and the chart in this repository. Used by
# deploy/terraform/test/e2e-kind.sh.
#
#   kind create cluster --name haltsql-terraform
#   kind load docker-image haltsql-local:e2e --name haltsql-terraform
#   terraform init && terraform apply \
#     -var kubeconfig_path=$HOME/.kube/config \
#     -var token_sha256=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context
}

provider "helm" {
  kubernetes = {
    config_path    = var.kubeconfig_path
    config_context = var.kube_context
  }
}

module "haltsql" {
  source = "../../modules/haltsql-kubernetes"

  release_name = "haltsql"
  namespace    = var.namespace

  image = {
    repository = var.image_repository
    tag        = var.image_tag
    # The image is side-loaded with `kind load`, never pulled.
    pull_policy = "Never"
  }
  replicas = 2

  tokens = [{
    name   = "e2e-agent"
    sha256 = var.token_sha256
    policy = "tf-analytics"
  }]

  policies = {
    "analytics.yaml" = file("${path.module}/policies/analytics.yaml")
  }

  server = {
    log_level = "info"
  }

  # Exercises the chart's extraConfig deep merge: server.admin is merged into
  # the rendered server block next to listen and auth (e2e-kind.sh checks
  # GET /v1/admin/status).
  config = {
    server = {
      admin = { enabled = true, callers = ["token:e2e-agent"] }
    }
  }

  # kindnet enforces NetworkPolicy; port-forwarded traffic enters through the
  # pod's own network namespace.
  network_policy = {
    enabled = true
  }
  pod_disruption_budget = {
    enabled       = true
    min_available = "1"
  }
}
