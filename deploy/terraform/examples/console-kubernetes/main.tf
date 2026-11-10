# haltsql-console on any Kubernetes cluster, through deploy/helm/haltsql-console,
# next to a haltsql release (for example one installed with
# modules/haltsql-kubernetes). Cloud specifics (IRSA / Workload Identity, ingress,
# storage, sign-in) come from a values overlay in deploy/cloud/<cloud>/console/.
#
#   terraform init && terraform apply \
#     -var kube_context=my-eks \
#     -var 'values_files=["../../../cloud/aws/console/eks.values.yaml"]'
#
# Guide: docs/console/deploy.md#terraform.

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

locals {
  chart_path = "${path.module}/../../../helm/haltsql-console"

  # The example's own values; values_files are applied after these and win
  # (except automation_tokens, applied last; see helm_release below).
  values = {
    image = merge(
      { repository = "ghcr.io/haltsql/haltsql-console" },
      var.image_digest == "" ? {} : { digest = var.image_digest },
    )
    rbac = {
      create      = true
      deployments = [var.verifier_release]
    }
    console = {
      config = {
        environment = { org = "HaltSQL", name = var.namespace }
        verifiers = [{
          name     = var.verifier_release
          url      = "http://${var.verifier_release}.${var.namespace}.svc:8080"
          kind     = "server"
          token    = "$${env:HALTSQL_ADMIN_TOKEN}"
          workload = "deployment/${var.verifier_release}"
        }]
        policies = {
          server_config = "/etc/haltsql/config/config.yaml"
        }
      }
    }
    existingSecret = var.admin_token_secret
    verifierConfig = {
      configMap         = "${var.verifier_release}-config"
      policiesConfigMap = "${var.verifier_release}-policies"
    }
    persistence = merge(
      { enabled = true, size = "20Gi", annotations = { "helm.sh/resource-policy" = "keep" } },
      var.storage_class == null ? {} : { storageClass = var.storage_class },
    )
  }
}

resource "helm_release" "console" {
  name      = var.release_name
  namespace = var.namespace
  chart     = local.chart_path

  # automation_tokens go last: Helm replaces lists, so a values file that sets
  # console.config.auth.tokens would otherwise drop them without an error.
  values = concat(
    [yamlencode(local.values)],
    [for f in var.values_files : file(f)],
    length(var.automation_tokens) == 0 ? [] : [yamlencode({
      console = { config = { auth = { tokens = var.automation_tokens } } }
    })],
  )

  # Recreate strategy on one replica: wait for the new pod before reporting success.
  wait          = true
  timeout       = 600
  atomic        = true
  max_history   = 10
  wait_for_jobs = false
}
