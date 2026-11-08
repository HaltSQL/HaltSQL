output "namespace" {
  description = "Namespace haltsql-server runs in."
  value       = helm_release.haltsql.namespace
}

output "release_name" {
  description = "Helm release name."
  value       = helm_release.haltsql.name
}

output "chart_version" {
  description = "Version of the installed chart."
  value       = helm_release.haltsql.metadata.version
}

output "service_name" {
  description = "Name of the haltsql-server Service."
  value       = local.fullname
}

output "service_account" {
  description = "ServiceAccount of the pods (bind cloud identities to it, e.g. aws_eks_pod_identity_association or a GKE/AKS federated credential)."
  value       = local.fullname
}

output "service_port" {
  description = "Service port."
  value       = var.service.port
}

output "endpoint" {
  description = "In-cluster URL of haltsql-server."
  value       = "${local.scheme}://${local.fullname}.${helm_release.haltsql.namespace}.svc.cluster.local:${var.service.port}"
}

output "endpoints" {
  description = "In-cluster URLs: base, verify, health and readiness."
  value = {
    base    = "${local.scheme}://${local.fullname}.${helm_release.haltsql.namespace}.svc.cluster.local:${var.service.port}"
    verify  = "${local.scheme}://${local.fullname}.${helm_release.haltsql.namespace}.svc.cluster.local:${var.service.port}/v1/verify"
    healthz = "${local.scheme}://${local.fullname}.${helm_release.haltsql.namespace}.svc.cluster.local:${var.service.port}/healthz"
    readyz  = "${local.scheme}://${local.fullname}.${helm_release.haltsql.namespace}.svc.cluster.local:${var.service.port}/readyz"
  }
}
