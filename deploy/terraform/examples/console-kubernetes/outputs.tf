output "namespace" {
  description = "Namespace of the console release."
  value       = helm_release.console.namespace
}

output "release" {
  description = "Helm release name and chart version."
  value       = "${helm_release.console.name} (${helm_release.console.metadata.chart} ${helm_release.console.metadata.version})"
}

output "port_forward" {
  description = "Reach the console without an ingress."
  value       = "kubectl -n ${helm_release.console.namespace} port-forward svc/${helm_release.console.name} 8090:8090"
}
