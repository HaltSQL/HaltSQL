# haltsql-server on any Kubernetes cluster (EKS, AKS, GKE, kind, self-managed)
# through the deploy/helm/haltsql chart.
#
# The module only renders chart values; the chart owns the manifests. Chart
# extension values (extraConfig, extraPolicies, extraEnv, networkPolicy.egress,
# proxy) are only sent when used, and the plan fails with a precondition error
# when a local chart lacks them, so a setting is never silently dropped. The
# chart in this repository has extraConfig, extraPolicies (bundle_source
# entries without cache_dir cache on its `cache` volume), extraEnv and
# networkPolicy.egress; proxy is not implemented yet.

locals {
  chart_local_path = coalesce(var.chart_path, "${path.module}/../../../helm/haltsql")
  use_repository   = var.chart_repository != null
  chart_ref        = local.use_repository ? "haltsql" : local.chart_local_path

  # Feature detection for a local chart: the top-level (or nested) key must
  # exist in its values.yaml. A chart from a repository is trusted to match
  # chart_version.
  chart_values_text = local.use_repository ? "" : file("${local.chart_local_path}/values.yaml")
  chart_supports = {
    extraConfig   = local.use_repository || can(regex("(?m)^extraConfig:", local.chart_values_text))
    extraPolicies = local.use_repository || can(regex("(?m)^extraPolicies:", local.chart_values_text))
    extraEnv      = local.use_repository || can(regex("(?m)^extraEnv:", local.chart_values_text))
    egress        = local.use_repository || can(regex("(?m)^networkPolicy:(\\n[ #].*)*\\n  egress:", local.chart_values_text))
    proxy         = local.use_repository || can(regex("(?m)^proxy:", local.chart_values_text))
    # Token binding (tokens[].context, server.requireBoundTokens) and
    # server.verifyThreads arrived together.
    tokenContext = local.use_repository || can(regex("(?m)^  requireBoundTokens:", local.chart_values_text))
  }

  # ---- Workload identity ---------------------------------------------------
  wi = var.workload_identity
  wi_sa_annotations = merge(
    local.wi.provider == "eks-irsa" ? { "eks.amazonaws.com/role-arn" = local.wi.aws_role_arn } : {},
    local.wi.provider == "aks" ? merge(
      { "azure.workload.identity/client-id" = local.wi.azure_client_id },
      local.wi.azure_tenant_id == null ? {} : { "azure.workload.identity/tenant-id" = local.wi.azure_tenant_id },
    ) : {},
    local.wi.provider == "gke" ? { "iam.gke.io/gcp-service-account" = local.wi.gcp_service_account } : {},
  )
  wi_pod_labels = local.wi.provider == "aks" ? { "azure.workload.identity/use" = "true" } : {}

  # ---- Optional, chart-extension values ------------------------------------
  extra_config = merge(var.config, var.config_yaml == "" ? {} : yamldecode(var.config_yaml))

  extra_policies = [
    for b in var.bundle_sources : { for k, v in {
      bundle_source = { for sk, sv in {
        oci        = b.oci
        plain_http = b.plain_http
        https      = b.https
        s3         = b.s3 == null ? null : { for k3, v3 in b.s3 : k3 => v3 if v3 != null }
      } : sk => sv if sv != null }
      public_keys     = b.public_keys
      name_prefix     = b.name_prefix
      poll_interval_s = b.poll_interval_s
      cache_dir       = b.cache_dir
      auth            = b.auth
    } : k => v if v != null }
  ]

  extra_env = [
    for e in var.secret_env : {
      name      = e.name
      valueFrom = { secretKeyRef = { name = e.secret_name, key = e.key } }
    }
  ]

  oidc = [for o in var.oidc_providers : { for k, v in o : k => v if v != null }]
  mtls = [for m in var.mtls_identities : { for k, v in m : k => v if v != null }]

  # context / request_context_fields are only sent when set, so a chart that
  # predates them still accepts unbound tokens.
  tokens = [for t in var.tokens : { for k, v in t : k => v if v != null }]

  tokens_bound = [
    for t in var.tokens : t.name if t.context != null || t.request_context_fields != null
  ]

  # Inline policies that isolate tenants, by policy name.
  tenancy_policies = toset(compact([
    for _, doc in var.policies : try(yamldecode(doc).tenancy != null ? yamldecode(doc).metadata.name : "", "")
  ]))

  unbound_tenant_tokens = [
    for t in var.tokens : t.name
    if t.context == null && t.request_context_fields == null && contains(local.tenancy_policies, t.policy)
  ]

  network_policy = merge(
    {
      enabled     = var.network_policy.enabled
      ingressFrom = var.network_policy.ingress_from
      metricsFrom = var.network_policy.metrics_from
    },
    length(var.network_policy.egress) > 0 ? { egress = var.network_policy.egress } : {},
  )

  # Features that make haltsql-server call out of the pod.
  needs_egress = (
    length(var.oidc_providers) > 0 ||
    length(var.bundle_sources) > 0 ||
    length([for s in var.server.audit_sinks : s if !contains(["stdout", "file"], try(s.type, ""))]) > 0 ||
    can(local.extra_config.secrets) || can(local.extra_config.opa) || can(local.extra_config.telemetry.otlp)
  )

  base_values = {
    fullnameOverride = var.fullname_override == null ? "" : var.fullname_override
    replicaCount     = var.replicas
    image = {
      repository = var.image.repository
      tag        = var.image.tag == null ? "" : var.image.tag
      digest     = var.image.digest == null ? "" : var.image.digest
      pullPolicy = var.image.pull_policy
    }
    imagePullSecrets = [for s in var.image_pull_secrets : { name = s }]
    serviceAccount = {
      create                       = true
      annotations                  = merge(var.service_account_annotations, local.wi_sa_annotations)
      automountServiceAccountToken = can(local.extra_config.secrets.vault.auth.kubernetes) || try(local.extra_config.secrets.vault.auth.method == "kubernetes", false)
    }
    podAnnotations = var.pod_annotations
    podLabels      = merge(var.pod_labels, local.wi_pod_labels)
    server = merge(local.server_extension_values, {
      port                 = var.server.port
      maxRequestBytes      = var.server.max_request_bytes
      allowUnauthenticated = var.server.allow_unauthenticated
      defaultPolicy        = var.server.default_policy
      reloadWatch          = var.server.reload_watch
      logLevel             = var.server.log_level
      logFormat            = var.server.log_format
      metrics              = var.server.metrics
      audit = {
        sinks     = var.server.audit_sinks
        logRawSql = var.server.log_raw_sql
      }
    })
    tokens              = local.tokens
    existingTokenSecret = var.existing_token_secret == null ? "" : var.existing_token_secret
    tls = {
      enabled    = var.tls.enabled
      secretName = var.tls.secret_name == null ? "" : var.tls.secret_name
      clientAuth = var.tls.client_auth
      minVersion = var.tls.min_version
      healthPort = var.tls.health_port
    }
    oidc                    = local.oidc
    mtlsIdentities          = local.mtls
    policies                = var.policies
    existingPolicyConfigMap = var.existing_policy_config_map == null ? "" : var.existing_policy_config_map
    existingPolicyFiles     = var.existing_policy_files
    service = {
      type        = var.service.type
      port        = var.service.port
      annotations = var.service.annotations
    }
    resources = {
      requests = { for k, v in var.resources.requests : k => v if v != null }
      limits   = { for k, v in var.resources.limits : k => v if v != null }
    }
    podDisruptionBudget = {
      enabled      = var.pod_disruption_budget.enabled
      minAvailable = can(tonumber(var.pod_disruption_budget.min_available)) ? tonumber(var.pod_disruption_budget.min_available) : var.pod_disruption_budget.min_available
    }
    autoscaling = {
      enabled                        = var.autoscaling.enabled
      minReplicas                    = var.autoscaling.min_replicas
      maxReplicas                    = var.autoscaling.max_replicas
      targetCPUUtilizationPercentage = var.autoscaling.target_cpu_utilization_percentage
    }
    networkPolicy = local.network_policy
    serviceMonitor = {
      enabled       = var.service_monitor.enabled
      interval      = var.service_monitor.interval
      scrapeTimeout = var.service_monitor.scrape_timeout
      labels        = var.service_monitor.labels
    }
    nodeSelector              = var.node_selector
    tolerations               = var.tolerations
    topologySpreadConstraints = var.topology_spread_constraints
  }

  # Merged into the chart's `server` value; only sent when set, so a chart
  # that predates these keys (and has a strict values schema) still installs.
  server_extension_values = merge(
    var.server.require_bound_tokens ? { requireBoundTokens = true } : {},
    var.server.verify_threads == null ? {} : { verifyThreads = var.server.verify_threads },
  )

  extension_values = merge(
    length(keys(local.extra_config)) > 0 ? { extraConfig = local.extra_config } : {},
    length(local.extra_policies) > 0 ? { extraPolicies = local.extra_policies } : {},
    length(local.extra_env) > 0 ? { extraEnv = local.extra_env } : {},
    var.proxy.enabled ? {
      proxy = {
        enabled  = true
        replicas = var.proxy.replicas
        port     = var.proxy.port
        config   = yamldecode(var.proxy.config_yaml)
      }
    } : {},
  )

  fullname = (
    var.fullname_override != null ? var.fullname_override :
    strcontains(var.release_name, "haltsql") ? var.release_name :
    substr("${var.release_name}-haltsql", 0, 63)
  )
  scheme = var.tls.enabled ? "https" : "http"
}

resource "kubernetes_namespace_v1" "this" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace
    labels = merge(var.namespace_labels, {
      "app.kubernetes.io/part-of"                  = "haltsql"
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/audit"           = "restricted"
    })
  }
}

resource "helm_release" "haltsql" {
  name             = var.release_name
  namespace        = var.create_namespace ? kubernetes_namespace_v1.this[0].metadata[0].name : var.namespace
  create_namespace = false
  chart            = local.chart_ref
  repository       = var.chart_repository
  version          = var.chart_version

  atomic          = var.atomic
  cleanup_on_fail = true
  wait            = true
  timeout         = var.helm_timeout_seconds
  max_history     = 10

  values = concat(
    [yamlencode(merge(local.base_values, local.extension_values))],
    var.extra_values,
  )

  lifecycle {
    precondition {
      condition     = length(keys(local.extra_config)) == 0 || local.chart_supports.extraConfig
      error_message = "config/config_yaml need chart value extraConfig, which the chart at ${local.chart_local_path} does not have. See docs/terraform.md (chart extensions)."
    }
    precondition {
      condition     = length(var.bundle_sources) == 0 || local.chart_supports.extraPolicies
      error_message = "bundle_sources need chart value extraPolicies, which the chart at ${local.chart_local_path} does not have. See docs/terraform.md (chart extensions)."
    }
    precondition {
      condition     = length(var.secret_env) == 0 || local.chart_supports.extraEnv
      error_message = "secret_env needs chart value extraEnv, which the chart at ${local.chart_local_path} does not have. See docs/terraform.md (chart extensions)."
    }
    precondition {
      condition     = length(var.network_policy.egress) == 0 || local.chart_supports.egress
      error_message = "network_policy.egress needs chart value networkPolicy.egress, which the chart at ${local.chart_local_path} does not have. See docs/terraform.md (chart extensions)."
    }
    precondition {
      condition     = (length(local.tokens_bound) == 0 && length(keys(local.server_extension_values)) == 0) || local.chart_supports.tokenContext
      error_message = "tokens[*].context, tokens[*].request_context_fields, server.require_bound_tokens and server.verify_threads need a chart with server.requireBoundTokens, which the chart at ${local.chart_local_path} does not have. See docs/terraform.md (chart extensions)."
    }
    precondition {
      condition     = !var.proxy.enabled || local.chart_supports.proxy
      error_message = "proxy.enabled needs chart value proxy, which the chart at ${local.chart_local_path} does not have. See docs/terraform.md (chart extensions)."
    }
    precondition {
      condition     = length(var.tokens) > 0 || length(var.oidc_providers) > 0 || length(var.mtls_identities) > 0 || var.server.allow_unauthenticated
      error_message = "no caller can authenticate: configure tokens, oidc_providers or mtls_identities (allow_unauthenticated is for local development only)."
    }
    precondition {
      condition     = length(var.policies) > 0 || var.existing_policy_config_map != null || length(var.bundle_sources) > 0
      error_message = "no policies: set policies, existing_policy_config_map or bundle_sources (haltsql-server is never ready without one)."
    }
  }
}

check "egress_for_outbound_features" {
  assert {
    condition     = !(var.network_policy.enabled && local.needs_egress && length(var.network_policy.egress) == 0)
    error_message = "The NetworkPolicy denies all egress, but OIDC, bundle_sources, a cloud audit sink or a secret provider is configured: haltsql-server will fail closed on those calls. Set network_policy.egress (or disable network_policy)."
  }
}

check "tokens_bound_to_a_tenant" {
  assert {
    condition     = length(local.unbound_tenant_tokens) == 0
    error_message = "These tokens are pinned to a policy with tenancy but have neither context nor request_context_fields, so their holders can name any tenant in the request body: ${join(", ", local.unbound_tenant_tokens)}. Set tokens[*].context (or use oidc_providers / mtls_identities); leave a token unbound only for a trusted backend that takes the tenant from its own session."
  }
}

check "unauthenticated_access" {
  assert {
    condition     = !var.server.allow_unauthenticated
    error_message = "server.allow_unauthenticated is set: haltsql-server accepts every caller without credentials. This is for local development only."
  }
}

check "eks_pod_identity_credentials" {
  assert {
    condition     = var.workload_identity.provider != "eks-pod-identity"
    error_message = "EKS Pod Identity hands out credentials through the container credentials endpoint, which haltsql-server's AWS credential chain does not read yet (it reads env, web identity and IMDS). Prefer eks-irsa. See docs/terraform.md."
  }
}
