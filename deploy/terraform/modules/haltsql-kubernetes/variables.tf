# Inputs of the haltsql-kubernetes module. Every value ends up in the values
# of the deploy/helm/haltsql chart (see main.tf for the exact mapping).

# ---------------------------------------------------------------------------
# Release and chart
# ---------------------------------------------------------------------------

variable "release_name" {
  description = "Helm release name. The chart's resources are named <release>-haltsql, or <release> when it already contains \"haltsql\"."
  type        = string
  default     = "haltsql"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,51}[a-z0-9])?$", var.release_name))
    error_message = "release_name must be a DNS-1123 label of at most 53 characters (lower-case letters, digits and '-')."
  }
}

variable "fullname_override" {
  description = "Overrides the chart's resource name (fullnameOverride). Null keeps the chart default."
  type        = string
  default     = null

  validation {
    condition     = var.fullname_override == null || can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.fullname_override))
    error_message = "fullname_override must be a DNS-1123 label of at most 63 characters."
  }
}

variable "namespace" {
  description = "Namespace to install into."
  type        = string
  default     = "haltsql"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS-1123 label."
  }
}

variable "create_namespace" {
  description = "Create the namespace (with Pod Security Standard \"restricted\" labels). Set to false when the namespace already exists."
  type        = bool
  default     = true
}

variable "namespace_labels" {
  description = "Extra labels for the namespace when create_namespace is true."
  type        = map(string)
  default     = {}
}

variable "chart_path" {
  description = "Local path of the haltsql chart. Null uses deploy/helm/haltsql of this repository. Ignored when chart_repository is set."
  type        = string
  default     = null
}

variable "chart_repository" {
  description = "Helm repository URL (https:// or oci://) to install the chart from instead of a local path."
  type        = string
  default     = null

  validation {
    condition     = var.chart_repository == null || can(regex("^(https|oci)://[^\\s?#]+$", var.chart_repository))
    error_message = "chart_repository must be an https:// or oci:// URL without query or fragment."
  }
}

variable "chart_version" {
  description = "Chart version when installing from chart_repository. Required with chart_repository so upgrades are explicit."
  type        = string
  default     = null

  validation {
    condition     = var.chart_repository == null || var.chart_version != null
    error_message = "chart_version is required when chart_repository is set."
  }
}

variable "helm_timeout_seconds" {
  description = "How long Helm waits for the release to become ready."
  type        = number
  default     = 300

  validation {
    condition     = var.helm_timeout_seconds >= 30 && var.helm_timeout_seconds <= 3600
    error_message = "helm_timeout_seconds must be between 30 and 3600."
  }
}

variable "atomic" {
  description = "Roll back the release if an install or upgrade fails."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Image and scale
# ---------------------------------------------------------------------------

variable "image" {
  description = "Container image. Set digest to pin an exact (signed) image; it takes precedence over tag."
  type = object({
    repository  = optional(string, "ghcr.io/haltsql/haltsql")
    tag         = optional(string)
    digest      = optional(string)
    pull_policy = optional(string, "IfNotPresent")
  })
  default = {}

  validation {
    condition     = can(regex("^[a-z0-9]+([._:/-][a-z0-9]+)*$", var.image.repository))
    error_message = "image.repository must be a lower-case image reference without tag or digest."
  }
  validation {
    condition     = var.image.tag == null || can(regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", var.image.tag))
    error_message = "image.tag must be a valid OCI tag."
  }
  validation {
    condition     = var.image.digest == null || can(regex("^sha256:[0-9a-f]{64}$", var.image.digest))
    error_message = "image.digest must be sha256:<64 lower-case hex>."
  }
  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image.pull_policy)
    error_message = "image.pull_policy must be Always, IfNotPresent or Never."
  }
}

variable "image_pull_secrets" {
  description = "Names of existing kubernetes.io/dockerconfigjson Secrets used to pull the image."
  type        = list(string)
  default     = []
}

variable "replicas" {
  description = "Replica count (ignored when autoscaling.enabled)."
  type        = number
  default     = 2

  validation {
    condition     = var.replicas >= 1 && var.replicas <= 100 && floor(var.replicas) == var.replicas
    error_message = "replicas must be an integer between 1 and 100."
  }
}

variable "autoscaling" {
  description = "HorizontalPodAutoscaler on CPU."
  type = object({
    enabled                           = optional(bool, false)
    min_replicas                      = optional(number, 2)
    max_replicas                      = optional(number, 10)
    target_cpu_utilization_percentage = optional(number, 70)
  })
  default = {}

  validation {
    condition     = var.autoscaling.min_replicas >= 1 && var.autoscaling.max_replicas >= var.autoscaling.min_replicas
    error_message = "autoscaling needs 1 <= min_replicas <= max_replicas."
  }
  validation {
    condition     = var.autoscaling.target_cpu_utilization_percentage > 0 && var.autoscaling.target_cpu_utilization_percentage <= 100
    error_message = "autoscaling.target_cpu_utilization_percentage must be in 1..100."
  }
}

variable "resources" {
  description = "Container resources. A memory limit is required: haltsql-server bounds request sizes, so a limit is always safe."
  type = object({
    requests = optional(object({
      cpu    = optional(string, "100m")
      memory = optional(string, "64Mi")
    }), {})
    limits = optional(object({
      cpu    = optional(string)
      memory = optional(string, "256Mi")
    }), {})
  })
  default = {}

  validation {
    condition = alltrue([
      for q in [var.resources.requests.cpu, var.resources.limits.cpu] :
      q == null || can(regex("^([0-9]+m|[0-9]+(\\.[0-9]+)?)$", q))
    ])
    error_message = "CPU quantities must look like 100m, 1 or 0.5."
  }
  validation {
    condition = alltrue([
      for q in [var.resources.requests.memory, var.resources.limits.memory] :
      q != null && can(regex("^[0-9]+(Ki|Mi|Gi|K|M|G)?$", q))
    ])
    error_message = "Memory requests and limits are required and must look like 64Mi or 1Gi."
  }
}

variable "node_selector" {
  description = "Pod nodeSelector."
  type        = map(string)
  default     = {}
}

variable "tolerations" {
  description = "Pod tolerations (Kubernetes shape)."
  type        = any
  default     = []
}

variable "topology_spread_constraints" {
  description = "Pod topologySpreadConstraints (Kubernetes shape)."
  type        = any
  default     = []
}

variable "pod_annotations" {
  description = "Extra pod annotations."
  type        = map(string)
  default     = {}
}

variable "pod_labels" {
  description = "Extra pod labels."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# haltsql-server settings
# ---------------------------------------------------------------------------

variable "server" {
  description = "haltsql-server settings rendered by the chart into the Config document."
  type = object({
    port                  = optional(number, 8080)
    max_request_bytes     = optional(number, 1048576)
    allow_unauthenticated = optional(bool, false)
    default_policy        = optional(string, "")
    reload_watch          = optional(bool, true)
    log_level             = optional(string, "info")
    log_format            = optional(string, "json")
    metrics               = optional(bool, true)
    log_raw_sql           = optional(bool, false)
    # Audit sinks, in the shape of the Config document's audit.sinks.
    audit_sinks = optional(any, [{ type = "stdout" }])
    # Fail the plan's Helm render when a token has neither context nor
    # request_context_fields (chart value server.requireBoundTokens).
    require_bound_tokens = optional(bool, false)
    # HALTSQL_VERIFY_THREADS (1-256); null lets the server use the CPU count.
    verify_threads = optional(number)
  })
  default = {}

  validation {
    condition     = var.server.port >= 1024 && var.server.port <= 65535 && floor(var.server.port) == var.server.port
    error_message = "server.port must be an unprivileged port (1024-65535): the container runs as uid 65532."
  }
  validation {
    condition     = var.server.max_request_bytes >= 1024 && var.server.max_request_bytes <= 67108864
    error_message = "server.max_request_bytes must be between 1024 and 67108864."
  }
  validation {
    condition     = var.server.verify_threads == null ? true : (var.server.verify_threads >= 1 && var.server.verify_threads <= 256 && floor(var.server.verify_threads) == var.server.verify_threads)
    error_message = "server.verify_threads must be an integer between 1 and 256."
  }
  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.server.log_level)
    error_message = "server.log_level must be debug, info, warn or error."
  }
  validation {
    condition     = contains(["json", "text"], var.server.log_format)
    error_message = "server.log_format must be json or text."
  }
  validation {
    condition = can(length(var.server.audit_sinks)) && length(var.server.audit_sinks) > 0 && alltrue([
      for s in var.server.audit_sinks : contains(["stdout", "file", "s3", "gcs", "elasticsearch", "kafka"], try(s.type, ""))
    ])
    error_message = "server.audit_sinks must be a non-empty list of sinks whose type is stdout, file, s3, gcs, elasticsearch or kafka."
  }
}

variable "tokens" {
  description = "Static bearer tokens. Only the SHA-256 of each token is given (never the token); each token is pinned to one policy. context fixes the token's context (e.g. { tenant_id = \"acme\" }) and request_context_fields lists the fields the request body may still add; a token with neither is unbound (its holder names the tenant in the request body)."
  type = list(object({
    name                   = string
    sha256                 = string
    policy                 = string
    context                = optional(any)
    request_context_fields = optional(list(string))
  }))
  default = []

  validation {
    condition = alltrue([
      for t in var.tokens : t.context == null ? true : try(alltrue([for k in keys(t.context) : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k))]), false)
    ])
    error_message = "tokens[*].context must be a map (give every token's context the same value types) whose keys are context field names (letters, digits and '_', not starting with a digit)."
  }
  validation {
    condition = alltrue([
      for t in var.tokens : alltrue([for f in(t.request_context_fields == null ? [] : t.request_context_fields) : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", f))])
    ])
    error_message = "tokens[*].request_context_fields must be context field names (letters, digits and '_', not starting with a digit)."
  }

  validation {
    condition     = alltrue([for t in var.tokens : can(regex("^[0-9a-f]{64}$", t.sha256))])
    error_message = "tokens[*].sha256 must be the 64 lower-case hex SHA-256 of the token, never the token itself."
  }
  validation {
    condition     = length(distinct([for t in var.tokens : t.name])) == length(var.tokens) && length(distinct([for t in var.tokens : t.sha256])) == length(var.tokens)
    error_message = "tokens must have unique names and unique hashes."
  }
}

variable "existing_token_secret" {
  description = "Existing Secret holding HALTSQL_TOKEN_<i>_SHA256 keys (one per entry of tokens, 0-based) instead of the chart-rendered Secret."
  type        = string
  default     = null
}

variable "policies" {
  description = "Policies keyed by file name (e.g. analytics.yaml); each value is a full Policy document as a YAML string."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for f, _ in var.policies : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\\.(yaml|yml|json)$", f))])
    error_message = "policies keys must be file names ending in .yaml, .yml or .json."
  }
  validation {
    condition     = alltrue([for _, doc in var.policies : can(yamldecode(doc)) && try(yamldecode(doc).kind, "") == "Policy"])
    error_message = "every policies value must be a YAML or JSON document with kind: Policy."
  }
}

variable "existing_policy_config_map" {
  description = "Existing ConfigMap holding policy files, instead of policies."
  type        = string
  default     = null
}

variable "existing_policy_files" {
  description = "Keys of existing_policy_config_map to load."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.existing_policy_files) == 0 || var.existing_policy_config_map != null
    error_message = "existing_policy_files needs existing_policy_config_map."
  }
}

variable "bundle_sources" {
  description = <<-EOT
    Signed policy bundles pulled from an OCI registry, S3 or HTTPS (Config
    policies[*].bundle_source). Exactly one of oci, s3 or https per entry.
    public_keys is mandatory. Needs chart support for extraPolicies (the
    module refuses to plan otherwise; see docs/terraform.md).
  EOT
  type = list(object({
    oci        = optional(string)
    plain_http = optional(bool)
    s3 = optional(object({
      bucket      = string
      key         = string
      region      = string
      endpoint    = optional(string)
      credentials = optional(any)
    }))
    https           = optional(string)
    public_keys     = list(string)
    name_prefix     = optional(string)
    poll_interval_s = optional(number)
    cache_dir       = optional(string)
    auth            = optional(map(string))
  }))
  default = []

  validation {
    condition     = alltrue([for b in var.bundle_sources : length([for f in [b.oci, b.s3, b.https] : f if f != null]) == 1])
    error_message = "each bundle_sources entry needs exactly one of oci, s3 or https."
  }
  validation {
    condition     = alltrue([for b in var.bundle_sources : length(b.public_keys) > 0])
    error_message = "bundle_sources[*].public_keys must not be empty: signature verification is mandatory."
  }
  validation {
    condition     = alltrue([for b in var.bundle_sources : b.oci == null || can(regex("^[^/\\s]*[.:][^/\\s]*/[a-z0-9._/-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha(256:[0-9a-f]{64}|512:[0-9a-f]{128}))?$|^localhost(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha(256:[0-9a-f]{64}|512:[0-9a-f]{128}))?$", b.oci))])
    error_message = "bundle_sources[*].oci must be registry[:port]/repository[:tag][@sha256:<hex>] with an explicit registry host."
  }
  validation {
    condition     = alltrue([for b in var.bundle_sources : b.https == null || can(regex("^https://[^\\s?#@]+$", b.https))])
    error_message = "bundle_sources[*].https must be an https URL without credentials, query or fragment."
  }
  validation {
    condition     = alltrue([for b in var.bundle_sources : b.plain_http != true || (b.oci != null && can(regex("^(localhost|127\\.[0-9.]+|\\[::1\\])(:[0-9]+)?/", b.oci)))])
    error_message = "bundle_sources[*].plain_http is only allowed with oci and a loopback registry."
  }
  validation {
    condition     = alltrue([for b in var.bundle_sources : b.poll_interval_s == null || (b.poll_interval_s >= 10 && b.poll_interval_s <= 86400)])
    error_message = "bundle_sources[*].poll_interval_s must be between 10 and 86400."
  }
  validation {
    condition     = alltrue([for b in var.bundle_sources : b.auth == null || b.s3 == null])
    error_message = "bundle_sources[*].auth is not allowed with s3: use s3.credentials."
  }
  validation {
    condition = alltrue([for b in var.bundle_sources : b.auth == null || (
      try(keys(b.auth) == tolist(["token"]), false) || try(toset(keys(b.auth)) == toset(["username", "password"]), false)
    )])
    error_message = "bundle_sources[*].auth must be {token} or {username, password}. Use $${env:...} placeholders, never literal secrets."
  }
  validation {
    # values end up in the ConfigMap and the Helm values: only placeholders, which
    # haltsql-server resolves at runtime, never the secret itself
    condition = alltrue([for b in var.bundle_sources : b.auth == null || alltrue([
      for k, v in coalesce(b.auth, {}) : can(regex("^\\$\\{(env|file|vault|aws-sm|gcp-sm):[^}]+\\}$", v))
    ])])
    error_message = "bundle_sources[*].auth values must each be one placeholder ($${env:...}, $${file:...}, $${vault:...}, $${aws-sm:...} or $${gcp-sm:...}); literal credentials would be stored in the ConfigMap and the Helm values."
  }
}

variable "config" {
  description = "Extra Config document keys (as an object) deep-merged by the chart into the rendered Config (chart value extraConfig), e.g. telemetry, secrets or opa. Needs chart support for extraConfig."
  type        = any
  default     = {}
}

variable "config_yaml" {
  description = "Same as config, as a YAML string. Merged after config (config_yaml wins)."
  type        = string
  default     = ""

  validation {
    condition     = var.config_yaml == "" || can(keys(yamldecode(var.config_yaml)))
    error_message = "config_yaml must be a YAML mapping."
  }
  validation {
    condition     = var.config_yaml == "" || length(setintersection(toset(try(keys(yamldecode(var.config_yaml)), [])), toset(["apiVersion", "kind", "policies"]))) == 0
    error_message = "config_yaml must not set apiVersion, kind or policies (use policies and bundle_sources)."
  }
}

variable "secret_env" {
  description = "Environment variables taken from existing Kubernetes Secrets, for $${env:NAME} placeholders in the config (chart value extraEnv). Needs chart support for extraEnv."
  type = list(object({
    name        = string
    secret_name = string
    key         = string
  }))
  default = []

  validation {
    condition     = alltrue([for e in var.secret_env : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", e.name)) && !startswith(e.name, "HALTSQL_TOKEN_")])
    error_message = "secret_env[*].name must be an environment variable name and must not use the reserved HALTSQL_TOKEN_ prefix."
  }
}

variable "extra_values" {
  description = "Extra Helm values as YAML strings, applied after the module's values (escape hatch for chart options the module does not model)."
  type        = list(string)
  default     = []
}

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

variable "oidc_providers" {
  description = "OpenID Connect providers (Config server.auth.oidc). Exactly one of policy, policy_claim (with allowed_policies) or policy_from_groups per provider."
  type = list(object({
    name                   = string
    issuer                 = string
    audiences              = list(string)
    jwks_uri               = optional(string)
    algorithms             = optional(list(string))
    leeway_seconds         = optional(number)
    jwks_cache_seconds     = optional(number)
    policy                 = optional(string)
    policy_claim           = optional(string)
    allowed_policies       = optional(list(string))
    policy_from_groups     = optional(any)
    context_claims         = optional(map(string))
    required_claims        = optional(any)
    request_context_fields = optional(list(string))
  }))
  default = []

  validation {
    condition     = alltrue([for o in var.oidc_providers : can(regex("^https://[^\\s?#@]+$", o.issuer))])
    error_message = "oidc_providers[*].issuer must be an https URL without credentials, query or fragment."
  }
  validation {
    condition     = alltrue([for o in var.oidc_providers : length(o.audiences) > 0])
    error_message = "oidc_providers[*].audiences must not be empty."
  }
  validation {
    condition     = alltrue([for o in var.oidc_providers : length([for f in [o.policy, o.policy_claim, o.policy_from_groups] : f if f != null]) == 1])
    error_message = "each OIDC provider needs exactly one of policy, policy_claim or policy_from_groups."
  }
  validation {
    condition     = alltrue([for o in var.oidc_providers : o.policy_claim == null || length(coalesce(o.allowed_policies, [])) > 0])
    error_message = "policy_claim needs a non-empty allowed_policies."
  }
  validation {
    condition     = alltrue([for o in var.oidc_providers : alltrue([for a in coalesce(o.algorithms, ["RS256"]) : contains(["RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA"], a)])])
    error_message = "oidc_providers[*].algorithms must be a subset of RS256 RS384 RS512 PS256 ES256 ES384 EdDSA."
  }
  validation {
    condition     = length(distinct([for o in var.oidc_providers : o.name])) == length(var.oidc_providers)
    error_message = "oidc_providers names must be unique."
  }
}

variable "tls" {
  description = "Built-in TLS from an existing kubernetes.io/tls Secret (tls.crt, tls.key and, for client certificates, ca.crt)."
  type = object({
    enabled     = optional(bool, false)
    secret_name = optional(string)
    client_auth = optional(string, "none")
    min_version = optional(string, "1.2")
    health_port = optional(number, 8081)
  })
  default = {}

  validation {
    condition     = !var.tls.enabled || var.tls.secret_name != null
    error_message = "tls.secret_name is required when tls.enabled is true."
  }
  validation {
    condition     = contains(["none", "optional", "required"], var.tls.client_auth)
    error_message = "tls.client_auth must be none, optional or required."
  }
  validation {
    condition     = contains(["1.2", "1.3"], var.tls.min_version)
    error_message = "tls.min_version must be \"1.2\" or \"1.3\"."
  }
}

variable "mtls_identities" {
  description = "Client-certificate identities (Config server.auth.mtls.identities). Need tls.enabled and tls.client_auth optional or required."
  type = list(object({
    spiffe_id              = optional(string)
    subject_cn             = optional(string)
    policy                 = string
    context                = optional(any)
    request_context_fields = optional(list(string))
  }))
  default = []

  validation {
    condition     = alltrue([for m in var.mtls_identities : (m.spiffe_id == null) != (m.subject_cn == null)])
    error_message = "each mTLS identity needs exactly one of spiffe_id or subject_cn."
  }
  validation {
    condition     = alltrue([for m in var.mtls_identities : m.spiffe_id == null || can(regex("^spiffe://[a-z0-9._-]+(/[^\\s?#]*)?$", m.spiffe_id))])
    error_message = "mtls_identities[*].spiffe_id must be a spiffe:// URI with a lower-case trust domain."
  }
  validation {
    condition     = length(var.mtls_identities) == 0 || (var.tls.enabled && var.tls.client_auth != "none")
    error_message = "mtls_identities need tls.enabled and tls.client_auth optional or required."
  }
}

# ---------------------------------------------------------------------------
# Cloud workload identity
# ---------------------------------------------------------------------------

variable "workload_identity" {
  description = <<-EOT
    Binds the pod's ServiceAccount to a cloud identity:
      none             - no binding (default)
      eks-irsa         - EKS IAM Roles for Service Accounts (aws_role_arn)
      eks-pod-identity - EKS Pod Identity (create aws_eks_pod_identity_association for the service_account output)
      aks              - AKS Workload Identity (azure_client_id, optional azure_tenant_id)
      gke              - GKE Workload Identity Federation (gcp_service_account)
  EOT
  type = object({
    provider            = optional(string, "none")
    aws_role_arn        = optional(string)
    azure_client_id     = optional(string)
    azure_tenant_id     = optional(string)
    gcp_service_account = optional(string)
  })
  default = {}

  validation {
    condition     = contains(["none", "eks-irsa", "eks-pod-identity", "aks", "gke"], var.workload_identity.provider)
    error_message = "workload_identity.provider must be none, eks-irsa, eks-pod-identity, aks or gke."
  }
  validation {
    condition     = var.workload_identity.provider != "eks-irsa" || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.workload_identity.aws_role_arn))
    error_message = "eks-irsa needs workload_identity.aws_role_arn (an IAM role ARN)."
  }
  validation {
    condition     = var.workload_identity.provider != "aks" || can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.workload_identity.azure_client_id))
    error_message = "aks needs workload_identity.azure_client_id (the managed identity's client id, a GUID)."
  }
  validation {
    condition     = var.workload_identity.provider != "gke" || can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]@[a-z][-a-z0-9]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.workload_identity.gcp_service_account))
    error_message = "gke needs workload_identity.gcp_service_account (NAME@PROJECT.iam.gserviceaccount.com)."
  }
}

variable "service_account_annotations" {
  description = "Extra ServiceAccount annotations (merged with the workload identity annotations)."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Networking, availability and monitoring
# ---------------------------------------------------------------------------

variable "service" {
  description = "Kubernetes Service. ClusterIP by default: haltsql is called from inside the cluster."
  type = object({
    type        = optional(string, "ClusterIP")
    port        = optional(number, 8080)
    annotations = optional(map(string), {})
  })
  default = {}

  validation {
    condition     = contains(["ClusterIP", "NodePort", "LoadBalancer"], var.service.type)
    error_message = "service.type must be ClusterIP, NodePort or LoadBalancer."
  }
  validation {
    condition     = var.service.port >= 1 && var.service.port <= 65535
    error_message = "service.port must be a TCP port."
  }
}

variable "network_policy" {
  description = <<-EOT
    NetworkPolicy: ingress only from the listed peers (empty = any pod in the
    namespace). The chart denies all egress, which is right for a server with
    file policies and stdout audit, but OIDC (JWKS), bundle_sources, cloud
    audit sinks and secret providers need egress rules: set egress (Kubernetes
    NetworkPolicyEgressRule list, needs chart support for networkPolicy.egress).
  EOT
  type = object({
    enabled      = optional(bool, true)
    ingress_from = optional(any, [])
    metrics_from = optional(any, [])
    egress       = optional(any, [])
  })
  default = {}
}

variable "pod_disruption_budget" {
  description = "PodDisruptionBudget (minAvailable; the chart does not support maxUnavailable)."
  type = object({
    enabled       = optional(bool, true)
    min_available = optional(string, "1")
  })
  default = {}

  validation {
    condition     = can(regex("^([0-9]+|[0-9]{1,2}%|100%)$", var.pod_disruption_budget.min_available))
    error_message = "pod_disruption_budget.min_available must be an integer or a percentage like 50%."
  }
}

variable "service_monitor" {
  description = "Prometheus Operator ServiceMonitor (needs the monitoring.coreos.com CRDs and server.metrics)."
  type = object({
    enabled        = optional(bool, false)
    interval       = optional(string, "30s")
    scrape_timeout = optional(string, "10s")
    labels         = optional(map(string), {})
  })
  default = {}

  validation {
    condition     = can(regex("^[0-9]+(ms|s|m)$", var.service_monitor.interval)) && can(regex("^[0-9]+(ms|s|m)$", var.service_monitor.scrape_timeout))
    error_message = "service_monitor.interval and scrape_timeout must be durations like 30s."
  }
}

# ---------------------------------------------------------------------------
# haltsql-proxy (PostgreSQL wire-protocol firewall)
# ---------------------------------------------------------------------------

variable "proxy" {
  description = <<-EOT
    Optionally run haltsql-proxy next to the server (chart value proxy). The
    proxy config (kind: ProxyConfig, see docs/proxy.md) is given as YAML.
    Needs chart support for proxy (the module refuses to plan otherwise).
  EOT
  type = object({
    enabled     = optional(bool, false)
    replicas    = optional(number, 2)
    port        = optional(number, 6432)
    config_yaml = optional(string, "")
  })
  default = {}

  validation {
    condition     = !var.proxy.enabled || can(keys(yamldecode(var.proxy.config_yaml)))
    error_message = "proxy.config_yaml must be a YAML mapping when proxy.enabled is true."
  }
  validation {
    condition     = var.proxy.port >= 1024 && var.proxy.port <= 65535 && var.proxy.replicas >= 1
    error_message = "proxy.port must be 1024-65535 and proxy.replicas at least 1."
  }
}
