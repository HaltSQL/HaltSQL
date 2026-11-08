# Input validation and fail-closed preconditions of haltsql-kubernetes.
# These runs only plan, and every one is expected to fail before any request
# reaches a cluster, so they need no Kubernetes API and no mock provider.
#
#   terraform -chdir=deploy/terraform/modules/haltsql-kubernetes init -backend=false
#   terraform -chdir=deploy/terraform/modules/haltsql-kubernetes test

provider "kubernetes" {
  host = "https://127.0.0.1:1"
}

provider "helm" {
  kubernetes = {
    host = "https://127.0.0.1:1"
  }
}

variables {
  tokens = [{
    name   = "agent"
    sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    policy = "p"
  }]
  policies = {
    "p.yaml" = "apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: { name: p }\n"
  }
}

run "rejects_plain_token_instead_of_hash" {
  command = plan
  variables {
    tokens = [{ name = "agent", sha256 = "my-secret-token", policy = "p" }]
  }
  expect_failures = [var.tokens]
}

run "rejects_duplicate_token_names" {
  command = plan
  variables {
    tokens = [
      { name = "a", sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", policy = "p" },
      { name = "a", sha256 = "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9", policy = "p" },
    ]
  }
  expect_failures = [var.tokens]
}

run "rejects_bad_release_name" {
  command = plan
  variables {
    release_name = "HaltSQL_Prod"
  }
  expect_failures = [var.release_name]
}

run "rejects_privileged_port" {
  command = plan
  variables {
    server = { port = 80 }
  }
  expect_failures = [var.server]
}

run "rejects_unknown_audit_sink" {
  command = plan
  variables {
    server = { audit_sinks = [{ type = "syslog" }] }
  }
  expect_failures = [var.server]
}

run "rejects_non_policy_document" {
  command = plan
  variables {
    policies = { "p.yaml" = "kind: Config\n" }
  }
  expect_failures = [var.policies]
}

run "rejects_bad_image_digest" {
  command = plan
  variables {
    image = { digest = "sha256:abc" }
  }
  expect_failures = [var.image]
}

run "rejects_bad_memory_quantity" {
  command = plan
  variables {
    resources = { limits = { memory = "lots" } }
  }
  expect_failures = [var.resources]
}

run "rejects_bundle_source_without_keys" {
  command = plan
  variables {
    bundle_sources = [{ oci = "ghcr.io/corp/policies:prod", public_keys = [] }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_bundle_source_with_two_forms" {
  command = plan
  variables {
    bundle_sources = [{
      oci         = "ghcr.io/corp/policies:prod"
      https       = "https://bundles.corp.example/p.haltsqlbundle"
      public_keys = ["k"]
    }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_oci_without_registry_host" {
  command = plan
  variables {
    bundle_sources = [{ oci = "corp/policies:prod", public_keys = ["k"] }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_plain_http_for_remote_registry" {
  command = plan
  variables {
    bundle_sources = [{ oci = "registry.corp.example/p:1", plain_http = true, public_keys = ["k"] }]
  }
  expect_failures = [var.bundle_sources]
}

# Regression: literal registry credentials were accepted and rendered into the
# ConfigMap and the (non-sensitive) Helm values.
run "rejects_literal_registry_password" {
  command = plan
  variables {
    bundle_sources = [{
      oci         = "registry.corp.example/haltsql/policies:prod"
      public_keys = ["ed25519:AAAA"]
      auth        = { username = "ci", password = "LITERAL-REGISTRY-PASSWORD" }
    }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_literal_registry_token" {
  command = plan
  variables {
    bundle_sources = [{
      oci         = "registry.corp.example/haltsql/policies:prod"
      public_keys = ["ed25519:AAAA"]
      auth        = { token = "ghp_literaltoken" }
    }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_placeholder_with_trailing_literal" {
  command = plan
  variables {
    bundle_sources = [{
      oci         = "registry.corp.example/haltsql/policies:prod"
      public_keys = ["ed25519:AAAA"]
      auth        = { token = "$${env:T}literal" }
    }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_auth_on_s3_bundle" {
  command = plan
  variables {
    bundle_sources = [{
      s3          = { bucket = "b", key = "k", region = "eu-west-1" }
      public_keys = ["k"]
      auth        = { token = "$${env:T}" }
    }]
  }
  expect_failures = [var.bundle_sources]
}

run "rejects_http_oidc_issuer" {
  command = plan
  variables {
    oidc_providers = [{ name = "idp", issuer = "http://idp.example", audiences = ["haltsql"], policy = "p" }]
  }
  expect_failures = [var.oidc_providers]
}

run "rejects_oidc_with_two_policy_selectors" {
  command = plan
  variables {
    oidc_providers = [{
      name             = "idp"
      issuer           = "https://idp.example"
      audiences        = ["haltsql"]
      policy           = "p"
      policy_claim     = "haltsql_policy"
      allowed_policies = ["p"]
    }]
  }
  expect_failures = [var.oidc_providers]
}

run "rejects_hs256_oidc_algorithm" {
  command = plan
  variables {
    oidc_providers = [{ name = "idp", issuer = "https://idp.example", audiences = ["haltsql"], policy = "p", algorithms = ["HS256"] }]
  }
  expect_failures = [var.oidc_providers]
}

run "rejects_mtls_without_client_auth" {
  command = plan
  variables {
    tls             = { enabled = true, secret_name = "haltsql-tls", client_auth = "none" }
    mtls_identities = [{ spiffe_id = "spiffe://corp.example/ns/a/sa/b", policy = "p" }]
  }
  expect_failures = [var.mtls_identities]
}

run "rejects_tls_without_secret" {
  command = plan
  variables {
    tls = { enabled = true }
  }
  expect_failures = [var.tls]
}

run "rejects_irsa_without_role" {
  command = plan
  variables {
    workload_identity = { provider = "eks-irsa" }
  }
  expect_failures = [var.workload_identity]
}

run "rejects_aks_without_client_id" {
  command = plan
  variables {
    workload_identity = { provider = "aks", azure_client_id = "not-a-guid" }
  }
  expect_failures = [var.workload_identity]
}

run "rejects_gke_with_bad_service_account" {
  command = plan
  variables {
    workload_identity = { provider = "gke", gcp_service_account = "haltsql" }
  }
  expect_failures = [var.workload_identity]
}

run "rejects_reserved_secret_env_name" {
  command = plan
  variables {
    secret_env = [{ name = "HALTSQL_TOKEN_0_SHA256", secret_name = "s", key = "k" }]
  }
  expect_failures = [var.secret_env]
}

run "rejects_config_yaml_setting_policies" {
  command = plan
  variables {
    config_yaml = "policies: []\n"
  }
  expect_failures = [var.config_yaml]
}

run "rejects_repository_without_version" {
  command = plan
  variables {
    chart_repository = "oci://ghcr.io/haltsql/charts"
  }
  expect_failures = [var.chart_version]
}

# Fail-closed preconditions: features a local chart cannot render must stop
# the plan instead of being dropped silently. The repository chart has
# extraPolicies and extraConfig, so those runs use a fixture chart without
# them.

run "refuses_bundle_sources_without_chart_support" {
  command = plan
  variables {
    chart_path     = "./tests/fixtures/chart-without-extensions"
    bundle_sources = [{ oci = "ghcr.io/corp/policies:prod", public_keys = ["k"] }]
    network_policy = { enabled = false }
  }
  expect_failures = [helm_release.haltsql]
}

run "refuses_proxy_without_chart_support" {
  command = plan
  variables {
    proxy = { enabled = true, config_yaml = "apiVersion: haltsql.dev/v1\nkind: ProxyConfig\n" }
  }
  expect_failures = [helm_release.haltsql]
}

run "refuses_extra_config_without_chart_support" {
  command = plan
  variables {
    chart_path = "./tests/fixtures/chart-without-extensions"
    config     = { telemetry = { metrics = { prometheus = false } } }
  }
  expect_failures = [helm_release.haltsql]
}

run "refuses_no_authentication" {
  command = plan
  variables {
    tokens = []
  }
  expect_failures = [helm_release.haltsql]
}

run "refuses_no_policies" {
  command = plan
  variables {
    policies = {}
  }
  expect_failures = [helm_release.haltsql]
}
