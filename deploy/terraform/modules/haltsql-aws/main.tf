# haltsql-server on ECS Fargate.
#
# Task layout: a short-lived, non-essential "config-writer" container writes
# the Config document into a task-scoped volume (the haltsql image is
# distroless, with no shell), then haltsql-server starts with a read-only
# root filesystem, uid 65532, no Linux capabilities and the config mounted
# read-only. Secrets reach the server only as environment variables injected
# by ECS (referenced in the config as ${env:NAME}).

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  config_path = "/etc/haltsql/config/config.yaml"
  server_args = concat(
    ["--config", local.config_path],
    var.health_port == null ? [] : ["--health-listen", "0.0.0.0:${var.health_port}"],
  )
  health_check_port     = var.health_port == null ? var.container_port : var.health_port
  health_check_protocol = var.health_port == null && var.server_tls ? "HTTPS" : "HTTP"

  log_config = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.this.name
      "awslogs-region"        = local.region
      "awslogs-stream-prefix" = var.name
    }
  }

  config_writer = {
    name      = "config-writer"
    image     = var.config_init_image
    essential = false
    user      = "0"
    command = [
      "sh", "-c",
      "set -eu; printf '%s' \"$CONFIG_B64\" | base64 -d > /config/config.yaml; chmod 0444 /config/config.yaml; chown 65532:65532 /audit /scratch; chmod 0700 /audit /scratch",
    ]
    environment = [{ name = "CONFIG_B64", value = base64encode(var.config_yaml) }]
    mountPoints = [
      { sourceVolume = "config", containerPath = "/config", readOnly = false },
      { sourceVolume = "audit", containerPath = "/audit", readOnly = false },
      { sourceVolume = "scratch", containerPath = "/scratch", readOnly = false },
    ]
    readonlyRootFilesystem = true
    linuxParameters = {
      capabilities = { drop = ["ALL"], add = ["CHOWN", "FOWNER"] }
    }
    logConfiguration = local.log_config
  }

  server = {
    name      = "haltsql"
    image     = var.image
    essential = true
    user      = "65532:65532"
    command   = local.server_args
    portMappings = concat(
      [{ containerPort = var.container_port, protocol = "tcp", name = "http" }],
      var.health_port == null ? [] : [{ containerPort = var.health_port, protocol = "tcp", name = "health" }],
    )
    environment = [
      for k, v in merge(var.environment, { HALTSQL_LISTEN = "0.0.0.0:${var.container_port}" }) :
      { name = k, value = v }
    ]
    secrets = [for k, v in var.secrets : { name = k, valueFrom = v }]
    mountPoints = [
      { sourceVolume = "config", containerPath = "/etc/haltsql/config", readOnly = true },
      { sourceVolume = "audit", containerPath = "/var/log/haltsql", readOnly = false },
      { sourceVolume = "scratch", containerPath = "/tmp", readOnly = false },
    ]
    dependsOn              = [{ containerName = "config-writer", condition = "SUCCESS" }]
    readonlyRootFilesystem = true
    privileged             = false
    linuxParameters = {
      capabilities       = { drop = ["ALL"] }
      initProcessEnabled = true
    }
    ulimits          = [{ name = "nofile", softLimit = 65536, hardLimit = 65536 }]
    stopTimeout      = 20
    logConfiguration = local.log_config
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = var.tags
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "config"
  }
  volume {
    name = "audit"
  }
  volume {
    name = "scratch"
  }

  container_definitions = jsonencode([local.config_writer, local.server])
  tags                  = var.tags
}

resource "aws_ecs_service" "this" {
  name                   = var.name
  cluster                = var.cluster_arn
  task_definition        = aws_ecs_task_definition.this.arn
  desired_count          = var.desired_count
  launch_type            = "FARGATE"
  platform_version       = "LATEST"
  propagate_tags         = "SERVICE"
  enable_execute_command = false
  wait_for_steady_state  = var.wait_for_steady_state

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = var.assign_public_ip
  }

  dynamic "load_balancer" {
    for_each = var.alb_target_group.enabled ? [aws_lb_target_group.alb[0].arn] : []
    content {
      target_group_arn = load_balancer.value
      container_name   = "haltsql"
      container_port   = var.container_port
    }
  }

  dynamic "load_balancer" {
    for_each = var.internal_nlb.enabled ? [aws_lb_target_group.nlb[0].arn] : []
    content {
      target_group_arn = load_balancer.value
      container_name   = "haltsql"
      container_port   = var.container_port
    }
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = length(var.ingress_cidr_blocks) + length(var.ingress_security_group_ids) > 0 || var.alb_target_group.enabled || var.internal_nlb.enabled
      error_message = "nothing can reach haltsql-server: set ingress_cidr_blocks, ingress_security_group_ids, alb_target_group or internal_nlb."
    }
  }
}

# ---------------------------------------------------------------------------
# Plan-time warnings (they never block an apply) for settings in config_yaml
# that are only safe in development or for a trusted backend.
# ---------------------------------------------------------------------------

locals {
  config_doc = yamldecode(var.config_yaml)

  # Inline policies that isolate tenants, by policy name. Policies from a
  # bundle are not visible here; haltsql-server logs the same warning for them.
  config_tenancy_policies = try([
    for p in local.config_doc.policies : p.inline.metadata.name if can(p.inline.tenancy)
  ], [])

  config_unbound_tenant_tokens = try([
    for t in local.config_doc.server.auth.tokens : t.name
    if !can(t.context) && !can(t.request_context_fields) && contains(local.config_tenancy_policies, t.policy)
  ], [])
}

check "unauthenticated_access" {
  assert {
    condition     = try(local.config_doc.server.auth.allow_unauthenticated, false) != true
    error_message = "config_yaml sets server.auth.allow_unauthenticated: haltsql-server accepts every caller without credentials. This is for local development only."
  }
}

check "tokens_bound_to_a_tenant" {
  assert {
    condition     = length(local.config_unbound_tenant_tokens) == 0
    error_message = "These tokens in config_yaml are pinned to a policy with tenancy but have neither context nor request_context_fields, so their holders can name any tenant in the request body: ${join(", ", local.config_unbound_tenant_tokens)}. Give each a context (or use OIDC); leave a token unbound only for a trusted backend that takes the tenant from its own session."
  }
}
