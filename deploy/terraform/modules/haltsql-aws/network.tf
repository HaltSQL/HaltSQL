# Security groups, the optional ALB target group and the optional internal NLB.

resource "aws_security_group" "tasks" {
  name_prefix = "${var.name}-tasks-"
  description = "haltsql-server tasks"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-tasks" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "tasks_cidr" {
  for_each = toset(var.ingress_cidr_blocks)

  security_group_id = aws_security_group.tasks.id
  description       = "haltsql-server from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = var.container_port
  to_port           = var.container_port
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "tasks_sg" {
  for_each = toset(var.ingress_security_group_ids)

  security_group_id            = aws_security_group.tasks.id
  description                  = "haltsql-server from ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = var.container_port
  to_port                      = var.container_port
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_ingress_rule" "tasks_health_cidr" {
  for_each = var.health_port == null ? toset([]) : toset(var.ingress_cidr_blocks)

  security_group_id = aws_security_group.tasks.id
  description       = "haltsql-server health port from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = var.health_port
  to_port           = var.health_port
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "tasks_health_sg" {
  for_each = var.health_port == null ? toset([]) : toset(var.ingress_security_group_ids)

  security_group_id            = aws_security_group.tasks.id
  description                  = "haltsql-server health port from ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = var.health_port
  to_port                      = var.health_port
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_nlb" {
  for_each = var.internal_nlb.enabled ? toset(distinct([tostring(var.container_port), tostring(local.health_check_port)])) : toset([])

  security_group_id            = aws_security_group.tasks.id
  description                  = "haltsql-server port ${each.value} from the internal NLB"
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
  referenced_security_group_id = aws_security_group.nlb[0].id
}

# Outbound HTTPS only: image pulls, Secrets Manager/SSM, S3 bundles and audit,
# OIDC JWKS and bundle registries. Narrow egress_cidr_blocks to VPC endpoint
# ranges, or use prefix lists, where the network allows it.
#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "tasks_https" {
  for_each = toset(var.egress_cidr_blocks)

  security_group_id = aws_security_group.tasks.id
  description       = "HTTPS to ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "tasks_https_prefix_list" {
  for_each = toset(var.egress_prefix_list_ids)

  security_group_id = aws_security_group.tasks.id
  description       = "HTTPS to prefix list ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = each.value
}

# ---------------------------------------------------------------------------
# ALB target group (attach to your own listener)
# ---------------------------------------------------------------------------

resource "aws_lb_target_group" "alb" {
  count = var.alb_target_group.enabled ? 1 : 0

  name                 = "${var.name}-alb"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  port                 = var.container_port
  protocol             = var.server_tls ? "HTTPS" : "HTTP"
  deregistration_delay = var.alb_target_group.deregistration_delay

  health_check {
    enabled             = true
    path                = "/readyz"
    port                = tostring(local.health_check_port)
    protocol            = local.health_check_protocol
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Internal NLB
# ---------------------------------------------------------------------------

resource "aws_security_group" "nlb" {
  count = var.internal_nlb.enabled ? 1 : 0

  name_prefix = "${var.name}-nlb-"
  description = "haltsql-server internal NLB"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-nlb" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "nlb_cidr" {
  for_each = var.internal_nlb.enabled ? toset(var.ingress_cidr_blocks) : toset([])

  security_group_id = aws_security_group.nlb[0].id
  description       = "NLB listener from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = var.internal_nlb.port
  to_port           = var.internal_nlb.port
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "nlb_sg" {
  for_each = var.internal_nlb.enabled ? toset(var.ingress_security_group_ids) : toset([])

  security_group_id            = aws_security_group.nlb[0].id
  description                  = "NLB listener from ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = var.internal_nlb.port
  to_port                      = var.internal_nlb.port
  referenced_security_group_id = each.value
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_tasks" {
  for_each = var.internal_nlb.enabled ? toset(distinct([tostring(var.container_port), tostring(local.health_check_port)])) : toset([])

  security_group_id            = aws_security_group.nlb[0].id
  description                  = "NLB to haltsql-server port ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
  referenced_security_group_id = aws_security_group.tasks.id
}

resource "aws_lb" "nlb" {
  count = var.internal_nlb.enabled ? 1 : 0

  name                             = "${var.name}-nlb"
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = coalesce(var.internal_nlb.subnet_ids, var.subnet_ids)
  security_groups                  = [aws_security_group.nlb[0].id]
  enable_cross_zone_load_balancing = var.internal_nlb.cross_zone
  enable_deletion_protection       = var.internal_nlb.deletion_protection

  dynamic "access_logs" {
    for_each = var.internal_nlb.access_logs_bucket == null ? [] : [var.internal_nlb.access_logs_bucket]
    content {
      bucket  = access_logs.value
      prefix  = var.internal_nlb.access_logs_prefix
      enabled = true
    }
  }

  tags = var.tags
}

resource "aws_lb_target_group" "nlb" {
  count = var.internal_nlb.enabled ? 1 : 0

  name                 = "${var.name}-nlb"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  port                 = var.container_port
  protocol             = var.internal_nlb.certificate_arn != null && var.server_tls ? "TLS" : "TCP"
  deregistration_delay = 20

  health_check {
    enabled             = true
    protocol            = local.health_check_protocol
    path                = "/readyz"
    port                = tostring(local.health_check_port)
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = var.tags
}

resource "aws_lb_listener" "nlb" {
  count = var.internal_nlb.enabled ? 1 : 0

  load_balancer_arn = aws_lb.nlb[0].arn
  port              = var.internal_nlb.port
  protocol          = var.internal_nlb.certificate_arn == null ? "TCP" : "TLS"
  certificate_arn   = var.internal_nlb.certificate_arn
  ssl_policy        = var.internal_nlb.certificate_arn == null ? null : var.internal_nlb.ssl_policy

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nlb[0].arn
  }

  tags = var.tags
}
