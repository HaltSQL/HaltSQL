# Two least-privilege roles:
#   execution role - used by ECS itself: pull the image, write the log
#                    stream, read exactly the secrets injected as env vars.
#   task role      - used by haltsql-server: read exactly the bundle objects
#                    and runtime secrets it is given, write audit objects.

locals {
  # ECS accepts ARN:json-key:version-stage:version-id; IAM wants the bare ARN.
  injected_sm_arns = distinct([
    for v in values(var.secrets) : join(":", slice(split(":", v), 0, 7))
    if strcontains(v, ":secretsmanager:")
  ])
  injected_ssm_arns = distinct([for v in values(var.secrets) : v if strcontains(v, ":ssm:")])

  ecr_match = regex("^(?:(?P<account>[0-9]{12})\\.dkr\\.ecr\\.(?P<region>[a-z0-9-]+)\\.amazonaws\\.com/(?P<repo>[^:@]+))?", var.image)
  ecr_repository_arn = local.ecr_match.account == null ? null : (
    "arn:${local.partition}:ecr:${local.ecr_match.region}:${local.ecr_match.account}:repository/${local.ecr_match.repo}"
  )

  bundle_object_arns = [for o in var.s3_bundle_objects : "arn:${local.partition}:s3:::${o.bucket}/${o.key}"]
  audit_prefix_arns  = [for d in var.s3_audit_destinations : "arn:${local.partition}:s3:::${d.bucket}/${d.prefix}*"]
  audit_locked_arns  = [for d in var.s3_audit_destinations : "arn:${local.partition}:s3:::${d.bucket}/${d.prefix}*" if d.object_lock]

  task_has_statements = length(local.bundle_object_arns) + length(local.audit_prefix_arns) + length(var.runtime_secret_arns) > 0
}

data "aws_iam_policy_document" "assume_ecs_tasks" {
  statement {
    sid     = "EcsTasksAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:ecs:${local.region}:${local.account_id}:*"]
    }
  }
}

# ---------------------------------------------------------------------------
# Execution role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  description        = "ECS execution role of ${var.name} (image pull, logs, injected secrets)"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json
  tags               = var.tags
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "WriteContainerLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.this.arn}:log-stream:*"]
  }

  dynamic "statement" {
    for_each = local.ecr_repository_arn == null ? [] : [local.ecr_repository_arn]
    content {
      sid       = "PullImage"
      actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
      resources = [statement.value]
    }
  }

  # ecr:GetAuthorizationToken does not support resource-level permissions.
  dynamic "statement" {
    for_each = local.ecr_repository_arn == null ? [] : [1]
    content {
      sid       = "EcrLogin"
      actions   = ["ecr:GetAuthorizationToken"]
      resources = ["*"] #trivy:ignore:AVD-AWS-0057
    }
  }

  dynamic "statement" {
    for_each = length(local.injected_sm_arns) == 0 ? [] : [1]
    content {
      sid       = "ReadInjectedSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.injected_sm_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.injected_ssm_arns) == 0 ? [] : [1]
    content {
      sid       = "ReadInjectedParameters"
      actions   = ["ssm:GetParameters"]
      resources = local.injected_ssm_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.kms_key_arns) == 0 || length(var.secrets) == 0 ? [] : [1]
    content {
      sid       = "DecryptInjectedSecrets"
      actions   = ["kms:Decrypt"]
      resources = var.kms_key_arns
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "haltsql-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# ---------------------------------------------------------------------------
# Task role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  description        = "Task role of ${var.name} (haltsql-server runtime access)"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json
  tags               = var.tags
}

data "aws_iam_policy_document" "task" {
  count = local.task_has_statements ? 1 : 0

  dynamic "statement" {
    for_each = length(local.bundle_object_arns) == 0 ? [] : [1]
    content {
      sid       = "ReadPolicyBundles"
      actions   = ["s3:GetObject"]
      resources = local.bundle_object_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.audit_prefix_arns) == 0 ? [] : [1]
    content {
      sid       = "WriteAuditObjects"
      actions   = ["s3:PutObject"]
      resources = local.audit_prefix_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.audit_locked_arns) == 0 ? [] : [1]
    content {
      sid       = "SetAuditRetention"
      actions   = ["s3:PutObjectRetention"]
      resources = local.audit_locked_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.runtime_secret_arns) == 0 ? [] : [1]
    content {
      sid       = "ReadRuntimeSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = var.runtime_secret_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.kms_key_arns) == 0 ? [] : [1]
    content {
      sid       = "UseDataKeys"
      actions   = length(local.audit_prefix_arns) > 0 ? ["kms:Decrypt", "kms:GenerateDataKey"] : ["kms:Decrypt"]
      resources = var.kms_key_arns
    }
  }
}

resource "aws_iam_role_policy" "task" {
  count = local.task_has_statements ? 1 : 0

  name   = "haltsql-runtime"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task[0].json
}
