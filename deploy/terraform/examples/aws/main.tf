# haltsql-server on ECS Fargate behind an internal NLB, in an existing VPC.

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      "app.kubernetes.io/part-of" = "haltsql"
      ManagedBy                   = "terraform"
    }
  }
}

resource "aws_kms_key" "haltsql" {
  description             = "${var.name}: secrets and logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.name}"]
    }
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enhanced"
  }
}

resource "aws_secretsmanager_secret" "agent_token_sha256" {
  name_prefix             = "${var.name}/agent-token-sha256-"
  description             = "SHA-256 of the example agent's haltsql bearer token"
  kms_key_id              = aws_kms_key.haltsql.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "agent_token_sha256" {
  secret_id     = aws_secretsmanager_secret.agent_token_sha256.id
  secret_string = var.agent_token_sha256
}

module "haltsql" {
  source = "../../modules/haltsql-aws"

  name        = var.name
  cluster_arn = aws_ecs_cluster.this.arn
  vpc_id      = var.vpc_id
  subnet_ids  = var.private_subnet_ids
  image       = var.image

  config_yaml = file("${path.module}/haltsql.yaml")
  secrets = {
    HALTSQL_AGENT_TOKEN_SHA256 = aws_secretsmanager_secret.agent_token_sha256.arn
  }
  kms_key_arns    = [aws_kms_key.haltsql.arn]
  log_kms_key_arn = aws_kms_key.haltsql.arn

  ingress_cidr_blocks = var.caller_cidr_blocks
  internal_nlb = {
    enabled             = true
    port                = 8080
    deletion_protection = var.nlb_deletion_protection
  }

  depends_on = [aws_secretsmanager_secret_version.agent_token_sha256]
}
