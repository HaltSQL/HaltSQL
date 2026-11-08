# Minimal AWS footprint for haltsql-server's S3 audit sink:
#   - a KMS key for the bucket,
#   - an S3 bucket with Object Lock (WORM), versioning, SSE-KMS, TLS-only access,
#     no public access, and a lifecycle rule,
#   - a least-privilege IAM policy (PutObject + PutObjectRetention on the
#     prefix, GetSecretValue on named secrets, KMS through S3 / Secrets Manager),
#   - optionally an IRSA role for an EKS service account.
# See docs/deploy-aws.md.

data "aws_region" "current" {}

locals {
  region       = data.aws_region.current.region
  audit_prefix = trimsuffix(var.audit_prefix, "/") == "" ? "" : "${trimsuffix(var.audit_prefix, "/")}/"
}

# ---------------------------------------------------------------------------
# KMS
# ---------------------------------------------------------------------------

resource "aws_kms_key" "audit" {
  description             = "${var.name} audit bucket encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name}-audit"
  target_key_id = aws_kms_key.audit.key_id
}

# ---------------------------------------------------------------------------
# Audit bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "audit" {
  bucket              = var.audit_bucket_name
  object_lock_enabled = true
  tags                = var.tags
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  count  = var.transition_to_glacier_ir_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "audit-to-glacier-ir"
    status = "Enabled"

    filter {
      prefix = local.audit_prefix
    }

    transition {
      days          = var.transition_to_glacier_ir_days
      storage_class = "GLACIER_IR"
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.audit.arn,
      "${aws_s3_bucket.audit.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.audit]
}

# ---------------------------------------------------------------------------
# Least-privilege policy for haltsql-server
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "haltsql" {
  statement {
    sid       = "WriteAuditObjectsUnderPrefix"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:PutObjectRetention"]
    resources = ["${aws_s3_bucket.audit.arn}/${local.audit_prefix}*"]
  }

  statement {
    sid       = "EncryptAuditObjects"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.audit.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = length(var.secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadHaltsqlSecrets"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = var.secret_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.secrets_kms_key_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptSecrets"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = var.secrets_kms_key_arns
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${local.region}.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_policy" "haltsql" {
  name        = "${var.name}-server"
  description = "haltsql-server: write audit objects, read its secrets"
  policy      = data.aws_iam_policy_document.haltsql.json
  tags        = var.tags
}

# ---------------------------------------------------------------------------
# Optional IRSA role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "irsa_trust" {
  count = var.irsa == null ? 0 : 1

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.irsa.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.irsa.oidc_issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.irsa.oidc_issuer_host}:sub"
      values   = ["system:serviceaccount:${var.irsa.namespace}:${var.irsa.service_account}"]
    }
  }
}

resource "aws_iam_role" "irsa" {
  count                = var.irsa == null ? 0 : 1
  name                 = "${var.name}-irsa"
  assume_role_policy   = data.aws_iam_policy_document.irsa_trust[0].json
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy_attachment" "irsa" {
  count      = var.irsa == null ? 0 : 1
  role       = aws_iam_role.irsa[0].name
  policy_arn = aws_iam_policy.haltsql.arn
}
