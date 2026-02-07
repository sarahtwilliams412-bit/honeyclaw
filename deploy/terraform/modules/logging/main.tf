# =============================================================================
# Honeyclaw Logging Module
# S3 buckets with Object Lock for tamper-proof log retention
# =============================================================================

variable "environment" { type = string }
variable "log_bucket_name" { type = string }
variable "retention_days" { type = number }
variable "object_lock_days" { type = number }
variable "enable_replication" { type = bool }
variable "replication_bucket_arn" { type = string }

# --- S3 Bucket with Object Lock ---

resource "aws_s3_bucket" "logs" {
  bucket = "${var.log_bucket_name}-${var.environment}"

  object_lock_enabled = true

  tags = {
    Name        = "honeyclaw-logs-${var.environment}"
    Purpose     = "honeypot-log-storage"
    Immutable   = "true"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.retention_days * 2
    }

    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }
  }
}

# --- Bucket Policy (restrict access) ---

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyDeleteObjectLock"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource  = "${aws_s3_bucket.logs.arn}/*"
      }
    ]
  })
}

# --- Cross-Region Replication (optional) ---

resource "aws_s3_bucket_replication_configuration" "logs" {
  count  = var.enable_replication ? 1 : 0
  bucket = aws_s3_bucket.logs.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = var.replication_bucket_arn
      storage_class = "STANDARD_IA"
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

resource "aws_iam_role" "replication" {
  count       = var.enable_replication ? 1 : 0
  name_prefix = "honeyclaw-log-replication-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
    }]
  })
}

# --- Outputs ---

output "bucket_name" {
  value = aws_s3_bucket.logs.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.logs.arn
}
