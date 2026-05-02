# ==========================================
# S3 BUCKET MODULE MAIN
# Purpose: Creates a secure, private bucket for application files.
# ==========================================
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "${var.project_name}-${var.environment}-storage-${random_string.suffix.result}"
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.app_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

