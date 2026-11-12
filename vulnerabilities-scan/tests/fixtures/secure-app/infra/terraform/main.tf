# Secure look-alike of the Terraform configuration.
terraform {
  required_version = ">= 1.5"
}

resource "aws_s3_bucket" "reports" {
  bucket = "fixture-reports-secure"
  # No public ACL: access stays private.
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id
  # Every public-access guard is on.
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "app" {
  engine = "postgres"
  # Encryption at rest on, not internet reachable.
  storage_encrypted   = true
  publicly_accessible = false
}

resource "aws_security_group" "app" {
  name = "fixture-app-secure"

  ingress {
    # Management ports are reachable only from the private range.
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}
