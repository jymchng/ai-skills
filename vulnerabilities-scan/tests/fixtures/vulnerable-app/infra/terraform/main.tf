# Intentionally insecure Terraform for the fixture.
terraform {
  required_version = ">= 1.5"
}

resource "aws_s3_bucket" "reports" {
  bucket = "fixture-reports"
  # iac-misconfiguration: the bucket is world readable
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id
  # iac-misconfiguration: the public-access guard is switched off
  block_public_acls = false
}

resource "aws_db_instance" "app" {
  engine = "postgres"
  # iac-misconfiguration: storage encryption disabled
  storage_encrypted = false
  # iac-misconfiguration: the database is reachable from the internet
  publicly_accessible = true
}

resource "aws_security_group" "app" {
  name = "fixture-app"

  ingress {
    # iac-misconfiguration: SSH open to the world
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    # iac-misconfiguration: versioning off
    status = "Disabled"
  }
}
