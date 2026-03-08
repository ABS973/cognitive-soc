terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.0" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "CognitiveSoc"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "SecureOpsLabs"
    }
  }
}

module "guardduty"  { source = "../../modules/guardduty";  environment = var.environment }
module "iam"        { source = "../../modules/iam";        environment = var.environment; account_id = data.aws_caller_identity.current.account_id; aws_region = var.aws_region }
module "sns"        { source = "../../modules/sns";        environment = var.environment; alert_email = var.alert_email; slack_webhook = var.slack_webhook_url }
module "lambda"     { source = "../../modules/lambda";     environment = var.environment; aws_region = var.aws_region; account_id = data.aws_caller_identity.current.account_id; lambda_exec_role_arn = module.iam.lambda_exec_role_arn; sns_alert_topic_arn = module.sns.alert_topic_arn; findings_bucket_name = aws_s3_bucket.findings.bucket; waf_acl_id = var.waf_acl_id }
module "eventbridge"{ source = "../../modules/eventbridge"; environment = var.environment; soar_orchestrator_lambda_arn = module.lambda.soar_orchestrator_arn; guardduty_detector_id = module.guardduty.detector_id }

resource "aws_s3_bucket" "findings" {
  bucket = "cognitive-soc-findings-${var.environment}-${data.aws_caller_identity.current.account_id}"
}
resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
