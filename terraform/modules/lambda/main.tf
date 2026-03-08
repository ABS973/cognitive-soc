locals {
  functions = ["guardduty_ingestor","soar_orchestrator","ec2_isolator","iam_revoker","s3_protector","ip_blocker","enrichment","notifier"]
}
data "archive_file" "zips" {
  for_each    = toset(local.functions)
  type        = "zip"
  source_dir  = "${path.root}/../../../lambda/${each.key}"
  output_path = "${path.module}/zips/${each.key}.zip"
}
resource "aws_lambda_function" "functions" {
  for_each         = toset(local.functions)
  function_name    = "cognitive-soc-${each.key}-${var.environment}"
  role             = var.lambda_exec_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256
  filename         = data.archive_file.zips[each.key].output_path
  source_code_hash = data.archive_file.zips[each.key].output_base64sha256
  environment {
    variables = {
      ENVIRONMENT         = var.environment
      AWS_ACCOUNT_ID      = var.account_id
      SNS_ALERT_TOPIC_ARN = var.sns_alert_topic_arn
      FINDINGS_BUCKET     = var.findings_bucket_name
      WAF_ACL_ID          = var.waf_acl_id
      LOG_LEVEL           = var.environment == "prod" ? "WARNING" : "DEBUG"
    }
  }
  tracing_config { mode = "Active" }
}
resource "aws_cloudwatch_log_group" "logs" {
  for_each          = toset(local.functions)
  name              = "/aws/lambda/cognitive-soc-${each.key}-${var.environment}"
  retention_in_days = 30
}
resource "aws_dynamodb_table" "incidents" {
  name           = "cognitive-soc-incidents-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "finding_id"
  range_key      = "timestamp"
  attribute { name = "finding_id"; type = "S" }
  attribute { name = "timestamp";  type = "S" }
  ttl             { attribute_name = "ttl"; enabled = true }
  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}
output "soar_orchestrator_arn" { value = aws_lambda_function.functions["soar_orchestrator"].arn }
variable "environment"          { type = string }
variable "aws_region"           { type = string }
variable "account_id"           { type = string }
variable "lambda_exec_role_arn" { type = string }
variable "sns_alert_topic_arn"  { type = string }
variable "findings_bucket_name" { type = string }
variable "waf_acl_id"           { type = string; default = "" }
