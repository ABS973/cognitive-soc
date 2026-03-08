locals {
  phase2_functions = [
    "cloudtrail_processor",
    "behavioral_baseline",
    "anomaly_scorer",
    "identity_graph_updater",
    "behavioral_alert",
  ]
}

data "archive_file" "phase2_zips" {
  for_each    = toset(local.phase2_functions)
  type        = "zip"
  source_dir  = "${path.root}/../../../lambda/${each.key}"
  output_path = "${path.module}/zips/${each.key}.zip"
}

resource "aws_lambda_function" "phase2_functions" {
  for_each = toset(local.phase2_functions)

  function_name    = "cognitive-soc-${each.key}-${var.environment}"
  role             = var.lambda_exec_role_arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 512

  filename         = data.archive_file.phase2_zips[each.key].output_path
  source_code_hash = data.archive_file.phase2_zips[each.key].output_base64sha256

  environment {
    variables = {
      ENVIRONMENT          = var.environment
      SNS_ALERT_TOPIC_ARN  = var.sns_alert_topic_arn
      NEPTUNE_ENDPOINT     = var.neptune_endpoint
      BASELINE_TABLE       = "cognitive-soc-baselines-${var.environment}"
      GRAPH_TABLE          = "cognitive-soc-graph-${var.environment}"
      ANOMALY_TABLE        = "cognitive-soc-anomaly-scores-${var.environment}"
      LOG_LEVEL            = var.environment == "prod" ? "WARNING" : "DEBUG"
    }
  }

  tracing_config { mode = "Active" }

  tags = { Phase = "2", Function = each.key }
}

resource "aws_cloudwatch_log_group" "phase2_logs" {
  for_each          = toset(local.phase2_functions)
  name              = "/aws/lambda/cognitive-soc-${each.key}-${var.environment}"
  retention_period_in_days = 30
}

output "cloudtrail_processor_arn" {
  value = aws_lambda_function.phase2_functions["cloudtrail_processor"].arn
}

variable "environment"          { type = string }
variable "lambda_exec_role_arn" { type = string }
variable "sns_alert_topic_arn"  { type = string }
variable "neptune_endpoint"     { type = string; default = "" }
