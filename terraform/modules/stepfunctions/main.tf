# ──────────────────────────────────────────────────────────────────────────────
# Cognitive SOC Phase 3 — Step Functions Investigation Orchestrator
# Express Workflow: fast, low-latency, designed for sub-60s execution
# ──────────────────────────────────────────────────────────────────────────────

variable "environment"         { type = string }
variable "aws_region"          { type = string }
variable "account_id"          { type = string }
variable "triage_lambda_arn"   { type = string }
variable "context_lambda_arn"  { type = string }
variable "bedrock_lambda_arn"  { type = string }
variable "report_lambda_arn"   { type = string }
variable "delivery_lambda_arn" { type = string }

locals {
  name = "cognitive-soc-investigation-${var.environment}"
}

# ── IAM Role for Step Functions ───────────────────────────────────────────────

resource "aws_iam_role" "sfn_role" {
  name = "${local.name}-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "sfn_lambda_invoke" {
  name = "${local.name}-sfn-lambda-invoke"
  role = aws_iam_role.sfn_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          var.triage_lambda_arn,
          var.context_lambda_arn,
          var.bedrock_lambda_arn,
          var.report_lambda_arn,
          var.delivery_lambda_arn,
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
                    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
                    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules",
                    "xray:GetSamplingTargets"]
        Resource = "*"
      }
    ]
  })
}

# ── CloudWatch Log Group ──────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "sfn_logs" {
  name              = "/aws/states/${local.name}"
  retention_in_days = 90
}

# ── Step Functions State Machine ──────────────────────────────────────────────
# Express Workflow — best for sub-60s, high-throughput event processing

resource "aws_sfn_state_machine" "investigation" {
  name     = local.name
  role_arn = aws_iam_role.sfn_role.arn
  type     = "EXPRESS"   # Fast, event-driven, perfect for investigation pipeline

  definition = jsonencode({
    Comment = "Cognitive SOC Phase 3: Autonomous AI Investigation Pipeline"
    StartAt = "Triage"

    States = {

      # ── Step 2: False Positive Triage ──────────────────────────────────────
      Triage = {
        Type     = "Task"
        Resource = var.triage_lambda_arn
        TimeoutSeconds = 20
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "TriageFailed"
          ResultPath  = "$.triage_error"
        }]
        Next = "TriageDecision"
      }

      # ── Triage routing ─────────────────────────────────────────────────────
      TriageDecision = {
        Type = "Choice"
        Choices = [
          {
            Variable      = "$.proceed"
            BooleanEquals = true
            Next          = "GatherContext"
          }
        ]
        Default = "Dismissed"
      }

      # ── Step 3: Context Gathering (parallel data fetches) ─────────────────
      GatherContext = {
        Type     = "Task"
        Resource = var.context_lambda_arn
        TimeoutSeconds = 60
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "ContextFailed"
          ResultPath  = "$.context_error"
        }]
        Next = "Investigate"
      }

      # ── Step 4/5: AI Investigation via Bedrock ────────────────────────────
      Investigate = {
        Type     = "Task"
        Resource = var.bedrock_lambda_arn
        TimeoutSeconds = 130
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException",
                             "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 3
          MaxAttempts     = 2
          BackoffRate     = 2
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "InvestigationFailed"
          ResultPath  = "$.investigation_error"
        }]
        Next = "GenerateReport"
      }

      # ── Step 6: Report Generation ─────────────────────────────────────────
      GenerateReport = {
        Type     = "Task"
        Resource = var.report_lambda_arn
        TimeoutSeconds = 40
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "ReportFailed"
          ResultPath  = "$.report_error"
        }]
        Next = "Deliver"
      }

      # ── Step 7: Delivery (Slack + SNS + SOAR) ────────────────────────────
      Deliver = {
        Type     = "Task"
        Resource = var.delivery_lambda_arn
        TimeoutSeconds = 40
        Retry = [{
          ErrorEquals     = ["Lambda.ServiceException"]
          IntervalSeconds = 2
          MaxAttempts     = 2
          BackoffRate     = 1.5
        }]
        End = true
      }

      # ── Terminal States ────────────────────────────────────────────────────
      Dismissed = {
        Type = "Succeed"
        Comment = "Triage engine classified as false positive or below threshold — investigation dismissed"
      }

      TriageFailed = {
        Type  = "Fail"
        Error = "TriageError"
        Cause = "Triage engine Lambda failed after retries"
      }

      ContextFailed = {
        Type  = "Fail"
        Error = "ContextGatheringError"
        Cause = "Context gatherer Lambda failed after retries"
      }

      InvestigationFailed = {
        Type  = "Fail"
        Error = "InvestigationError"
        Cause = "Bedrock investigation Lambda failed after retries"
      }

      ReportFailed = {
        Type  = "Fail"
        Error = "ReportGenerationError"
        Cause = "Report generator Lambda failed after retries"
      }
    }
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn_logs.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  tags = {
    Environment = var.environment
    Project     = "cognitive-soc"
    Phase       = "3"
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "state_machine_arn" {
  value       = aws_sfn_state_machine.investigation.arn
  description = "ARN of the investigation Step Functions state machine"
}

output "state_machine_name" {
  value       = aws_sfn_state_machine.investigation.name
  description = "Name of the investigation state machine"
}
