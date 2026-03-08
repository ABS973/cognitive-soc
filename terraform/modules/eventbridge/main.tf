# ─── GuardDuty Finding → SOAR Orchestrator ───────────────────────
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "cognitive-soc-guardduty-findings-${var.environment}"
  description = "Captures all GuardDuty findings and routes to SOAR orchestrator"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]  # Medium (4) and above
    }
  })
}

resource "aws_cloudwatch_event_target" "soar_orchestrator" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SOAROrchestrator"
  arn       = var.soar_orchestrator_lambda_arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.soar_orchestrator_lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

# ─── High Severity Findings → Immediate Alert ────────────────────
resource "aws_cloudwatch_event_rule" "high_severity" {
  name        = "cognitive-soc-high-severity-${var.environment}"
  description = "Routes high/critical findings for immediate escalation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]  # High (7+) and Critical (8.9+)
    }
  })
}

variable "soar_orchestrator_lambda_arn" {
  type = string
}
variable "guardduty_detector_id" {
  type = string
}
variable "environment" {
  type = string
}
