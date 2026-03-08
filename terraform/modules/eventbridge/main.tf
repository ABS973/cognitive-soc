resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "cognitive-soc-guardduty-findings-${var.environment}"
  description = "Routes GuardDuty findings to SOAR orchestrator"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 4] }] }
  })
}
resource "aws_cloudwatch_event_target" "soar" {
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
variable "environment"                   { type = string }
variable "soar_orchestrator_lambda_arn"  { type = string }
variable "guardduty_detector_id"         { type = string }
