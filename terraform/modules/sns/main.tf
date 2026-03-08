resource "aws_sns_topic" "alerts" {
  name              = "cognitive-soc-alerts-${var.environment}"
  kms_master_key_id = "alias/aws/sns"
}
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
output "alert_topic_arn" { value = aws_sns_topic.alerts.arn }
variable "environment"  { type = string }
variable "alert_email"  { type = string }
variable "slack_webhook"{ type = string; default = "" }
