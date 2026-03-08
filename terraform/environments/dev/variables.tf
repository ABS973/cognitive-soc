variable "aws_region" {
  description = "AWS region to deploy Cognitive SOC"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address to receive security alerts"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alert notifications"
  type        = string
  sensitive   = true
  default     = ""
}

variable "waf_acl_id" {
  description = "WAF Web ACL ID for IP blocking playbook (optional)"
  type        = string
  default     = ""
}
