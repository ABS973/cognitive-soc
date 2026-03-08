variable "aws_region"        { type = string; default = "us-east-1" }
variable "environment"       { type = string; default = "dev" }
variable "alert_email"       { type = string }
variable "slack_webhook_url" { type = string; sensitive = true; default = "" }
variable "waf_acl_id"        { type = string; default = "" }
