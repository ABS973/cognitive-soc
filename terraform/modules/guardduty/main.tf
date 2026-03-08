resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection { scan_ec2_instance_with_findings { ebs_volumes { enable = true } } }
  }
  tags = { Name = "cognitive-soc-${var.environment}" }
}
output "detector_id" { value = aws_guardduty_detector.main.id }
variable "environment" { type = string }
