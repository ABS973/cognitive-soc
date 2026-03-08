data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "cognitive-soc-lambda-exec-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

# ─── Core Lambda Permissions ─────────────────────────────────────
data "aws_iam_policy_document" "lambda_permissions" {
  # CloudWatch Logs
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${var.account_id}:*"]
  }

  # GuardDuty — read findings
  statement {
    effect    = "Allow"
    actions   = ["guardduty:GetFindings", "guardduty:ListFindings", "guardduty:ArchiveFindings"]
    resources = ["*"]
  }

  # EC2 — isolation playbook
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:ModifyInstanceAttribute",
      "ec2:CreateSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
      "ec2:StopInstances"
    ]
    resources = ["*"]
  }

  # IAM — credential revocation playbook
  statement {
    effect = "Allow"
    actions = [
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys",
      "iam:GetUser",
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy",
      "iam:PutUserPolicy"
    ]
    resources = ["*"]
  }

  # S3 — bucket protection playbook
  statement {
    effect = "Allow"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPolicy",
      "s3:GetBucketPolicy"
    ]
    resources = ["*"]
  }

  # WAF — IP blocking playbook
  statement {
    effect = "Allow"
    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet",
      "wafv2:ListIPSets"
    ]
    resources = ["*"]
  }

  # SNS — notifications
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = ["arn:aws:sns:${var.aws_region}:${var.account_id}:cognitive-soc-*"]
  }

  # S3 — findings storage
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["arn:aws:s3:::cognitive-soc-findings-*/*"]
  }

  # DynamoDB — state management
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query"
    ]
    resources = ["arn:aws:dynamodb:${var.aws_region}:${var.account_id}:table/cognitive-soc-*"]
  }

  # Secrets Manager — API keys for threat intel
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:cognitive-soc/*"]
  }
}

resource "aws_iam_policy" "lambda_permissions" {
  name   = "cognitive-soc-lambda-policy-${var.environment}"
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

resource "aws_iam_role_policy_attachment" "lambda_permissions" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_permissions.arn
}

output "lambda_exec_role_arn" {
  value = aws_iam_role.lambda_exec.arn
}

variable "environment" { type = string }
variable "account_id" { type = string }
variable "aws_region" { type = string }
