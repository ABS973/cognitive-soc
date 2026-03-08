data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service"; identifiers = ["lambda.amazonaws.com"] }
  }
}
resource "aws_iam_role" "lambda_exec" {
  name               = "cognitive-soc-lambda-exec-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}
data "aws_iam_policy_document" "perms" {
  statement { effect = "Allow"; actions = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]; resources = ["*"] }
  statement { effect = "Allow"; actions = ["guardduty:GetFindings","guardduty:ListFindings","guardduty:ArchiveFindings"]; resources = ["*"] }
  statement { effect = "Allow"; actions = ["ec2:DescribeInstances","ec2:DescribeSecurityGroups","ec2:ModifyInstanceAttribute","ec2:CreateSecurityGroup","ec2:RevokeSecurityGroupEgress","ec2:CreateSnapshot","ec2:CreateTags","ec2:StopInstances"]; resources = ["*"] }
  statement { effect = "Allow"; actions = ["iam:UpdateAccessKey","iam:ListAccessKeys","iam:PutUserPolicy","iam:TagUser"]; resources = ["*"] }
  statement { effect = "Allow"; actions = ["s3:PutBucketPublicAccessBlock","s3:PutBucketPolicy","s3:DeleteBucketPolicy","s3:PutBucketEncryption","s3:GetBucketPolicy","s3:GetBucketTagging","s3:PutBucketTagging"]; resources = ["*"] }
  statement { effect = "Allow"; actions = ["wafv2:GetIPSet","wafv2:UpdateIPSet","wafv2:ListIPSets","wafv2:CreateIPSet"]; resources = ["*"] }
  statement { effect = "Allow"; actions = ["sns:Publish"]; resources = ["arn:aws:sns:${var.aws_region}:${var.account_id}:cognitive-soc-*"] }
  statement { effect = "Allow"; actions = ["s3:PutObject","s3:GetObject"]; resources = ["arn:aws:s3:::cognitive-soc-findings-*/*"] }
  statement { effect = "Allow"; actions = ["dynamodb:PutItem","dynamodb:GetItem","dynamodb:UpdateItem","dynamodb:Query"]; resources = ["arn:aws:dynamodb:${var.aws_region}:${var.account_id}:table/cognitive-soc-*"] }
  statement { effect = "Allow"; actions = ["secretsmanager:GetSecretValue"]; resources = ["arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:cognitive-soc/*"] }
  statement { effect = "Allow"; actions = ["lambda:InvokeFunction"]; resources = ["arn:aws:lambda:${var.aws_region}:${var.account_id}:function:cognitive-soc-*"] }
}
resource "aws_iam_policy" "perms" {
  name   = "cognitive-soc-lambda-policy-${var.environment}"
  policy = data.aws_iam_policy_document.perms.json
}
resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.perms.arn
}
output "lambda_exec_role_arn" { value = aws_iam_role.lambda_exec.arn }
variable "environment" { type = string }
variable "account_id"  { type = string }
variable "aws_region"  { type = string }
