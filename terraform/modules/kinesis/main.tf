# ─── Kinesis Data Stream ─────────────────────────────────────────
resource "aws_kinesis_stream" "cloudtrail" {
  name             = "cognitive-soc-cloudtrail-${var.environment}"
  shard_count      = 1  # Scale up in production
  retention_period = 24 # Hours

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"

  tags = { Name = "cognitive-soc-cloudtrail-${var.environment}" }
}

# ─── CloudTrail → Kinesis ────────────────────────────────────────
resource "aws_cloudtrail" "main" {
  name                          = "cognitive-soc-trail-${var.environment}"
  s3_bucket_name                = var.cloudtrail_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  tags = { Name = "cognitive-soc-trail-${var.environment}" }
}

# ─── Lambda Event Source Mapping (Kinesis → CloudTrail Processor) ─
resource "aws_lambda_event_source_mapping" "kinesis_processor" {
  event_source_arn              = aws_kinesis_stream.cloudtrail.arn
  function_name                 = var.cloudtrail_processor_lambda_arn
  starting_position             = "LATEST"
  batch_size                    = 100
  parallelization_factor        = 2
  bisect_batch_on_function_error = true

  destination_config {
    on_failure {
      destination_arn = var.sns_alert_topic_arn
    }
  }
}

output "kinesis_stream_arn"  { value = aws_kinesis_stream.cloudtrail.arn }
output "kinesis_stream_name" { value = aws_kinesis_stream.cloudtrail.name }

variable "environment"                    { type = string }
variable "cloudtrail_bucket_name"         { type = string }
variable "cloudtrail_processor_lambda_arn"{ type = string }
variable "sns_alert_topic_arn"            { type = string }
