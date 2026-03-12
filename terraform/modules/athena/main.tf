# ──────────────────────────────────────────────────────────────────────────────
# Cognitive SOC Phase 3 — Athena CloudTrail Query Engine
# Serverless SQL over CloudTrail logs stored in S3
# ──────────────────────────────────────────────────────────────────────────────

variable "environment"          { type = string }
variable "cloudtrail_bucket"    { type = string   description = "S3 bucket where CloudTrail logs are stored" }
variable "cloudtrail_prefix"    { type = string   default = "AWSLogs"   description = "S3 prefix for CloudTrail logs" }
variable "athena_results_bucket" { type = string  description = "S3 bucket for Athena query results" }

locals {
  name   = "cognitive-soc-${var.environment}"
  db     = "cognitive_soc_cloudtrail_${var.environment}"
}

# ── S3 Bucket for Athena Results ─────────────────────────────────────────────

resource "aws_s3_bucket" "athena_results" {
  bucket        = var.athena_results_bucket
  force_destroy = var.environment == "dev"

  tags = {
    Environment = var.environment
    Project     = "cognitive-soc"
    Phase       = "3"
    Purpose     = "athena-query-results"
  }
}

resource "aws_s3_bucket_versioning" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "expire-old-results"
    status = "Enabled"
    expiration { days = 30 }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Athena Workgroup ──────────────────────────────────────────────────────────

resource "aws_athena_workgroup" "cognitive_soc" {
  name  = "${local.name}-workgroup"
  state = "ENABLED"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = 10737418240  # 10 GB hard limit per query

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/phase3-investigations/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = {
    Environment = var.environment
    Project     = "cognitive-soc"
    Phase       = "3"
  }
}

# ── Glue Database for CloudTrail ──────────────────────────────────────────────

resource "aws_glue_catalog_database" "cloudtrail" {
  name        = local.db
  description = "Cognitive SOC CloudTrail forensic analysis database"
}

# ── Glue Table — CloudTrail Logs Schema ──────────────────────────────────────
# This schema matches the standard CloudTrail log format from AWS

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.cloudtrail.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"           = "cloudtrail"
    "projection.enabled"       = "true"
    "projection.timestamp.type"   = "date"
    "projection.timestamp.range"  = "2024/01/01,NOW"
    "projection.timestamp.format" = "yyyy/MM/dd"
    "projection.timestamp.interval"       = "1"
    "projection.timestamp.interval.unit"  = "DAYS"
    "storage.location.template" = "s3://${var.cloudtrail_bucket}/${var.cloudtrail_prefix}/$${timestamp}/"
    "serialization.format"     = "1"
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_bucket}/${var.cloudtrail_prefix}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
      parameters = { "serialization.format" = "1" }
    }

    # CloudTrail log schema — key fields for security investigation
    columns {
      name = "eventversion"   type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }
    columns {
      name = "eventtime"         type = "string"
    }
    columns {
      name = "eventsource"       type = "string"
    }
    columns {
      name = "eventname"         type = "string"
    }
    columns {
      name = "awsregion"         type = "string"
    }
    columns {
      name = "sourceipaddress"   type = "string"
    }
    columns {
      name = "useragent"         type = "string"
    }
    columns {
      name = "errorcode"         type = "string"
    }
    columns {
      name = "errormessage"      type = "string"
    }
    columns {
      name = "requestparameters" type = "string"
    }
    columns {
      name = "responseelements"  type = "string"
    }
    columns {
      name = "additionaleventdata" type = "string"
    }
    columns {
      name = "requestid"         type = "string"
    }
    columns {
      name = "eventid"           type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"         type = "string"
    }
    columns {
      name = "apiversion"        type = "string"
    }
    columns {
      name = "readonly"          type = "string"
    }
    columns {
      name = "recipientaccountid" type = "string"
    }
    columns {
      name = "serviceeventdetails" type = "string"
    }
    columns {
      name = "sharedeventid"     type = "string"
    }
    columns {
      name = "vpcendpointid"     type = "string"
    }
  }

  # Partition projection on date for efficient queries
  partition_keys {
    name = "timestamp"
    type = "string"
  }
}

# ── Named Queries — Phase 3 Investigation Templates ──────────────────────────

resource "aws_athena_named_query" "entity_90day_history" {
  name      = "${local.name}-entity-90day-history"
  workgroup = aws_athena_workgroup.cognitive_soc.name
  database  = aws_glue_catalog_database.cloudtrail.name
  description = "Phase 3: Get 90-day CloudTrail history for a specific entity"

  query = <<-SQL
    SELECT
        eventtime,
        eventname,
        eventsource,
        sourceipaddress,
        awsregion,
        errorcode,
        errormessage,
        useridentity.type        AS identity_type,
        useridentity.arn         AS identity_arn,
        useridentity.username    AS username,
        requestparameters,
        responseelements
    FROM ${local.db}.cloudtrail_logs
    WHERE (
        useridentity.arn LIKE '%REPLACE_WITH_ENTITY_ID%'
        OR useridentity.username = 'REPLACE_WITH_ENTITY_ID'
        OR useridentity.principalid LIKE '%REPLACE_WITH_ENTITY_ID%'
    )
    AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '90' day
    ORDER BY eventtime DESC
    LIMIT 200
  SQL
}

resource "aws_athena_named_query" "privilege_escalation_hunt" {
  name      = "${local.name}-privilege-escalation-hunt"
  workgroup = aws_athena_workgroup.cognitive_soc.name
  database  = aws_glue_catalog_database.cloudtrail.name
  description = "Phase 3: Hunt for privilege escalation patterns in the last 7 days"

  query = <<-SQL
    SELECT
        eventtime,
        useridentity.arn        AS entity,
        eventname,
        eventsource,
        sourceipaddress,
        errorcode
    FROM ${local.db}.cloudtrail_logs
    WHERE eventsource IN ('iam.amazonaws.com', 'sts.amazonaws.com')
    AND eventname IN (
        'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile',
        'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
        'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
        'CreateRole', 'AssumeRole', 'AddUserToGroup',
        'UpdateAssumeRolePolicy', 'SetDefaultPolicyVersion'
    )
    AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
    ORDER BY eventtime DESC
    LIMIT 500
  SQL
}

resource "aws_athena_named_query" "data_exfiltration_hunt" {
  name      = "${local.name}-data-exfiltration-hunt"
  workgroup = aws_athena_workgroup.cognitive_soc.name
  database  = aws_glue_catalog_database.cloudtrail.name
  description = "Phase 3: Hunt for S3 data exfiltration patterns"

  query = <<-SQL
    SELECT
        eventtime,
        useridentity.arn        AS entity,
        eventname,
        sourceipaddress,
        awsregion,
        requestparameters
    FROM ${local.db}.cloudtrail_logs
    WHERE eventsource = 's3.amazonaws.com'
    AND eventname IN ('GetObject', 'ListBuckets', 'ListObjects', 'ListObjectsV2',
                      'PutBucketPolicy', 'PutBucketAcl', 'DeleteBucketPolicy')
    AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '24' hour
    ORDER BY eventtime DESC
    LIMIT 1000
  SQL
}

resource "aws_athena_named_query" "cloudtrail_disruption_hunt" {
  name      = "${local.name}-cloudtrail-disruption-hunt"
  workgroup = aws_athena_workgroup.cognitive_soc.name
  database  = aws_glue_catalog_database.cloudtrail.name
  description = "Phase 3: Detect attempts to disable or disrupt CloudTrail logging"

  query = <<-SQL
    SELECT
        eventtime,
        useridentity.arn        AS entity,
        eventname,
        sourceipaddress,
        errorcode
    FROM ${local.db}.cloudtrail_logs
    WHERE eventsource = 'cloudtrail.amazonaws.com'
    AND eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail',
                      'PutEventSelectors', 'RemoveTags')
    AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
    ORDER BY eventtime DESC
  SQL
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "athena_database_name" {
  value       = aws_glue_catalog_database.cloudtrail.name
  description = "Glue/Athena database name for CloudTrail queries"
}

output "athena_workgroup_name" {
  value       = aws_athena_workgroup.cognitive_soc.name
  description = "Athena workgroup name"
}

output "athena_results_bucket" {
  value       = aws_s3_bucket.athena_results.bucket
  description = "S3 bucket for Athena query results"
}
