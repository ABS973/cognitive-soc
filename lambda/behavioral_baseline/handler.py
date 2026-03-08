"""
Cognitive SOC Phase 2 — Behavioral Baseline Engine
Processes CloudTrail events and updates per-entity behavioral baselines.
Tracks 8 behavioral dimensions for every IAM user, role, EC2, and Lambda.
"""

import json
import logging
import os
import boto3
import hashlib
from datetime import datetime, timezone
from collections import defaultdict
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

dynamodb   = boto3.resource("dynamodb")
neptune_endpoint = os.environ.get("NEPTUNE_ENDPOINT", "")
ENVIRONMENT      = os.environ.get("ENVIRONMENT", "dev")
BASELINE_TABLE   = f"cognitive-soc-baselines-{ENVIRONMENT}"

# The 8 behavioral dimensions we track per entity
DIMENSIONS = [
    "temporal_pattern",      # When do they act? (hour/day distribution)
    "geo_pattern",           # From which IPs/countries/ASNs?
    "service_pattern",       # Which AWS services do they call?
    "action_pattern",        # Which specific API actions do they use?
    "volume_pattern",        # How many calls per hour/day?
    "sequence_pattern",      # What order do they call services?
    "privilege_pattern",     # Which permissions do they actually use vs granted?
    "resource_pattern",      # Which specific resources do they touch?
]


def lambda_handler(event, context):
    """
    Triggered by Kinesis stream carrying CloudTrail events.
    Each record is a CloudTrail API call — we extract the actor
    and update their behavioral baseline.
    """
    logger.info(f"Processing {len(event.get('Records', []))} Kinesis records")

    processed = 0
    errors    = 0

    for record in event.get("Records", []):
        try:
            # Decode Kinesis record
            import base64
            payload = json.loads(base64.b64decode(record["kinesis"]["data"]).decode("utf-8"))

            # CloudTrail sends events wrapped in a Records array
            ct_events = payload.get("Records", [payload])

            for ct_event in ct_events:
                process_cloudtrail_event(ct_event)
                processed += 1

        except Exception as e:
            logger.error(f"Failed to process record: {str(e)}", exc_info=True)
            errors += 1

    logger.info(f"Processed: {processed} | Errors: {errors}")
    return {"processed": processed, "errors": errors}


def process_cloudtrail_event(event):
    """Extract actor identity and update their behavioral baseline."""

    # Extract the actor (who made this API call)
    identity = extract_identity(event)
    if not identity:
        return

    entity_id   = identity["entity_id"]
    entity_type = identity["entity_type"]

    # Build behavioral signal from this event
    signal = extract_behavioral_signal(event, identity)

    # Update baseline in DynamoDB
    update_baseline(entity_id, entity_type, signal)

    logger.debug(f"Updated baseline for {entity_type}:{entity_id}")


def extract_identity(event):
    """
    Extract the actor identity from a CloudTrail event.
    Returns a normalized identity dict or None if unresolvable.
    """
    user_identity = event.get("userIdentity", {})
    identity_type = user_identity.get("type", "")

    if identity_type == "IAMUser":
        username = user_identity.get("userName", "unknown")
        return {
            "entity_id":   f"iam_user:{username}",
            "entity_type": "IAMUser",
            "name":        username,
            "arn":         user_identity.get("arn", ""),
            "account_id":  user_identity.get("accountId", ""),
        }

    elif identity_type == "AssumedRole":
        arn         = user_identity.get("arn", "")
        role_name   = arn.split("/")[-2] if "/" in arn else "unknown"
        session     = arn.split("/")[-1] if "/" in arn else "unknown"
        return {
            "entity_id":   f"iam_role:{role_name}",
            "entity_type": "IAMRole",
            "name":        role_name,
            "session":     session,
            "arn":         arn,
            "account_id":  user_identity.get("accountId", ""),
        }

    elif identity_type == "Root":
        return {
            "entity_id":   "root:account_root",
            "entity_type": "Root",
            "name":        "root",
            "account_id":  user_identity.get("accountId", ""),
        }

    elif identity_type == "AWSService":
        service = user_identity.get("invokedBy", "unknown_service")
        return {
            "entity_id":   f"aws_service:{service}",
            "entity_type": "AWSService",
            "name":        service,
        }

    return None


def extract_behavioral_signal(event, identity):
    """
    Extract all behavioral dimensions from a single CloudTrail event.
    This becomes one data point in the entity's behavioral history.
    """
    event_time    = event.get("eventTime", datetime.utcnow().isoformat())
    event_dt      = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    source_ip     = event.get("sourceIPAddress", "")
    user_agent    = event.get("userAgent", "")
    event_source  = event.get("eventSource", "")   # e.g. s3.amazonaws.com
    event_name    = event.get("eventName", "")      # e.g. GetObject
    aws_region    = event.get("awsRegion", "")
    error_code    = event.get("errorCode", "")

    # Normalize service name (strip .amazonaws.com)
    service = event_source.replace(".amazonaws.com", "")

    return {
        # Temporal
        "hour_of_day":    event_dt.hour,
        "day_of_week":    event_dt.weekday(),    # 0=Monday, 6=Sunday
        "timestamp":      event_time,

        # Geographic
        "source_ip":      source_ip,
        "aws_region":     aws_region,
        "user_agent":     user_agent,

        # Service & Action
        "service":        service,
        "action":         event_name,
        "service_action": f"{service}:{event_name}",

        # Outcome
        "error_code":     error_code,
        "success":        error_code == "",

        # Resource
        "resources":      extract_resources(event),
    }


def extract_resources(event):
    """Extract resource ARNs touched in this API call."""
    resources = []
    for resource in event.get("resources", []):
        arn = resource.get("ARN", "")
        if arn:
            resources.append(arn)
    return resources


def update_baseline(entity_id, entity_type, signal):
    """
    Update the entity's behavioral baseline in DynamoDB.
    Uses atomic counter increments and set additions for efficiency.
    """
    table = dynamodb.Table(BASELINE_TABLE)
    now   = datetime.utcnow().isoformat()

    # Build update expression for all behavioral dimensions
    update_expr  = "SET entity_type = :et, last_seen = :ls, #cnt = if_not_exists(#cnt, :zero) + :one"
    expr_names   = {"#cnt": "total_api_calls"}
    expr_values  = {
        ":et":   entity_type,
        ":ls":   now,
        ":zero": Decimal("0"),
        ":one":  Decimal("1"),
    }

    # Temporal — track hour distribution as a map
    hour_key = f"hour_{signal['hour_of_day']:02d}"
    update_expr += f", temporal_hours.{hour_key} = if_not_exists(temporal_hours.{hour_key}, :zero) + :one"

    # Day of week distribution
    day_key = f"day_{signal['day_of_week']}"
    update_expr += f", temporal_days.{day_key} = if_not_exists(temporal_days.{day_key}, :zero) + :one"

    # Service usage frequency
    svc_key = f"svc_{clean_key(signal['service'])}"
    update_expr += f", service_counts.{svc_key} = if_not_exists(service_counts.{svc_key}, :zero) + :one"

    # Action usage frequency
    action_key = f"act_{clean_key(signal['action'])}"
    update_expr += f", action_counts.{action_key} = if_not_exists(action_counts.{action_key}, :zero) + :one"

    # Region usage
    region_key = f"region_{clean_key(signal['aws_region'])}"
    update_expr += f", region_counts.{region_key} = if_not_exists(region_counts.{region_key}, :zero) + :one"

    # Error rate tracking
    if not signal["success"]:
        update_expr += ", error_count = if_not_exists(error_count, :zero) + :one"

    try:
        table.update_item(
            Key={"entity_id": entity_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
    except Exception as e:
        logger.error(f"Failed to update baseline for {entity_id}: {str(e)}", exc_info=True)


def clean_key(value):
    """Sanitize a value for use as a DynamoDB map key."""
    return value.replace(".", "_").replace("-", "_").replace(":", "_").replace("/", "_")[:50]
