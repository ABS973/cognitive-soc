"""
Cognitive SOC Phase 2 — CloudTrail Processor
Ingests raw CloudTrail events from Kinesis and fans out to:
1. Behavioral Baseline engine (update the entity's fingerprint)
2. Anomaly Scorer (score this event against the baseline)
3. Identity Graph Updater (update Neptune graph relationships)

This is the entry point for all Phase 2 processing.
"""

import json
import logging
import os
import base64
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

lambda_client = boto3.client("lambda")
ENVIRONMENT   = os.environ.get("ENVIRONMENT", "dev")

# Actions to SKIP (AWS internal noise — not useful for behavioral analysis)
SKIP_EVENT_SOURCES = {
    "health.amazonaws.com",
    "support.amazonaws.com",
    "trustedadvisor.amazonaws.com",
}

SKIP_EVENT_NAMES = {
    "LookupEvents",  # CloudTrail itself
    "DescribeEventAggregates",
    "ListHealthEvents",
}


def lambda_handler(event, context):
    """Process Kinesis records containing CloudTrail events."""
    logger.info(f"CloudTrail processor received {len(event.get('Records', []))} records")

    stats = {"total": 0, "processed": 0, "skipped": 0, "errors": 0}

    for record in event.get("Records", []):
        try:
            payload      = json.loads(base64.b64decode(record["kinesis"]["data"]).decode("utf-8"))
            ct_events    = payload.get("Records", [payload])

            for ct_event in ct_events:
                stats["total"] += 1

                if should_skip(ct_event):
                    stats["skipped"] += 1
                    continue

                process_event(ct_event)
                stats["processed"] += 1

        except Exception as e:
            logger.error(f"Record processing failed: {str(e)}", exc_info=True)
            stats["errors"] += 1

    logger.info(f"Stats: {stats}")
    return stats


def should_skip(event):
    """Filter out noise events not useful for behavioral analysis."""
    event_source = event.get("eventSource", "")
    event_name   = event.get("eventName", "")

    if event_source in SKIP_EVENT_SOURCES:
        return True
    if event_name in SKIP_EVENT_NAMES:
        return True

    # Skip read-only events from AWS services acting on your behalf
    user_identity = event.get("userIdentity", {})
    if user_identity.get("type") == "AWSService":
        event_lower = event_name.lower()
        # Keep sensitive AWS service actions
        if not any(event_lower.startswith(p) for p in ["create", "delete", "put", "attach", "modify"]):
            return True

    return False


def process_event(ct_event):
    """Fan out a CloudTrail event to all Phase 2 processors."""
    # Extract identity for routing
    identity = extract_identity(ct_event)
    if not identity:
        return

    signal = extract_signal(ct_event, identity)

    # 1. Update behavioral baseline (async — fire and forget)
    lambda_client.invoke(
        FunctionName=f"cognitive-soc-behavioral_baseline-{ENVIRONMENT}",
        InvocationType="Event",
        Payload=json.dumps({
            "Records": [{
                "kinesis": {
                    "data": base64.b64encode(
                        json.dumps({"Records": [ct_event]}).encode()
                    ).decode()
                }
            }]
        })
    )

    # 2. Score for anomalies (async)
    lambda_client.invoke(
        FunctionName=f"cognitive-soc-anomaly_scorer-{ENVIRONMENT}",
        InvocationType="Event",
        Payload=json.dumps({
            "entity_id":   identity["entity_id"],
            "entity_type": identity["entity_type"],
            "signal":      signal,
        })
    )

    # 3. Update identity graph (async)
    lambda_client.invoke(
        FunctionName=f"cognitive-soc-identity_graph_updater-{ENVIRONMENT}",
        InvocationType="Event",
        Payload=json.dumps({
            "identity": identity,
            "signal":   signal,
            "event":    ct_event,
        })
    )


def extract_identity(event):
    """Extract normalized identity from CloudTrail event."""
    ui   = event.get("userIdentity", {})
    itype = ui.get("type", "")

    if itype == "IAMUser":
        name = ui.get("userName", "unknown")
        return {"entity_id": f"iam_user:{name}", "entity_type": "IAMUser", "name": name}
    elif itype == "AssumedRole":
        arn       = ui.get("arn", "")
        role_name = arn.split("/")[-2] if arn.count("/") >= 2 else "unknown"
        return {"entity_id": f"iam_role:{role_name}", "entity_type": "IAMRole", "name": role_name}
    elif itype == "Root":
        return {"entity_id": "root:account_root", "entity_type": "Root", "name": "root"}

    return None


def extract_signal(event, identity):
    """Extract behavioral signal from a CloudTrail event."""
    event_time = event.get("eventTime", datetime.utcnow().isoformat())
    try:
        from datetime import timezone
        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        hour_of_day  = dt.hour
        day_of_week  = dt.weekday()
    except Exception:
        hour_of_day  = 0
        day_of_week  = 0

    service = event.get("eventSource", "").replace(".amazonaws.com", "")

    return {
        "hour_of_day":    hour_of_day,
        "day_of_week":    day_of_week,
        "timestamp":      event_time,
        "source_ip":      event.get("sourceIPAddress", ""),
        "aws_region":     event.get("awsRegion", ""),
        "user_agent":     event.get("userAgent", ""),
        "service":        service,
        "action":         event.get("eventName", ""),
        "service_action": f"{service}:{event.get('eventName', '')}",
        "error_code":     event.get("errorCode", ""),
        "success":        event.get("errorCode", "") == "",
        "resources":      [r.get("ARN", "") for r in event.get("resources", [])],
    }
