"""
Cognitive SOC Phase 3 — Alert Ingestor
Entry point for the AI Investigation pipeline.

Receives findings from two sources:
  1. GuardDuty findings (via EventBridge) — same format as Phase 1
  2. Behavioral anomaly alerts (from Phase 2 anomaly_scorer)

For every High/Critical finding, it:
  - Normalises the finding to a standard investigation schema
  - Attaches Phase 1 enrichment (MITRE mapping, IP reputation)
  - Attaches Phase 2 context (behavioral deviation scores)
  - Triggers the Step Functions investigation workflow
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sfn_client    = boto3.client("stepfunctions")
lambda_client = boto3.client("lambda")
dynamodb      = boto3.resource("dynamodb")

ENVIRONMENT       = os.environ.get("ENVIRONMENT", "dev")
SFN_ARN           = os.environ.get("INVESTIGATION_SFN_ARN", "")
INVESTIGATION_TABLE = f"cognitive-soc-investigations-{ENVIRONMENT}"

# Minimum severity to trigger AI investigation
# GuardDuty scale: 0-10. 7.0+ = High, 8.9+ = Critical
MIN_SEVERITY_GUARDDUTY  = float(os.environ.get("MIN_SEVERITY_GUARDDUTY", "7.0"))

# Behavioral DNA scale: 0-100. 70+ = Medium, 85+ = High, 95+ = Critical
MIN_SCORE_BEHAVIORAL    = float(os.environ.get("MIN_SCORE_BEHAVIORAL", "85.0"))


def lambda_handler(event, context):
    """
    Normalise incoming finding and trigger the Step Functions investigation.
    Called by EventBridge for GuardDuty findings, or directly by anomaly_scorer.
    """
    logger.info("Alert Ingestor triggered")
    logger.debug(f"Raw event: {json.dumps(event, default=str)}")

    try:
        source = detect_source(event)
        logger.info(f"Finding source: {source}")

        if source == "guardduty":
            finding = normalise_guardduty(event)
        elif source == "behavioral":
            finding = normalise_behavioral(event)
        else:
            logger.warning(f"Unknown event source — skipping")
            return {"triggered": False, "reason": "unknown_source"}

        # Severity gate — only investigate High/Critical
        if not meets_threshold(finding):
            logger.info(
                f"Finding below investigation threshold: "
                f"severity={finding['severity_score']} source={source}"
            )
            return {"triggered": False, "reason": "below_threshold", "finding_id": finding["finding_id"]}

        # Enrich with Phase 1 threat intel (MITRE + IP reputation)
        enrichment = invoke_enrichment(finding)
        finding["enrichment"] = enrichment

        # Persist investigation record to DynamoDB (status: QUEUED)
        record_investigation(finding)

        # Trigger Step Functions workflow
        execution_arn = start_investigation(finding)

        logger.info(f"Investigation started: {execution_arn} for finding {finding['finding_id']}")
        return {
            "triggered":      True,
            "finding_id":     finding["finding_id"],
            "severity":       finding["severity_label"],
            "execution_arn":  execution_arn,
        }

    except Exception as e:
        logger.error(f"Alert Ingestor failed: {str(e)}", exc_info=True)
        raise


# ── Source Detection ────────────────────────────────────────────────────────

def detect_source(event):
    """Determine if this is a GuardDuty EventBridge event or a behavioral alert."""
    # GuardDuty via EventBridge always has detail-type
    if event.get("detail-type") == "GuardDuty Finding":
        return "guardduty"
    # Behavioral alert has anomaly_result set by anomaly_scorer
    if event.get("anomaly_result") or event.get("source") == "cognitive_soc_behavioral_dna":
        return "behavioral"
    # Direct finding dict (used in testing)
    if event.get("type", "").startswith("BehavioralAnomaly"):
        return "behavioral"
    if "detail" in event:
        return "guardduty"
    return "unknown"


# ── Normalisation ───────────────────────────────────────────────────────────

def normalise_guardduty(event):
    """Normalise a GuardDuty EventBridge event into the standard investigation schema."""
    detail = event.get("detail", {})

    # Extract entity information from the finding resource block
    resource     = detail.get("resource", {})
    service      = detail.get("service", {})
    entity_id, entity_type = extract_entity(resource, service)

    severity_raw   = float(detail.get("severity", 0))
    severity_label = guardduty_severity_label(severity_raw)

    return {
        "finding_id":       detail.get("id", f"gd-{int(datetime.utcnow().timestamp())}"),
        "finding_type":     detail.get("type", "Unknown"),
        "source":           "guardduty",
        "severity_score":   severity_raw,          # 0-10 scale
        "severity_label":   severity_label,
        "account_id":       detail.get("accountId", ""),
        "region":           detail.get("region", ""),
        "title":            detail.get("title", ""),
        "description":      detail.get("description", ""),
        "entity_id":        entity_id,
        "entity_type":      entity_type,
        "resource":         resource,
        "raw_service":      service,
        "created_at":       detail.get("createdAt", datetime.utcnow().isoformat()),
        "ingested_at":      datetime.utcnow().isoformat(),
        "behavioral_scores": {},   # Will be populated if Phase 2 data exists
    }


def normalise_behavioral(event):
    """Normalise a Phase 2 behavioral anomaly alert into the investigation schema."""
    finding        = event.get("finding", event)   # Handle both wrapped and direct
    anomaly        = event.get("anomaly_result", {})
    entity_id      = anomaly.get("entity_id", finding.get("entity_id", "unknown"))
    score          = float(anomaly.get("composite_score", 0))

    return {
        "finding_id":       finding.get("id", f"beh-{entity_id}-{int(datetime.utcnow().timestamp())}"),
        "finding_type":     "BehavioralAnomaly:IAMUser/DeviationFromBaseline",
        "source":           "behavioral_dna",
        "severity_score":   score,                 # 0-100 scale
        "severity_label":   anomaly.get("severity", behavioral_severity_label(score)),
        "account_id":       finding.get("account_id", ""),
        "region":           anomaly.get("signal", {}).get("aws_region", ""),
        "title":            finding.get("title", f"Behavioral anomaly: {entity_id}"),
        "description":      finding.get("description", ""),
        "entity_id":        entity_id,
        "entity_type":      "IAMUser",
        "resource":         finding.get("resource", {}),
        "raw_service":      finding.get("service", {}),
        "created_at":       anomaly.get("timestamp", datetime.utcnow().isoformat()),
        "ingested_at":      datetime.utcnow().isoformat(),
        "behavioral_scores": anomaly.get("dimension_scores", {}),
        "behavioral_composite": score,
        "behavioral_observations": anomaly.get("observations", 0),
    }


# ── Severity ─────────────────────────────────────────────────────────────────

def meets_threshold(finding):
    """Return True if this finding crosses the investigation threshold."""
    source = finding["source"]
    score  = finding["severity_score"]

    if source == "guardduty":
        return score >= MIN_SEVERITY_GUARDDUTY
    elif source == "behavioral_dna":
        return score >= MIN_SCORE_BEHAVIORAL
    return False


def guardduty_severity_label(severity):
    if severity >= 8.9: return "CRITICAL"
    if severity >= 7.0: return "HIGH"
    if severity >= 4.0: return "MEDIUM"
    return "LOW"


def behavioral_severity_label(score):
    if score >= 95: return "CRITICAL"
    if score >= 85: return "HIGH"
    if score >= 70: return "MEDIUM"
    return "LOW"


# ── Entity Extraction ────────────────────────────────────────────────────────

def extract_entity(resource, service):
    """
    Extract the primary entity (IAM user, EC2 instance, S3 bucket)
    from the GuardDuty resource block.
    """
    resource_type = resource.get("resourceType", "")

    if resource_type == "AccessKey":
        user_detail = resource.get("accessKeyDetails", {})
        return user_detail.get("userName", "unknown"), "IAMUser"

    if resource_type == "Instance":
        instance = resource.get("instanceDetails", {})
        return instance.get("instanceId", "unknown"), "EC2Instance"

    if resource_type == "S3Bucket":
        buckets = resource.get("s3BucketDetails", [{}])
        return buckets[0].get("name", "unknown"), "S3Bucket"

    # Fallback: extract from API call action
    api_action = service.get("action", {}).get("awsApiCallAction", {})
    if api_action:
        caller = api_action.get("callerType", "")
        return caller or "unknown", "APICallEntity"

    return "unknown", "Unknown"


# ── Enrichment ───────────────────────────────────────────────────────────────

def invoke_enrichment(finding):
    """
    Call the Phase 1 enrichment Lambda for MITRE + IP reputation.
    Non-fatal — if enrichment fails, investigation still proceeds.
    """
    try:
        response = lambda_client.invoke(
            FunctionName=f"cognitive-soc-enrichment-{ENVIRONMENT}",
            InvocationType="RequestResponse",
            Payload=json.dumps({
                "type":     finding["finding_type"],
                "resource": finding["resource"],
                "service":  finding["raw_service"],
                "severity": finding["severity_score"],
            })
        )
        result = json.loads(response["Payload"].read())
        logger.info(f"Enrichment: {result.get('summary', 'no summary')}")
        return result
    except Exception as e:
        logger.warning(f"Enrichment failed (non-fatal): {str(e)}")
        return {"enriched": False, "reason": str(e)}


# ── DynamoDB ─────────────────────────────────────────────────────────────────

def record_investigation(finding):
    """Create investigation record in DynamoDB with status QUEUED."""
    try:
        table = dynamodb.Table(INVESTIGATION_TABLE)
        table.put_item(Item={
            "investigation_id": finding["finding_id"],
            "created_at":       finding["ingested_at"],
            "finding_type":     finding["finding_type"],
            "entity_id":        finding["entity_id"],
            "entity_type":      finding["entity_type"],
            "severity":         finding["severity_label"],
            "severity_score":   str(finding["severity_score"]),
            "source":           finding["source"],
            "status":           "QUEUED",
            "account_id":       finding["account_id"],
            "region":           finding["region"],
            "ttl":              int(datetime.utcnow().timestamp()) + (90 * 24 * 3600),
        })
    except Exception as e:
        logger.warning(f"DynamoDB record failed (non-fatal): {str(e)}")


# ── Step Functions ────────────────────────────────────────────────────────────

def start_investigation(finding):
    """Trigger the Step Functions investigation state machine."""
    if not SFN_ARN:
        raise ValueError("INVESTIGATION_SFN_ARN environment variable not set")

    execution_name = f"inv-{finding['finding_id'][:40]}-{int(datetime.utcnow().timestamp())}"
    # Step Functions execution names only allow alphanumeric, hyphens, underscores
    execution_name = execution_name.replace(":", "-").replace("/", "-")[:80]

    response = sfn_client.start_execution(
        stateMachineArn=SFN_ARN,
        name=execution_name,
        input=json.dumps(finding, default=str),
    )
    return response["executionArn"]

# Expose utility for testing


def is_private_ip(ip):
    """Return True if IP is RFC1918 private or loopback."""
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "169.254.")
    return any(ip.startswith(p) for p in private_prefixes)
