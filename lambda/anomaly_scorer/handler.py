"""
Cognitive SOC Phase 2 — Anomaly Scorer
Scores every new CloudTrail event against the entity's behavioral baseline.
Uses a multi-model ensemble:
  1. Statistical deviation scoring (Z-score on distributions)
  2. Unseen behavior detection (new services/regions/actions)
  3. Temporal anomaly detection (unusual time patterns)
  4. Peer comparison (deviation from team/role cluster)

Emits a composite anomaly score 0-100.
Score >= 70 → Medium alert
Score >= 85 → High alert
Score >= 95 → Critical alert
"""

import json
import logging
import os
import boto3
import math
from datetime import datetime
from decimal import Decimal

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

dynamodb        = boto3.resource("dynamodb")
lambda_client   = boto3.client("lambda")
ENVIRONMENT     = os.environ.get("ENVIRONMENT", "dev")
BASELINE_TABLE  = f"cognitive-soc-baselines-{ENVIRONMENT}"

# Scoring thresholds
THRESHOLD_MEDIUM   = 70
THRESHOLD_HIGH     = 85
THRESHOLD_CRITICAL = 95

# Minimum observations before scoring (avoid false positives on new entities)
MIN_OBSERVATIONS = 100


def lambda_handler(event, context):
    """
    Score a new CloudTrail event against the entity's behavioral baseline.
    Called by the CloudTrail processor for every API call.
    """
    entity_id   = event.get("entity_id")
    entity_type = event.get("entity_type")
    signal      = event.get("signal", {})

    if not entity_id or not signal:
        return {"scored": False, "reason": "missing_entity_id_or_signal"}

    # Fetch entity's baseline
    baseline = get_baseline(entity_id)

    if not baseline:
        logger.debug(f"No baseline yet for {entity_id} — skipping scoring")
        return {"scored": False, "reason": "no_baseline"}

    total_calls = int(baseline.get("total_api_calls", 0))
    if total_calls < MIN_OBSERVATIONS:
        logger.debug(f"Insufficient observations for {entity_id}: {total_calls}/{MIN_OBSERVATIONS}")
        return {"scored": False, "reason": "insufficient_observations", "observations": total_calls}

    # Run all anomaly detection models
    scores = {
        "temporal_score":   score_temporal_anomaly(signal, baseline),
        "geo_score":        score_geo_anomaly(signal, baseline),
        "service_score":    score_service_anomaly(signal, baseline),
        "action_score":     score_action_anomaly(signal, baseline),
        "sequence_score":   score_sequence_anomaly(signal, baseline),
    }

    # Weighted composite score
    composite = calculate_composite_score(scores)

    result = {
        "scored":       True,
        "entity_id":    entity_id,
        "entity_type":  entity_type,
        "composite_score": composite,
        "dimension_scores": scores,
        "severity":     get_severity(composite),
        "signal":       signal,
        "timestamp":    datetime.utcnow().isoformat(),
        "observations": total_calls,
    }

    logger.info(f"Anomaly score for {entity_id}: {composite:.1f} ({result['severity']})")

    # Trigger alert if score exceeds threshold
    if composite >= THRESHOLD_MEDIUM:
        trigger_behavioral_alert(result, baseline)

    return result


def get_baseline(entity_id):
    """Fetch entity baseline from DynamoDB."""
    try:
        table    = dynamodb.Table(BASELINE_TABLE)
        response = table.get_item(Key={"entity_id": entity_id})
        return response.get("Item")
    except Exception as e:
        logger.error(f"Failed to fetch baseline for {entity_id}: {str(e)}")
        return None


def score_temporal_anomaly(signal, baseline):
    """
    Score how unusual the TIME of this action is for this entity.
    Uses the entity's historical hour/day distribution.
    Returns 0-100 (100 = most anomalous).
    """
    hour    = signal.get("hour_of_day", 0)
    day     = signal.get("day_of_week", 0)
    total   = float(baseline.get("total_api_calls", 1))

    # Get historical hour distribution
    temporal_hours = baseline.get("temporal_hours", {})
    hour_key       = f"hour_{hour:02d}"
    hour_count     = float(temporal_hours.get(hour_key, 0))
    hour_frequency = hour_count / total

    # If this hour has never been seen → very anomalous
    if hour_count == 0:
        return 95.0

    # Expected frequency for this hour (uniform = 1/24 ≈ 0.042)
    # If actual frequency is much lower than expected, it's anomalous
    expected_min_frequency = 1 / 24 / 3  # 3x less than uniform = suspicious
    if hour_frequency < expected_min_frequency:
        # Scale anomaly: lower frequency = higher score
        score = min(90, (expected_min_frequency / hour_frequency) * 20)
        return score

    return max(0, (1 - hour_frequency * 24) * 30)


def score_geo_anomaly(signal, baseline):
    """
    Score how unusual the SOURCE REGION is for this entity.
    New regions = high anomaly. Rare regions = medium anomaly.
    """
    aws_region = signal.get("aws_region", "")
    total      = float(baseline.get("total_api_calls", 1))

    region_counts = baseline.get("region_counts", {})
    region_key    = f"region_{aws_region.replace('-', '_')}"
    region_count  = float(region_counts.get(region_key, 0))

    # Region never seen before
    if region_count == 0:
        return 90.0

    region_frequency = region_count / total

    # Rarely used region
    if region_frequency < 0.02:  # Less than 2% of activity
        return 70.0
    elif region_frequency < 0.05:
        return 50.0

    return 0.0


def score_service_anomaly(signal, baseline):
    """
    Score how unusual the AWS SERVICE being called is for this entity.
    """
    service = signal.get("service", "")
    total   = float(baseline.get("total_api_calls", 1))

    service_counts = baseline.get("service_counts", {})
    service_key    = f"svc_{service.replace('.', '_').replace('-', '_')}"
    service_count  = float(service_counts.get(service_key, 0))

    # Service never called before
    if service_count == 0:
        # Higher score for sensitive services
        sensitive_services = {"iam", "sts", "kms", "secretsmanager", "ssm", "cloudtrail", "organizations"}
        if service in sensitive_services:
            return 95.0
        return 75.0

    service_frequency = service_count / total
    if service_frequency < 0.01:  # Less than 1% of calls
        return 60.0

    return 0.0


def score_action_anomaly(signal, baseline):
    """
    Score how unusual the specific API ACTION is for this entity.
    Sensitive actions (Create*, Delete*, Put*) get higher base scores.
    """
    action = signal.get("action", "")
    total  = float(baseline.get("total_api_calls", 1))

    action_counts = baseline.get("action_counts", {})
    action_key    = f"act_{action}"
    action_count  = float(action_counts.get(action_key, 0))

    # Determine base sensitivity of this action
    action_lower = action.lower()
    if any(action_lower.startswith(p) for p in ["create", "delete", "put", "attach", "detach", "revoke"]):
        sensitivity_bonus = 20
    elif any(action_lower.startswith(p) for p in ["list", "describe", "get"]):
        sensitivity_bonus = 5
    else:
        sensitivity_bonus = 10

    # Action never performed before
    if action_count == 0:
        return min(100, 70 + sensitivity_bonus)

    action_frequency = action_count / total
    if action_frequency < 0.005:  # Very rare action
        return min(100, 55 + sensitivity_bonus)

    return 0.0


def score_sequence_anomaly(signal, baseline):
    """
    Score sequence anomalies — is this action happening in an unusual context?
    E.g., iam:CreateAccessKey happening right after iam:ListUsers is suspicious.
    Simple implementation: checks if error rate is unusually high (recon pattern).
    """
    error_count = float(baseline.get("error_count", 0))
    total       = float(baseline.get("total_api_calls", 1))
    error_rate  = error_count / total

    # High error rate can indicate credential stuffing or permission probing
    if error_rate > 0.3 and not signal.get("success", True):
        return 65.0

    return 0.0


def calculate_composite_score(scores):
    """
    Weighted composite score across all dimensions.
    Temporal and service anomalies are weighted highest.
    """
    weights = {
        "temporal_score":  0.25,
        "geo_score":       0.20,
        "service_score":   0.25,
        "action_score":    0.20,
        "sequence_score":  0.10,
    }

    composite = sum(scores.get(k, 0) * w for k, w in weights.items())

    # Boost score if MULTIPLE dimensions are anomalous simultaneously
    anomalous_dimensions = sum(1 for v in scores.values() if v >= 50)
    if anomalous_dimensions >= 3:
        composite = min(100, composite * 1.3)
    elif anomalous_dimensions >= 2:
        composite = min(100, composite * 1.15)

    return round(composite, 2)


def get_severity(score):
    """Convert numeric score to severity label."""
    if score >= THRESHOLD_CRITICAL:
        return "CRITICAL"
    elif score >= THRESHOLD_HIGH:
        return "HIGH"
    elif score >= THRESHOLD_MEDIUM:
        return "MEDIUM"
    else:
        return "NORMAL"


def trigger_behavioral_alert(result, baseline):
    """
    Send anomalous behavior to the Phase 1 alert pipeline.
    Creates a synthetic finding compatible with the SOAR orchestrator.
    """
    logger.info(f"Triggering behavioral alert for {result['entity_id']} — score: {result['composite_score']}")

    synthetic_finding = {
        "id":          f"behavioral-{result['entity_id']}-{int(datetime.utcnow().timestamp())}",
        "type":        "BehavioralAnomaly:IAMUser/DeviationFromBaseline",
        "severity":    score_to_guardduty_severity(result["composite_score"]),
        "account_id":  "behavioral_engine",
        "region":      result["signal"].get("aws_region", "unknown"),
        "title":       f"Behavioral DNA anomaly detected for {result['entity_id']}",
        "description": build_alert_description(result),
        "resource":    {"behavioralDetails": result},
        "service":     {"action": {"actionType": "BEHAVIORAL_ANOMALY"}},
        "created_at":  result["timestamp"],
        "source":      "cognitive_soc_behavioral_dna",
    }

    # Send to notifier Lambda directly
    lambda_client.invoke(
        FunctionName=f"cognitive-soc-behavioral_alert-{ENVIRONMENT}",
        InvocationType="Event",
        Payload=json.dumps({
            "finding":        synthetic_finding,
            "anomaly_result": result,
            "escalate":       result["severity"] in ("CRITICAL", "HIGH"),
        })
    )


def score_to_guardduty_severity(score):
    """Map anomaly score to GuardDuty-compatible severity scale (0-10)."""
    if score >= THRESHOLD_CRITICAL:
        return 8.9
    elif score >= THRESHOLD_HIGH:
        return 7.0
    elif score >= THRESHOLD_MEDIUM:
        return 5.0
    return 2.0


def build_alert_description(result):
    """Build human-readable description of the behavioral anomaly."""
    scores   = result["dimension_scores"]
    signal   = result["signal"]
    entity   = result["entity_id"]

    anomalies = []
    if scores.get("temporal_score", 0) >= 50:
        hour = signal.get("hour_of_day", "?")
        anomalies.append(f"unusual time of activity (hour {hour:02d}:00 UTC)" if isinstance(hour, int) else "unusual time of activity")
    if scores.get("geo_score", 0) >= 50:
        anomalies.append(f"activity from unusual region ({signal.get('aws_region', 'unknown')})")
    if scores.get("service_score", 0) >= 50:
        anomalies.append(f"first-time access to {signal.get('service', 'unknown')} service")
    if scores.get("action_score", 0) >= 50:
        anomalies.append(f"unusual API action: {signal.get('action', 'unknown')}")

    anomaly_str = "; ".join(anomalies) if anomalies else "multiple behavioral deviations detected"

    return (
        f"Behavioral DNA anomaly detected for {entity}. "
        f"Composite anomaly score: {result['composite_score']:.1f}/100. "
        f"Anomalies: {anomaly_str}. "
        f"Based on analysis of {result['observations']} historical API calls."
    )
