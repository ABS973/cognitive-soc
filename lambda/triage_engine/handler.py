"""
Cognitive SOC Phase 3 — Triage Engine
False positive classifier and investigation priority assignment.

Analyses each alert against:
  - Entity's triage history (how often does this entity trigger similar alerts?)
  - Behavioral context (did Phase 2 confirm anomalous behavior?)
  - Alert frequency (is this alert firing too often to be real?)
  - Time context (is this during normal business hours from a known location?)

Outputs one of three decisions:
  INVESTIGATE   → full AI investigation needed
  MONITOR       → log and watch, skip full investigation for now
  DISMISS       → high confidence false positive, suppress

Also assigns investigation priority: CRITICAL / HIGH / MEDIUM
"""

import json
import logging
import os
import boto3
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

dynamodb    = boto3.resource("dynamodb")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

TRIAGE_TABLE    = f"cognitive-soc-triage-history-{ENVIRONMENT}"
INCIDENTS_TABLE = f"cognitive-soc-incidents-{ENVIRONMENT}"

# False positive score thresholds
FP_DISMISS_THRESHOLD  = 70   # Score >= 70 → dismiss
FP_MONITOR_THRESHOLD  = 45   # Score 45-69 → monitor


def lambda_handler(event, context):
    """
    Classify a finding as INVESTIGATE / MONITOR / DISMISS.
    Called by Step Functions as step 2 of the investigation workflow.
    Input: normalised finding dict from alert_ingestor.
    """
    logger.info("Triage Engine triggered")

    finding    = event
    finding_id = finding.get("finding_id", "unknown")
    entity_id  = finding.get("entity_id", "unknown")
    severity   = finding.get("severity_label", "HIGH")

    # CRITICAL findings always get investigated regardless of FP score
    if severity == "CRITICAL":
        logger.info(f"CRITICAL finding {finding_id} — bypassing FP check, INVESTIGATE immediately")
        return build_result(finding, "INVESTIGATE", "CRITICAL", 0, "Critical severity bypasses FP filter")

    # Run false positive scoring
    fp_score, fp_reasons = calculate_fp_score(finding)
    logger.info(f"FP score for {entity_id}: {fp_score} ({'; '.join(fp_reasons)})")

    # Make triage decision
    if fp_score >= FP_DISMISS_THRESHOLD:
        decision = "DISMISS"
    elif fp_score >= FP_MONITOR_THRESHOLD:
        decision = "MONITOR"
    else:
        decision = "INVESTIGATE"

    # Assign investigation priority
    priority = assign_priority(finding, fp_score, decision)

    # Record triage decision for future FP learning
    record_triage_decision(finding, decision, fp_score)

    result = build_result(finding, decision, priority, fp_score, "; ".join(fp_reasons))
    logger.info(f"Triage decision for {finding_id}: {decision} (priority={priority}, fp_score={fp_score})")
    return result


# ── False Positive Scoring ───────────────────────────────────────────────────

def calculate_fp_score(finding):
    """
    Calculate false positive probability score (0-100).
    Higher score = more likely to be a false positive.
    Returns (score, list_of_reasons).
    """
    score   = 0
    reasons = []

    entity_id    = finding.get("entity_id", "unknown")
    finding_type = finding.get("finding_type", "")
    severity     = finding.get("severity_label", "HIGH")
    behavioral   = finding.get("behavioral_scores", {})
    behavioral_composite = float(finding.get("behavioral_composite", 0))

    # ── Rule 1: Repeated alert with no confirmed threat (+40) ──────────────
    repeat_count = get_repeat_alert_count(entity_id, finding_type, days=30)
    if repeat_count >= 5:
        score   += 40
        reasons.append(f"alert type repeated {repeat_count}x in 30 days with no confirmed threat")
    elif repeat_count >= 3:
        score   += 20
        reasons.append(f"alert type repeated {repeat_count}x in 30 days")

    # ── Rule 2: Business hours + known geo (GuardDuty only) (+20) ──────────
    if finding.get("source") == "guardduty":
        ingested = finding.get("ingested_at", datetime.utcnow().isoformat())
        if is_business_hours_utc(ingested):
            score   += 15
            reasons.append("activity during typical business hours (UTC)")

    # ── Rule 3: No IOC matches in enrichment (+15) ─────────────────────────
    enrichment = finding.get("enrichment", {})
    ip_rep     = enrichment.get("ip_reputation", {})
    if enrichment.get("enriched") and not ip_rep.get("is_known_malicious", False):
        score   += 15
        reasons.append("no known malicious IOC indicators found")

    # ── Rule 4: Behavioral DNA CONFIRMS anomaly (-30 to score) ────────────
    # If Phase 2 says behavior is anomalous, this is LESS likely to be FP
    if behavioral_composite >= 85:
        score   = max(0, score - 30)
        reasons.append(f"Behavioral DNA confirms anomaly (score={behavioral_composite:.0f}) — reducing FP likelihood")
    elif behavioral_composite >= 70:
        score   = max(0, score - 15)
        reasons.append(f"Behavioral DNA shows deviation (score={behavioral_composite:.0f})")

    # ── Rule 5: Known low-noise finding types ──────────────────────────────
    noisy_types = {
        "Recon:EC2/PortProbeUnprotectedPort",
        "Recon:EC2/PortProbeEMRUnprotectedPort",
        "UnauthorizedAccess:EC2/TorIPCaller",
        "UnauthorizedAccess:EC2/TorClient",
    }
    if finding_type in noisy_types:
        score   += 20
        reasons.append(f"{finding_type} is a historically high-noise finding type")

    # ── Rule 6: HIGH confidence IOC → definitely not FP (-50) ─────────────
    if ip_rep.get("confidence_score", 0) >= 80:
        score   = max(0, score - 50)
        reasons.append(f"IOC confidence {ip_rep['confidence_score']}% — strong malicious indicator")

    # Cap at 100
    score = min(100, score)

    if not reasons:
        reasons.append("no false positive indicators found")

    return score, reasons


def get_repeat_alert_count(entity_id, finding_type, days=30):
    """Count how many times this entity has triggered this alert type in the last N days."""
    try:
        table    = dynamodb.Table(TRIAGE_TABLE)
        response = table.get_item(Key={"entity_id": entity_id, "finding_type": finding_type})
        item     = response.get("Item", {})
        return int(item.get("no_threat_count", 0))
    except Exception as e:
        logger.debug(f"Triage history lookup failed (non-fatal): {str(e)}")
        return 0


def is_business_hours_utc(timestamp_str):
    """Return True if timestamp falls in 07:00-19:00 UTC Mon-Fri."""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return dt.weekday() < 5 and 7 <= dt.hour < 19
    except Exception:
        return False


# ── Priority Assignment ──────────────────────────────────────────────────────

def assign_priority(finding, fp_score, decision):
    """Assign investigation priority based on severity + FP score + behavioral data."""
    if decision == "DISMISS":
        return "LOW"

    severity   = finding.get("severity_label", "HIGH")
    behavioral = float(finding.get("behavioral_composite", 0))

    if severity == "CRITICAL" or (severity == "HIGH" and behavioral >= 85):
        return "CRITICAL"
    if severity == "HIGH" or (severity == "MEDIUM" and behavioral >= 70):
        return "HIGH"
    if severity == "MEDIUM":
        return "MEDIUM"
    return "LOW"


# ── DynamoDB ─────────────────────────────────────────────────────────────────

def record_triage_decision(finding, decision, fp_score):
    """
    Update triage history for this entity + finding type.
    Used by Rule 1 in future triage decisions.
    """
    try:
        entity_id    = finding.get("entity_id", "unknown")
        finding_type = finding.get("finding_type", "unknown")
        table        = dynamodb.Table(TRIAGE_TABLE)

        if decision in ("DISMISS", "MONITOR"):
            # Increment no_threat_count
            table.update_item(
                Key={"entity_id": entity_id, "finding_type": finding_type},
                UpdateExpression="ADD no_threat_count :inc SET last_seen = :ts",
                ExpressionAttributeValues={
                    ":inc": 1,
                    ":ts":  datetime.utcnow().isoformat(),
                }
            )
        else:
            # Reset no_threat_count when we decide to investigate
            table.update_item(
                Key={"entity_id": entity_id, "finding_type": finding_type},
                UpdateExpression="SET no_threat_count = :zero, last_investigated = :ts",
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":ts":   datetime.utcnow().isoformat(),
                }
            )
    except Exception as e:
        logger.debug(f"Triage history update failed (non-fatal): {str(e)}")


# ── Result Builder ────────────────────────────────────────────────────────────

def build_result(finding, decision, priority, fp_score, fp_reason):
    """Build the triage result dict passed to Step Functions next state."""
    return {
        **finding,                        # Pass all finding fields through
        "triage_decision":   decision,
        "triage_priority":   priority,
        "fp_score":          fp_score,
        "fp_reason":         fp_reason,
        "triage_timestamp":  datetime.utcnow().isoformat(),
        "proceed":           decision == "INVESTIGATE",
    }
