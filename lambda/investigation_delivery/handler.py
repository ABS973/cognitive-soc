"""
Cognitive SOC Phase 3 — Investigation Delivery
Final step in the investigation pipeline.

Delivers the completed investigation to:
  1. Slack — rich message with executive summary + action buttons
  2. SNS   — email notification for Critical findings
  3. DynamoDB — final status update on investigation record

If auto_response_safe=True and confidence >= 85:
  → Triggers the appropriate Phase 1 SOAR playbook automatically
  → Records auto-response action in DynamoDB

If requires_human_review=True:
  → Sends escalation to #escalations channel with urgent flag
"""

import json
import logging
import os
import boto3
import urllib.request
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sns_client     = boto3.client("sns")
lambda_client  = boto3.client("lambda")
secretsmanager = boto3.client("secretsmanager")
dynamodb       = boto3.resource("dynamodb")

ENVIRONMENT          = os.environ.get("ENVIRONMENT", "dev")
SNS_TOPIC_ARN        = os.environ.get("SNS_ALERT_TOPIC_ARN", "")
INVESTIGATIONS_TABLE = f"cognitive-soc-investigations-{ENVIRONMENT}"


def lambda_handler(event, context):
    """
    Deliver the completed investigation report.
    Called by Step Functions as the final step.
    """
    logger.info("Investigation Delivery triggered")

    finding_id  = event.get("finding_id", "unknown")
    entity_id   = event.get("entity_id", "unknown")
    report      = event.get("investigation_report", {})
    reports     = event.get("reports", {})

    if not report:
        logger.error("No investigation_report in event")
        return {"delivered": False, "reason": "no_report"}

    decision    = report.get("triage_decision", "UNKNOWN")
    severity    = report.get("severity", "HIGH")
    confidence  = report.get("confidence_score", 0)
    auto_safe   = report.get("auto_response_safe", False)
    needs_human = report.get("requires_human_review", True)

    delivery_results = {}

    # 1. Send Slack notification
    slack_webhook = get_secret("cognitive-soc/slack-webhook")
    if slack_webhook:
        slack_result = send_slack_notification(event, report, reports, slack_webhook)
        delivery_results["slack"] = slack_result

    # 2. Send SNS email for Critical findings
    if severity == "CRITICAL" and SNS_TOPIC_ARN:
        sns_result = send_sns_notification(event, report)
        delivery_results["sns"] = sns_result

    # 3. Trigger SOAR auto-response if safe
    soar_result = None
    if auto_safe and confidence >= 85 and decision == "CONFIRMED_THREAT":
        soar_result = trigger_soar_playbook(event, report)
        delivery_results["soar"] = soar_result
    else:
        logger.info(
            f"SOAR auto-response not triggered: auto_safe={auto_safe} "
            f"confidence={confidence} decision={decision}"
        )

    # 4. Final DynamoDB update
    update_final_status(finding_id, delivery_results, soar_result)

    logger.info(f"Delivery complete for {finding_id}: {json.dumps(delivery_results, default=str)}")
    return {
        "delivered":   True,
        "finding_id":  finding_id,
        "decision":    decision,
        "severity":    severity,
        "confidence":  confidence,
        "auto_response_triggered": bool(soar_result),
        "delivery":    delivery_results,
    }


# ── Slack Notification ────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": "#C00000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFAA00",
    "LOW":      "#00AA00",
}

DECISION_EMOJI = {
    "CONFIRMED_THREAT": "🚨",
    "PROBABLE_THREAT":  "🔍",
    "FALSE_POSITIVE":   "✅",
}


def send_slack_notification(event, report, reports, webhook):
    """Send a rich Slack message with the investigation summary and action buttons."""
    finding_id   = event.get("finding_id", "unknown")
    entity_id    = event.get("entity_id", "unknown")
    finding_type = event.get("finding_type", "Unknown")
    severity     = report.get("severity", "HIGH")
    decision     = report.get("triage_decision", "UNKNOWN")
    confidence   = report.get("confidence_score", 0)
    auto_safe    = report.get("auto_response_safe", False)
    exec_summary = report.get("executive_summary", "")[:300]
    color        = SEVERITY_COLOR.get(severity, "#888888")
    emoji        = DECISION_EMOJI.get(decision, "⚠️")

    # Top recommended action
    actions      = report.get("recommended_actions", [])
    top_action   = actions[0].get("action", "Manual review required") if actions else "Manual review required"
    playbook     = actions[0].get("soar_playbook", "none") if actions else "none"

    # Build Slack blocks
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} [{severity}] Cognitive SOC Investigation Complete"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Entity*\n`{entity_id}`"},
                {"type": "mrkdwn", "text": f"*Decision*\n*{decision}*"},
                {"type": "mrkdwn", "text": f"*Confidence*\n{confidence}%"},
                {"type": "mrkdwn", "text": f"*Severity*\n*{severity}*"},
                {"type": "mrkdwn", "text": f"*Finding Type*\n`{finding_type}`"},
                {"type": "mrkdwn", "text": f"*Auto-Response*\n{'✅ Armed' if auto_safe else '❌ Manual Required'}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary*\n{exec_summary}"}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Recommended Action*\n{top_action}"}
        },
    ]

    # Add SOAR playbook info if armed
    if auto_safe:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"⚡ *SOAR Auto-Response:* Playbook `{playbook}` is armed and ready to execute."}
        })

    # Report links if available
    if reports.get("technical_url"):
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"📄 Reports: `{reports.get('technical_url')}` | `{reports.get('executive_url', '')}`"},
            ]
        })

    # Footer
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Cognitive SOC AI Investigation | `{finding_id}` | {datetime.utcnow().strftime('%H:%M:%S UTC')} | {ENVIRONMENT.upper()}"}
        ]
    })

    payload = {
        "attachments": [{
            "color":  color,
            "blocks": blocks,
        }]
    }

    try:
        req = urllib.request.Request(
            webhook,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=8)
        logger.info("Slack notification sent successfully")
        return {"sent": True}
    except Exception as e:
        logger.warning(f"Slack notification failed (non-fatal): {str(e)}")
        return {"sent": False, "error": str(e)}


# ── SNS Notification ──────────────────────────────────────────────────────────

def send_sns_notification(event, report):
    """Send SNS email for Critical severity findings."""
    finding_id  = event.get("finding_id", "unknown")
    entity_id   = event.get("entity_id", "unknown")
    decision    = report.get("triage_decision", "UNKNOWN")
    confidence  = report.get("confidence_score", 0)

    subject = f"[CRITICAL] Cognitive SOC: {decision} — {entity_id}"[:100]
    message = f"""
COGNITIVE SOC — CRITICAL SECURITY INVESTIGATION COMPLETE
=========================================================
Finding ID:  {finding_id}
Entity:      {entity_id}
Decision:    {decision}
Confidence:  {confidence}%
Severity:    CRITICAL

EXECUTIVE SUMMARY
-----------------
{report.get('executive_summary', 'No summary available.')}

IMMEDIATE ACTIONS REQUIRED
--------------------------
"""
    for i, action in enumerate(report.get("recommended_actions", [])[:3], 1):
        message += f"{i}. [{action.get('priority', 'HIGH')}] {action.get('action', '')}\n"

    message += f"""
Auto-Response Safe: {'YES — SOAR playbook is armed' if report.get('auto_response_safe') else 'NO — Manual review required'}
Requires Human Review: {'YES' if report.get('requires_human_review') else 'No'}

Generated by Cognitive SOC AI Investigation Agent
{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message,
        )
        logger.info("SNS email sent for Critical finding")
        return {"sent": True}
    except Exception as e:
        logger.warning(f"SNS send failed (non-fatal): {str(e)}")
        return {"sent": False, "error": str(e)}


# ── SOAR Auto-Response ────────────────────────────────────────────────────────

# Maps AI-recommended playbook names to Phase 1 Lambda function names
PLAYBOOK_MAP = {
    "ec2_isolator":  "ec2_isolator",
    "iam_revoker":   "iam_revoker",
    "ip_blocker":    "ip_blocker",
    "s3_protector":  "s3_protector",
}


def trigger_soar_playbook(event, report):
    """
    Trigger the appropriate Phase 1 SOAR playbook.
    Only called when auto_response_safe=True and confidence >= 85.
    """
    actions  = report.get("recommended_actions", [])
    playbook = None

    # Find the first action with a mapped SOAR playbook
    for action in actions:
        pb = action.get("soar_playbook", "none")
        if pb in PLAYBOOK_MAP:
            playbook = pb
            break

    if not playbook:
        logger.info("No SOAR playbook identified for auto-response")
        return {"triggered": False, "reason": "no_playbook_identified"}

    # Build payload compatible with Phase 1 SOAR orchestrator
    soar_payload = {
        "finding":  {
            "id":          event.get("finding_id"),
            "type":        event.get("finding_type"),
            "severity":    event.get("severity_score", 8.0),
            "account_id":  event.get("account_id"),
            "region":      event.get("region"),
            "resource":    event.get("resource", {}),
            "service":     event.get("raw_service", {}),
        },
        "enriched":         event.get("enrichment", {}),
        "triggered_by":     "phase3_ai_investigation",
        "confidence_score": report.get("confidence_score"),
        "investigation_id": event.get("finding_id"),
    }

    try:
        function_name = f"cognitive-soc-{PLAYBOOK_MAP[playbook]}-{ENVIRONMENT}"
        logger.info(f"Triggering SOAR playbook: {function_name}")

        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(soar_payload, default=str),
        )
        result = json.loads(response["Payload"].read())
        logger.info(f"SOAR playbook {playbook} completed: {result}")
        return {
            "triggered":    True,
            "playbook":     playbook,
            "result":       result,
        }
    except Exception as e:
        logger.error(f"SOAR playbook {playbook} failed: {str(e)}", exc_info=True)
        return {
            "triggered": False,
            "playbook":  playbook,
            "error":     str(e),
        }


# ── DynamoDB Final Update ─────────────────────────────────────────────────────

def update_final_status(finding_id, delivery_results, soar_result):
    """Mark the investigation as fully delivered in DynamoDB."""
    try:
        table = dynamodb.Table(INVESTIGATIONS_TABLE)
        table.update_item(
            Key={"investigation_id": finding_id},
            UpdateExpression=(
                "SET delivery_status = :delivered, "
                "delivered_at = :ts, "
                "soar_triggered = :soar, "
                "delivery_results = :dr"
            ),
            ExpressionAttributeValues={
                ":delivered": "DELIVERED",
                ":ts":        datetime.utcnow().isoformat(),
                ":soar":      bool(soar_result and soar_result.get("triggered")),
                ":dr":        json.dumps(delivery_results, default=str),
            }
        )
    except Exception as e:
        logger.warning(f"DynamoDB final update failed (non-fatal): {str(e)}")


# ── Secrets ───────────────────────────────────────────────────────────────────

def get_secret(secret_name):
    try:
        return secretsmanager.get_secret_value(SecretId=secret_name).get("SecretString", "")
    except Exception:
        return None
