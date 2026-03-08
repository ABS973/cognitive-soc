"""
Cognitive SOC — Notifier Lambda
Sends formatted security alerts to:
- Slack (rich block messages)
- SNS (email/SMS)
- PagerDuty (for critical findings)
"""

import json
import logging
import os
import boto3
import urllib.request
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sns_client = boto3.client("sns")
secretsmanager = boto3.client("secretsmanager")

SNS_ALERT_TOPIC_ARN = os.environ["SNS_ALERT_TOPIC_ARN"]
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟠",
    "LOW":      "🟡",
}


def lambda_handler(event, context):
    finding = event.get("finding", {})
    enriched = event.get("enriched", {})
    playbook_result = event.get("playbook_result", {})
    escalate = event.get("escalate", False)

    severity_context = enriched.get("severity_context", {})
    severity_label = severity_context.get("label", "UNKNOWN")
    emoji = SEVERITY_EMOJI.get(severity_label, "⚠️")

    actions = playbook_result.get("actions_taken", [])
    actions_str = ", ".join(actions) if actions else "None"

    # Send to SNS (email)
    send_sns_alert(finding, enriched, playbook_result, emoji, severity_label)

    # Send to Slack if webhook configured
    slack_webhook = get_secret("cognitive-soc/slack-webhook")
    if slack_webhook:
        send_slack_alert(finding, enriched, playbook_result, emoji, severity_label, slack_webhook)

    # Send to PagerDuty for critical findings
    if escalate and severity_label in ("CRITICAL", "HIGH"):
        pd_key = get_secret("cognitive-soc/pagerduty-routing-key")
        if pd_key:
            send_pagerduty_alert(finding, enriched, pd_key)

    return {"notified": True, "channels": ["sns", "slack" if slack_webhook else "none"]}


def send_sns_alert(finding, enriched, playbook_result, emoji, severity_label):
    """Send alert to SNS topic (delivers to email subscribers)."""
    attack = enriched.get("attack_mapping", {})
    actions = ", ".join(playbook_result.get("actions_taken", ["none"]))

    subject = f"{emoji} [{severity_label}] Cognitive SOC Alert: {finding.get('type', 'Unknown')}"
    message = f"""
COGNITIVE SOC — SECURITY ALERT
================================
Severity:     {severity_label}
Finding Type: {finding.get('type', 'Unknown')}
Account:      {finding.get('account_id', 'Unknown')}
Region:       {finding.get('region', 'Unknown')}
Detected At:  {finding.get('created_at', 'Unknown')}

DESCRIPTION
-----------
{finding.get('description', 'No description available')}

MITRE ATT&CK
------------
Tactic:    {attack.get('tactic', 'Unknown')}
Technique: {attack.get('technique', 'Unknown')} — {attack.get('name', 'Unknown')}

AUTOMATED RESPONSE
------------------
Actions Taken: {actions}

ENRICHMENT
----------
Summary: {enriched.get('summary', 'No enrichment available')}

Finding ID: {finding.get('id', 'Unknown')}
Environment: {ENVIRONMENT.upper()}
"""

    sns_client.publish(
        TopicArn=SNS_ALERT_TOPIC_ARN,
        Subject=subject[:100],  # SNS subject limit
        Message=message
    )
    logger.info(f"SNS alert sent for finding {finding.get('id')}")


def send_slack_alert(finding, enriched, playbook_result, emoji, severity_label, webhook_url):
    """Send rich formatted alert to Slack."""
    attack = enriched.get("attack_mapping", {})
    ip_rep = enriched.get("ip_reputation", {})
    severity_context = enriched.get("severity_context", {})
    actions = playbook_result.get("actions_taken", [])

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Cognitive SOC Alert — {severity_label}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Finding Type*\n{finding.get('type', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Severity*\n{severity_label} ({finding.get('severity', 0)})"},
                {"type": "mrkdwn", "text": f"*Account*\n{finding.get('account_id', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Region*\n{finding.get('region', 'Unknown')}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description*\n{finding.get('description', 'N/A')}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*ATT&CK Tactic*\n{attack.get('tactic', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*ATT&CK Technique*\n{attack.get('technique', 'Unknown')} — {attack.get('name', '')}"},
            ]
        },
    ]

    # Add IP reputation block if available
    if ip_rep.get("ip"):
        malicious_flag = "🔴 KNOWN MALICIOUS" if ip_rep.get("is_known_malicious") else "✅ No reports"
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Source IP*\n{ip_rep['ip']}"},
                {"type": "mrkdwn", "text": f"*IP Reputation*\n{malicious_flag} (AbuseScore: {ip_rep.get('confidence_score', 0)}%)"},
                {"type": "mrkdwn", "text": f"*Country*\n{ip_rep.get('country', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*ISP*\n{ip_rep.get('isp', 'Unknown')}"},
            ]
        })

    # Add automated response block
    if actions:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*🤖 Automated Response*\n" + "\n".join([f"• `{a}`" for a in actions])}
        })

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Finding ID: `{finding.get('id', 'unknown')}` | {ENVIRONMENT.upper()} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"}
        ]
    })

    payload = json.dumps({"blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            logger.info(f"Slack alert sent: {response.status}")
    except Exception as e:
        logger.warning(f"Slack notification failed (non-fatal): {str(e)}")


def send_pagerduty_alert(finding, enriched, routing_key):
    """Trigger a PagerDuty incident for critical findings."""
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": finding.get("id", "unknown"),
        "payload": {
            "summary": enriched.get("summary", finding.get("type", "Security Alert")),
            "severity": "critical" if enriched.get("severity_context", {}).get("label") == "CRITICAL" else "error",
            "source": f"CognitiveSoc-{ENVIRONMENT}",
            "custom_details": {
                "finding_type": finding.get("type"),
                "account_id": finding.get("account_id"),
                "region": finding.get("region"),
                "finding_id": finding.get("id"),
            }
        }
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://events.pagerduty.com/v2/enqueue",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            logger.info(f"PagerDuty alert triggered: {response.status}")
    except Exception as e:
        logger.warning(f"PagerDuty alert failed (non-fatal): {str(e)}")


def get_secret(secret_name):
    """Retrieve a secret from AWS Secrets Manager."""
    try:
        response = secretsmanager.get_secret_value(SecretId=secret_name)
        return response.get("SecretString", "")
    except Exception:
        return None
