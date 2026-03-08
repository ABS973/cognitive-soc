"""
Cognitive SOC — Notifier Lambda
Sends alerts to SNS (email) + Slack + PagerDuty.
"""
import json, logging, os, boto3, urllib.request
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
sns_client     = boto3.client("sns")
secretsmanager = boto3.client("secretsmanager")
SNS_TOPIC_ARN  = os.environ["SNS_ALERT_TOPIC_ARN"]
ENVIRONMENT    = os.environ.get("ENVIRONMENT", "dev")
EMOJI          = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

def lambda_handler(event, context):
    finding        = event.get("finding", {})
    enriched       = event.get("enriched", {})
    playbook_result= event.get("playbook_result", {})
    label          = enriched.get("severity_context", {}).get("label", "UNKNOWN")
    emoji          = EMOJI.get(label, "⚠️")

    send_sns(finding, enriched, playbook_result, emoji, label)

    webhook = get_secret("cognitive-soc/slack-webhook")
    if webhook:
        send_slack(finding, enriched, playbook_result, emoji, label, webhook)

    if event.get("escalate") and label in ("CRITICAL", "HIGH"):
        pd_key = get_secret("cognitive-soc/pagerduty-routing-key")
        if pd_key:
            send_pagerduty(finding, enriched, pd_key)

    return {"notified": True}

def send_sns(finding, enriched, result, emoji, label):
    attack  = enriched.get("attack_mapping", {})
    actions = ", ".join(result.get("actions_taken", ["none"]))
    subject = f"{emoji} [{label}] Cognitive SOC: {finding.get('type','Unknown')}"[:100]
    message = f"""COGNITIVE SOC ALERT
Severity:     {label}
Finding Type: {finding.get('type','Unknown')}
Account:      {finding.get('account_id','Unknown')}
Region:       {finding.get('region','Unknown')}
ATT&CK:       {attack.get('tactic','Unknown')} — {attack.get('technique','')}
Actions Taken:{actions}
Summary:      {enriched.get('summary','')}
Finding ID:   {finding.get('id','Unknown')}"""
    sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)

def send_slack(finding, enriched, result, emoji, label, webhook):
    attack  = enriched.get("attack_mapping", {})
    ip_rep  = enriched.get("ip_reputation", {})
    actions = result.get("actions_taken", [])
    blocks  = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} Cognitive SOC — {label}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Finding*\n{finding.get('type','Unknown')}"},
            {"type": "mrkdwn", "text": f"*Severity*\n{label} ({finding.get('severity',0)})"},
            {"type": "mrkdwn", "text": f"*Account*\n{finding.get('account_id','Unknown')}"},
            {"type": "mrkdwn", "text": f"*Region*\n{finding.get('region','Unknown')}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*ATT&CK Tactic*\n{attack.get('tactic','Unknown')}"},
            {"type": "mrkdwn", "text": f"*Technique*\n{attack.get('technique','')}"},
        ]},
    ]
    if ip_rep.get("ip"):
        flag = "🔴 KNOWN MALICIOUS" if ip_rep.get("is_known_malicious") else "✅ Clean"
        blocks.append({"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Source IP*\n{ip_rep['ip']}"},
            {"type": "mrkdwn", "text": f"*Reputation*\n{flag}"},
        ]})
    if actions:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": "*🤖 Automated Actions*\n" + "\n".join([f"• `{a}`" for a in actions])}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
        "text": f"ID: `{finding.get('id','?')}` | {ENVIRONMENT.upper()} | {datetime.utcnow().strftime('%H:%M:%S UTC')}"}]})
    try:
        req = urllib.request.Request(webhook, data=json.dumps({"blocks": blocks}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning(f"Slack failed (non-fatal): {e}")

def send_pagerduty(finding, enriched, key):
    payload = {"routing_key": key, "event_action": "trigger",
               "dedup_key": finding.get("id","unknown"),
               "payload": {"summary": enriched.get("summary", finding.get("type","")),
                           "severity": "critical", "source": f"CognitiveSoc-{ENVIRONMENT}"}}
    try:
        req = urllib.request.Request("https://events.pagerduty.com/v2/enqueue",
            data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning(f"PagerDuty failed (non-fatal): {e}")

def get_secret(name):
    try:
        return secretsmanager.get_secret_value(SecretId=name).get("SecretString","")
    except Exception:
        return None
