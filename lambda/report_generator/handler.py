"""
Cognitive SOC Phase 3 — Report Generator
Formats the Bedrock investigation JSON into two deliverable reports:

  1. Technical Report (Markdown)
     Full incident details for SOC analysts:
     - Executive summary
     - Attack timeline (ASCII table)
     - Behavioral evidence breakdown
     - MITRE ATT&CK chain
     - IOC findings
     - Affected resources
     - Recommended actions with SOAR playbook references

  2. Executive Summary (plain English, 3 paragraphs)
     For Ahmed / CISO / non-technical stakeholders.
     No jargon. What happened, how bad, what to do.

Both reports are stored in S3 and the paths are returned for delivery.
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3_client = boto3.client("s3")
dynamodb  = boto3.resource("dynamodb")

ENVIRONMENT        = os.environ.get("ENVIRONMENT", "dev")
REPORTS_BUCKET     = os.environ.get("REPORTS_BUCKET", f"cognitive-soc-reports-{ENVIRONMENT}")
INVESTIGATIONS_TABLE = f"cognitive-soc-investigations-{ENVIRONMENT}"


def lambda_handler(event, context):
    """
    Generate technical + executive reports and store them in S3.
    Called by Step Functions as step 6.
    """
    logger.info("Report Generator triggered")

    finding_id = event.get("finding_id", "unknown")
    report     = event.get("investigation_report", {})

    if not report:
        raise ValueError("No investigation_report found in event")

    entity_id  = event.get("entity_id", "unknown")
    account_id = event.get("account_id", "unknown")
    timestamp  = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # Generate both report formats
    technical_md  = generate_technical_report(event, report)
    executive_md  = generate_executive_summary(event, report)

    # Store in S3
    base_key      = f"{account_id}/{finding_id}/{timestamp}"
    technical_key = f"{base_key}-technical.md"
    executive_key = f"{base_key}-executive.md"

    store_report(technical_md, technical_key)
    store_report(executive_md, executive_key)

    # Update DynamoDB investigation record
    update_investigation_record(finding_id, report, technical_key, executive_key)

    logger.info(f"Reports generated for {finding_id}: s3://{REPORTS_BUCKET}/{base_key}")

    return {
        **event,
        "reports": {
            "technical_s3_key": technical_key,
            "executive_s3_key": executive_key,
            "bucket":           REPORTS_BUCKET,
            "technical_url":    f"s3://{REPORTS_BUCKET}/{technical_key}",
            "executive_url":    f"s3://{REPORTS_BUCKET}/{executive_key}",
        }
    }


# ── Technical Report ──────────────────────────────────────────────────────────

def generate_technical_report(event, report):
    """Generate the full Markdown technical report."""
    finding_type  = event.get("finding_type", "Unknown")
    entity_id     = event.get("entity_id", "unknown")
    severity      = report.get("severity", "HIGH")
    decision      = report.get("triage_decision", "UNKNOWN")
    confidence    = report.get("confidence_score", 0)
    timestamp     = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    finding_id    = event.get("finding_id", "unknown")

    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
    decision_icon = {"CONFIRMED_THREAT": "⚠️", "PROBABLE_THREAT": "🔍", "FALSE_POSITIVE": "✅"}.get(decision, "❓")

    lines = [
        f"# {severity_icon} Cognitive SOC — Incident Investigation Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Finding ID** | `{finding_id}` |",
        f"| **Generated** | {timestamp} |",
        f"| **Entity** | `{entity_id}` |",
        f"| **Finding Type** | `{finding_type}` |",
        f"| **Severity** | **{severity}** |",
        f"| **Triage Decision** | {decision_icon} **{decision}** |",
        f"| **AI Confidence** | {confidence}% |",
        f"| **Auto-Response Safe** | {'✅ Yes' if report.get('auto_response_safe') else '❌ No — Human Review Required'} |",
        f"| **Model** | `{report.get('model_used', 'claude-sonnet-4-6')}` |",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        report.get("executive_summary", "_No summary available._"),
        f"",
        f"---",
        f"",
        f"## What Happened",
        f"",
        report.get("what_happened", "_Investigation details unavailable._"),
        f"",
        f"---",
        f"",
    ]

    # Attack Timeline
    timeline = report.get("attack_timeline", [])
    if timeline:
        lines += [
            f"## Attack Timeline",
            f"",
            f"| Time | Action | Significance |",
            f"|---|---|---|",
        ]
        for event_item in timeline:
            time_val = str(event_item.get("time", "")).replace("|", "\\|")
            action   = str(event_item.get("action", "")).replace("|", "\\|")
            sig      = str(event_item.get("significance", "")).replace("|", "\\|")
            lines.append(f"| `{time_val}` | {action} | {sig} |")
        lines += ["", "---", ""]

    # MITRE ATT&CK Chain
    mitre = report.get("mitre_chain", [])
    if mitre:
        lines += [
            f"## MITRE ATT&CK Chain",
            f"",
            f"| Tactic | Technique | Name | Evidence |",
            f"|---|---|---|---|",
        ]
        for m in mitre:
            tactic  = str(m.get("tactic", "")).replace("|", "\\|")
            tech    = str(m.get("technique", "")).replace("|", "\\|")
            name    = str(m.get("technique_name", "")).replace("|", "\\|")
            evidence = str(m.get("evidence", "")).replace("|", "\\|")
            lines.append(f"| {tactic} | `{tech}` | {name} | {evidence} |")
        lines += ["", "---", ""]

    # Behavioral Evidence
    beh_evidence = report.get("behavioral_evidence", [])
    if beh_evidence:
        lines += [
            f"## Behavioral DNA Evidence",
            f"",
            f"| Dimension | Anomaly | Score |",
            f"|---|---|---|",
        ]
        for b in beh_evidence:
            dim     = str(b.get("dimension", "")).replace("|", "\\|")
            anomaly = str(b.get("anomaly", "")).replace("|", "\\|")
            score   = b.get("score", 0)
            bar     = score_bar(float(score))
            lines.append(f"| {dim} | {anomaly} | {bar} `{score}` |")
        lines += ["", "---", ""]

    # IOC Findings
    ioc_findings = report.get("ioc_findings", [])
    if ioc_findings:
        lines += [
            f"## IOC Findings",
            f"",
            f"| IOC | Reputation | Confidence | Detail |",
            f"|---|---|---|---|",
        ]
        for ioc in ioc_findings:
            val        = str(ioc.get("ioc", "")).replace("|", "\\|")
            rep        = str(ioc.get("reputation", "")).replace("|", "\\|")
            conf       = ioc.get("confidence", 0)
            detail     = str(ioc.get("detail", "")).replace("|", "\\|")
            rep_icon   = {"malicious": "🔴", "suspicious": "🟡", "clean": "🟢"}.get(rep, "⚪")
            lines.append(f"| `{val}` | {rep_icon} {rep} | {conf}% | {detail} |")
        lines += ["", "---", ""]

    # Affected Resources
    resources = report.get("affected_resources", [])
    if resources:
        lines += [
            f"## Affected Resources",
            f"",
            f"| Resource | Risk | Action Taken |",
            f"|---|---|---|",
        ]
        for r in resources:
            res    = str(r.get("resource", "")).replace("|", "\\|")
            risk   = str(r.get("risk", "")).replace("|", "\\|")
            action = str(r.get("action_taken", "none")).replace("|", "\\|")
            lines.append(f"| `{res}` | {risk} | {action} |")
        lines += ["", "---", ""]

    # Recommended Actions
    actions = report.get("recommended_actions", [])
    if actions:
        lines += [f"## Recommended Actions", f""]
        for i, action in enumerate(actions, 1):
            priority = action.get("priority", "MEDIUM")
            prio_icon = {"IMMEDIATE": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(priority, "⚪")
            playbook  = action.get("soar_playbook", "none")
            lines += [
                f"### {i}. {prio_icon} {priority}: {action.get('action', '')}",
                f"",
                f"**Rationale:** {action.get('rationale', '')}",
                f"",
                f"**SOAR Playbook:** `{playbook}`" if playbook != "none" else "**SOAR Playbook:** Manual action required",
                f"",
            ]
        lines += ["---", ""]

    # False Positive Indicators
    fp_indicators = report.get("false_positive_indicators", [])
    if fp_indicators:
        lines += [f"## False Positive Indicators", f""]
        for indicator in fp_indicators:
            lines.append(f"- {indicator}")
        lines += ["", "---", ""]

    # Investigation Notes
    notes = report.get("investigation_notes", "")
    if notes:
        lines += [
            f"## Investigation Notes",
            f"",
            f"> {notes}",
            f"",
            f"---",
            f"",
        ]

    lines += [
        f"",
        f"_Generated by Cognitive SOC AI Investigation Agent | {timestamp}_",
        f"_Model: {report.get('model_used', BEDROCK_MODEL_DISPLAY)} | Environment: {ENVIRONMENT.upper()}_",
    ]

    return "\n".join(lines)


# ── Executive Summary ─────────────────────────────────────────────────────────

def generate_executive_summary(event, report):
    """Generate a plain-English executive summary (3 paragraphs, no jargon)."""
    finding_id = event.get("finding_id", "unknown")
    entity_id  = event.get("entity_id", "unknown")
    severity   = report.get("severity", "HIGH")
    decision   = report.get("triage_decision", "UNKNOWN")
    confidence = report.get("confidence_score", 0)
    timestamp  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    urgency = {
        "CRITICAL": "requires immediate action",
        "HIGH":     "requires attention today",
        "MEDIUM":   "should be reviewed within 24 hours",
        "LOW":      "can be reviewed at next opportunity",
    }.get(severity, "requires review")

    status_line = {
        "CONFIRMED_THREAT": f"Our AI security system has confirmed this as a real threat (confidence: {confidence}%).",
        "PROBABLE_THREAT":  f"Our AI security system assessed this as a probable threat (confidence: {confidence}%). Manual confirmation is recommended.",
        "FALSE_POSITIVE":   f"Our AI security system assessed this as a false positive (confidence: {confidence}%). No immediate action is required.",
    }.get(decision, f"This alert has been investigated with {confidence}% confidence.")

    actions = report.get("recommended_actions", [])
    action_summary = ""
    if actions:
        immediate = [a for a in actions if a.get("priority") == "IMMEDIATE"]
        if immediate:
            action_summary = f"Immediate action required: {immediate[0].get('action', 'Review alert')}."
        else:
            action_summary = f"Recommended action: {actions[0].get('action', 'Review alert')}."

    lines = [
        f"# Cognitive SOC — Executive Security Briefing",
        f"",
        f"**Date:** {timestamp}  |  **Severity:** {severity}  |  **Reference:** `{finding_id}`",
        f"",
        f"---",
        f"",
        f"## What Happened",
        f"",
        report.get("executive_summary", "A security alert was detected and investigated."),
        f"",
        f"## How Serious Is This",
        f"",
        f"{status_line} This is classified as **{severity}** severity and {urgency}.",
        f"",
        f"## What You Need To Do",
        f"",
        f"{action_summary} " + (
            "Automated response has been approved and will execute immediately."
            if report.get("auto_response_safe")
            else "Manual review is required before any automated response is triggered."
        ),
        f"",
        f"---",
        f"",
        f"_Full technical investigation report is available separately._",
        f"_Generated by Cognitive SOC | {timestamp}_",
    ]

    return "\n".join(lines)


# ── S3 Storage ────────────────────────────────────────────────────────────────

def store_report(content, s3_key):
    """Store report Markdown in S3."""
    try:
        s3_client.put_object(
            Bucket=REPORTS_BUCKET,
            Key=s3_key,
            Body=content.encode("utf-8"),
            ContentType="text/markdown",
            ServerSideEncryption="AES256",
        )
        logger.info(f"Report stored: s3://{REPORTS_BUCKET}/{s3_key}")
    except Exception as e:
        logger.error(f"Failed to store report to S3: {str(e)}")
        raise


# ── DynamoDB Update ───────────────────────────────────────────────────────────

def update_investigation_record(finding_id, report, technical_key, executive_key):
    """Update the DynamoDB investigation record with report paths and final status."""
    try:
        table  = dynamodb.Table(INVESTIGATIONS_TABLE)
        status = {
            "CONFIRMED_THREAT": "CONFIRMED_THREAT",
            "PROBABLE_THREAT":  "PROBABLE_THREAT",
            "FALSE_POSITIVE":   "FALSE_POSITIVE",
        }.get(report.get("triage_decision"), "INVESTIGATED")

        table.update_item(
            Key={"investigation_id": finding_id},
            UpdateExpression=(
                "SET #status = :status, confidence_score = :conf, "
                "technical_report_key = :tech, executive_report_key = :exec, "
                "triage_decision = :decision, auto_response_safe = :auto, "
                "requires_human_review = :human, investigated_at = :ts"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status":   status,
                ":conf":     str(report.get("confidence_score", 0)),
                ":tech":     technical_key,
                ":exec":     executive_key,
                ":decision": report.get("triage_decision", "UNKNOWN"),
                ":auto":     report.get("auto_response_safe", False),
                ":human":    report.get("requires_human_review", True),
                ":ts":       datetime.utcnow().isoformat(),
            }
        )
    except Exception as e:
        logger.warning(f"DynamoDB update failed (non-fatal): {str(e)}")


# ── Utilities ─────────────────────────────────────────────────────────────────

def score_bar(score):
    """Build a text-based score bar for the technical report."""
    filled = min(10, int(score / 10))
    return "█" * filled + "░" * (10 - filled)

BEDROCK_MODEL_DISPLAY = os.environ.get("BEDROCK_MODEL", "claude-sonnet-4-6")
