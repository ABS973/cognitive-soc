"""
Cognitive SOC Phase 3 — Bedrock Investigator
The AI investigation agent powered by Claude claude-sonnet-4-6 via AWS Bedrock.

Receives the full context package from context_gatherer and produces a
structured InvestigationReport JSON with:
  - Triage decision (CONFIRMED_THREAT / PROBABLE_THREAT / FALSE_POSITIVE)
  - Confidence score (0-100)
  - Attack timeline reconstruction
  - MITRE ATT&CK chain mapping
  - Behavioral evidence summary
  - Recommended actions with priority
  - Auto-response safety flag

Claude is instructed to reason only from the provided data — never hallucinate.
Output schema is enforced with up to 3 retries on parse failure.
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

bedrock = boto3.client("bedrock-runtime", region_name=os.environ.get("BEDROCK_REGION", "us-east-1"))

ENVIRONMENT     = os.environ.get("ENVIRONMENT", "dev")
BEDROCK_MODEL   = os.environ.get("BEDROCK_MODEL", "anthropic.claude-sonnet-4-20250514-v2:0")
MAX_TOKENS      = int(os.environ.get("BEDROCK_MAX_TOKENS", "4096"))
TEMPERATURE     = float(os.environ.get("BEDROCK_TEMPERATURE", "0.1"))
MAX_RETRIES     = 3


# ── System Prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an elite AWS cloud security analyst working for Cognitive SOC.
Your job is to investigate security incidents with surgical precision.

CRITICAL RULES:
1. You NEVER guess or hallucinate. You reason ONLY from the data provided to you.
2. If data is missing or unavailable, you explicitly say so in your reasoning.
3. You always output VALID JSON matching the exact schema below. Nothing else.
4. You always cite specific log entries, behavioral scores, or IOC data as evidence.
5. You assign confidence scores honestly — if evidence is thin, confidence should be low.

YOUR EXPERTISE:
- AWS CloudTrail forensics: reading API call sequences, identifying credential abuse
- IAM security: privilege escalation paths, lateral movement via role assumption
- MITRE ATT&CK Cloud and Enterprise frameworks
- Behavioral anomaly analysis: what makes activity suspicious vs normal
- Incident timeline reconstruction from API call sequences

TRIAGE DECISIONS:
- CONFIRMED_THREAT: Strong evidence of malicious activity. Multiple corroborating indicators.
- PROBABLE_THREAT:  Suspicious activity with meaningful evidence but not conclusive.
- FALSE_POSITIVE:   Evidence points away from malicious intent. Explainable by normal activity.

AUTO-RESPONSE SAFETY:
Set auto_response_safe to true ONLY if:
- triage_decision is CONFIRMED_THREAT
- confidence_score >= 85
- The recommended SOAR action is reversible (IP blocking, session revocation)
- You have NOT found evidence that the entity is a service account that may break production

OUTPUT FORMAT — you must return ONLY this JSON, no preamble, no explanation outside it:
{
  "triage_decision": "CONFIRMED_THREAT | PROBABLE_THREAT | FALSE_POSITIVE",
  "confidence_score": <integer 0-100>,
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "executive_summary": "<2-3 sentence plain English summary for a non-technical executive>",
  "what_happened": "<Detailed narrative of the incident, 3-5 paragraphs>",
  "attack_timeline": [
    {"time": "<ISO timestamp or relative>", "action": "<what happened>", "significance": "<why this matters>"}
  ],
  "affected_resources": [
    {"resource": "<ARN or name>", "risk": "<what risk this resource now faces>", "action_taken": "<none | remediation applied>"}
  ],
  "mitre_chain": [
    {"tactic": "<MITRE tactic>", "technique": "<T-number>", "technique_name": "<name>", "evidence": "<specific log entry or indicator>"}
  ],
  "behavioral_evidence": [
    {"dimension": "<temporal|geographic|service|action|sequence>", "anomaly": "<what was anomalous>", "score": <0-100>}
  ],
  "ioc_findings": [
    {"ioc": "<IP or domain>", "reputation": "<clean|suspicious|malicious>", "confidence": <0-100>, "detail": "<context>"}
  ],
  "recommended_actions": [
    {"priority": "IMMEDIATE | HIGH | MEDIUM", "action": "<specific action>", "rationale": "<why>", "soar_playbook": "<ec2_isolator|iam_revoker|ip_blocker|s3_protector|none>"}
  ],
  "false_positive_indicators": ["<reason 1>", "<reason 2>"],
  "investigation_notes": "<Any caveats, missing data, or limitations of this investigation>",
  "requires_human_review": <true|false>,
  "auto_response_safe": <true|false>
}"""


def lambda_handler(event, context):
    """
    Run the AI investigation using Claude claude-sonnet-4-6 via AWS Bedrock.
    Called by Step Functions as step 5 (after context_gatherer).
    """
    logger.info("Bedrock Investigator triggered")

    finding_id = event.get("finding_id", "unknown")
    entity_id  = event.get("entity_id", "unknown")

    logger.info(f"Investigating finding={finding_id} entity={entity_id} model={BEDROCK_MODEL}")

    # Build the investigation request message
    investigation_request = build_investigation_request(event)

    # Call Bedrock with retry logic
    report = None
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            raw_response = call_bedrock(investigation_request, attempt)
            report       = parse_and_validate(raw_response, attempt)
            if report:
                break
        except Exception as e:
            last_error = str(e)
            logger.warning(f"Bedrock attempt {attempt}/{MAX_RETRIES} failed: {str(e)}")

    if not report:
        logger.error(f"All {MAX_RETRIES} Bedrock attempts failed. Using fallback report.")
        report = build_fallback_report(event, last_error)

    # Attach metadata
    report["finding_id"]      = finding_id
    report["entity_id"]       = entity_id
    report["investigated_at"] = datetime.utcnow().isoformat()
    report["model_used"]      = BEDROCK_MODEL

    # Pass full context through for report_generator
    return {**event, "investigation_report": report}


# ── Request Builder ───────────────────────────────────────────────────────────

def build_investigation_request(event):
    """
    Build the structured investigation request message for Claude.
    Carefully selects the most relevant data to stay within token limits.
    """
    finding    = {
        "finding_id":    event.get("finding_id"),
        "finding_type":  event.get("finding_type"),
        "severity":      event.get("severity_label"),
        "entity_id":     event.get("entity_id"),
        "entity_type":   event.get("entity_type"),
        "title":         event.get("title"),
        "description":   event.get("description"),
        "account_id":    event.get("account_id"),
        "region":        event.get("region"),
        "created_at":    event.get("created_at"),
        "source":        event.get("source"),
    }

    baseline   = summarise_baseline(event.get("behavioral_baseline", {}))
    deviations = extract_deviations(event.get("behavioral_scores", {}), event.get("behavioral_composite", 0))
    cloudtrail = event.get("cloudtrail_events", [])[:50]  # Cap at 50 events to manage tokens
    ioc        = event.get("ioc_enrichment", {})
    enrichment = event.get("enrichment", {})
    peer       = event.get("peer_comparison", {})
    history    = event.get("entity_history", {})

    # Build MITRE context from Phase 1 enrichment
    mitre = enrichment.get("attack_mapping", {})

    request = {
        "alert": finding,
        "behavioral_baseline_summary": baseline,
        "behavioral_deviations": deviations,
        "cloudtrail_events": cloudtrail,
        "cloudtrail_event_count": event.get("context_summary", {}).get("cloudtrail_event_count", 0),
        "ioc_enrichment": {
            "ips":             ioc.get("ips", {}),
            "enriched_count":  ioc.get("enriched_count", 0),
        },
        "mitre_context": mitre,
        "peer_comparison": peer,
        "entity_history": {
            "total_incidents":   history.get("incident_count", 0),
            "confirmed_threats": history.get("confirmed_threats", 0),
            "recent_incidents":  history.get("recent_incidents", [])[:3],
        },
        "investigation_instructions": (
            "Investigate this security alert thoroughly. "
            "Use the behavioral baseline deviations, CloudTrail event sequence, "
            "and IOC enrichment data to determine: what happened, how serious it is, "
            "and what should be done. "
            "If CloudTrail events are available, reconstruct the attack timeline in chronological order. "
            "Map each suspicious action to a MITRE ATT&CK technique. "
            "Return ONLY the JSON report. No preamble."
        )
    }

    return json.dumps(request, default=str)


def summarise_baseline(baseline):
    """Extract a concise summary of behavioral baseline for the prompt."""
    if not baseline or not baseline.get("entity_id"):
        return {"available": False}
    return {
        "available":         True,
        "total_api_calls":   baseline.get("total_api_calls", 0),
        "typical_hours":     extract_top_hours(baseline.get("temporal_hours", {})),
        "typical_services":  extract_top_services(baseline.get("service_counts", {})),
        "typical_regions":   extract_top_regions(baseline.get("region_counts", {})),
        "error_rate":        round(
            float(baseline.get("error_count", 0)) / max(float(baseline.get("total_api_calls", 1)), 1), 3
        ),
    }


def extract_deviations(dim_scores, composite):
    """Extract anomalous dimensions from Phase 2 scores."""
    if not dim_scores:
        return []
    deviations = []
    dimension_labels = {
        "temporal_score":  "temporal",
        "geo_score":       "geographic",
        "service_score":   "service",
        "action_score":    "action",
        "sequence_score":  "sequence",
    }
    for key, label in dimension_labels.items():
        score = float(dim_scores.get(key, 0))
        if score >= 50:
            deviations.append({
                "dimension": label,
                "score":     score,
                "severity":  "HIGH" if score >= 80 else "MEDIUM",
            })
    if composite >= 70:
        deviations.insert(0, {"dimension": "composite", "score": composite, "severity": "HIGH" if composite >= 85 else "MEDIUM"})
    return deviations


def extract_top_hours(hours_dict, top_n=5):
    if not hours_dict: return []
    sorted_hours = sorted(hours_dict.items(), key=lambda x: float(x[1]), reverse=True)
    return [h[0].replace("hour_", "") + ":00 UTC" for h in sorted_hours[:top_n]]


def extract_top_services(svc_dict, top_n=10):
    if not svc_dict: return []
    sorted_svcs = sorted(svc_dict.items(), key=lambda x: float(x[1]), reverse=True)
    return [s[0].replace("svc_", "").replace("_", ".") for s in sorted_svcs[:top_n]]


def extract_top_regions(region_dict, top_n=5):
    if not region_dict: return []
    sorted_regions = sorted(region_dict.items(), key=lambda x: float(x[1]), reverse=True)
    return [r[0].replace("region_", "").replace("_", "-") for r in sorted_regions[:top_n]]


# ── Bedrock API ───────────────────────────────────────────────────────────────

def call_bedrock(investigation_request, attempt):
    """Call AWS Bedrock with the investigation request."""

    # On retries, add explicit correction instruction
    correction = ""
    if attempt > 1:
        correction = "\n\nIMPORTANT: Your previous response was not valid JSON. Return ONLY valid JSON matching the schema. No explanation, no markdown, no preamble."

    messages = [
        {
            "role": "user",
            "content": investigation_request + correction
        }
    ]

    response = bedrock.invoke_model(
        modelId=BEDROCK_MODEL,
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens":        MAX_TOKENS,
            "temperature":       TEMPERATURE,
            "system":            SYSTEM_PROMPT,
            "messages":          messages,
        })
    )

    response_body = json.loads(response["body"].read())
    raw_text      = response_body["content"][0]["text"]
    logger.debug(f"Bedrock raw response (attempt {attempt}): {raw_text[:500]}")
    return raw_text


# ── Response Parsing ──────────────────────────────────────────────────────────

REQUIRED_FIELDS = {
    "triage_decision", "confidence_score", "severity",
    "executive_summary", "what_happened", "recommended_actions",
    "requires_human_review", "auto_response_safe"
}


def parse_and_validate(raw_text, attempt):
    """
    Parse and validate the Bedrock JSON response.
    Returns parsed dict if valid, None if invalid.
    """
    # Strip any markdown code fences Claude might add despite instructions
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text  = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

    try:
        report = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parse failed on attempt {attempt}: {str(e)}")
        return None

    # Validate required fields
    missing = REQUIRED_FIELDS - set(report.keys())
    if missing:
        logger.warning(f"Missing required fields on attempt {attempt}: {missing}")
        return None

    # Validate triage_decision values
    valid_decisions = {"CONFIRMED_THREAT", "PROBABLE_THREAT", "FALSE_POSITIVE"}
    if report.get("triage_decision") not in valid_decisions:
        logger.warning(f"Invalid triage_decision: {report.get('triage_decision')}")
        return None

    # Enforce auto_response_safe safety rules
    report = enforce_auto_response_rules(report)

    logger.info(
        f"Valid investigation report: decision={report['triage_decision']} "
        f"confidence={report['confidence_score']} auto_response_safe={report['auto_response_safe']}"
    )
    return report


def enforce_auto_response_rules(report):
    """
    Safety override: ensure auto_response_safe is only true when conditions are fully met.
    This is a hard enforcement layer on top of Claude's judgment.
    """
    if report.get("auto_response_safe"):
        # Must be CONFIRMED_THREAT with confidence >= 85
        if report.get("triage_decision") != "CONFIRMED_THREAT":
            report["auto_response_safe"] = False
            logger.info("auto_response_safe overridden to False: not CONFIRMED_THREAT")
        elif int(report.get("confidence_score", 0)) < 85:
            report["auto_response_safe"] = False
            logger.info(f"auto_response_safe overridden to False: confidence={report.get('confidence_score')} < 85")
    return report


# ── Fallback Report ───────────────────────────────────────────────────────────

def build_fallback_report(event, error):
    """
    Return a safe fallback report when Bedrock fails after all retries.
    Always requires human review — never auto-responds.
    """
    logger.warning(f"Building fallback report due to: {error}")
    return {
        "triage_decision":       "PROBABLE_THREAT",
        "confidence_score":      0,
        "severity":              event.get("severity_label", "HIGH"),
        "executive_summary":     (
            f"A {event.get('severity_label', 'HIGH')} severity alert was detected for entity "
            f"{event.get('entity_id', 'unknown')} but the AI investigation could not complete. "
            "Manual review is required immediately."
        ),
        "what_happened":         f"Alert type: {event.get('finding_type')}. AI investigation failed: {error}",
        "attack_timeline":       [],
        "affected_resources":    [],
        "mitre_chain":           [],
        "behavioral_evidence":   [],
        "ioc_findings":          [],
        "recommended_actions":   [{"priority": "IMMEDIATE", "action": "Manual investigation required", "rationale": "AI investigation unavailable", "soar_playbook": "none"}],
        "false_positive_indicators": [],
        "investigation_notes":   f"AI investigation failed after {MAX_RETRIES} attempts. Error: {error}",
        "requires_human_review": True,
        "auto_response_safe":    False,
        "fallback":              True,
    }
