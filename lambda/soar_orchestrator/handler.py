"""
Cognitive SOC — SOAR Orchestrator
Routes GuardDuty findings to the appropriate automated response playbook.
Each finding type maps to a specific Lambda playbook for remediation.
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

lambda_client = boto3.client("lambda")
s3_client = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

FINDINGS_BUCKET = os.environ["FINDINGS_BUCKET"]
ENVIRONMENT = os.environ["ENVIRONMENT"]
ACCOUNT_ID = os.environ["AWS_ACCOUNT_ID"]

# Maps GuardDuty finding types to Lambda playbooks
PLAYBOOK_ROUTING = {
    # EC2 threats → isolate the instance
    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom": "ec2_isolator",
    "UnauthorizedAccess:EC2/MaliciousIPCaller":        "ec2_isolator",
    "Backdoor:EC2/C&CActivity.B":                      "ec2_isolator",
    "Backdoor:EC2/C&CActivity.B!DNS":                  "ec2_isolator",
    "Trojan:EC2/BlackholeTraffic":                     "ec2_isolator",
    "CryptoCurrency:EC2/BitcoinTool.B":                "ec2_isolator",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS":            "ec2_isolator",

    # IAM threats → revoke credentials
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom": "iam_revoker",
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller":        "iam_revoker",
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B":    "iam_revoker",
    "CredentialAccess:IAMUser/AnomalousBehavior":          "iam_revoker",
    "Persistence:IAMUser/AnomalousBehavior":               "iam_revoker",
    "PrivilegeEscalation:IAMUser/AnomalousBehavior":       "iam_revoker",

    # S3 threats → re-apply protections
    "Policy:S3/BucketPublicAccessGranted":       "s3_protector",
    "Policy:S3/BucketAnonymousAccessGranted":    "s3_protector",
    "Stealth:S3/ServerAccessLoggingDisabled":    "s3_protector",
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom": "s3_protector",

    # Brute force / recon → block IP
    "UnauthorizedAccess:EC2/SSHBruteForce":      "ip_blocker",
    "UnauthorizedAccess:EC2/RDPBruteForce":      "ip_blocker",
    "Recon:EC2/PortProbeUnprotectedPort":        "ip_blocker",
    "Recon:IAMUser/MaliciousIPCaller":           "ip_blocker",
}

# Finding types that always get immediate human escalation regardless of playbook
ALWAYS_ESCALATE = {
    "Policy:IAMUser/RootCredentialUsage",
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
    "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Stealth:IAMUser/PasswordPolicyChange",
}


def lambda_handler(event, context):
    """
    Entry point. Called by EventBridge when GuardDuty fires a finding.
    """
    logger.info("SOAR Orchestrator triggered")
    logger.debug(f"Event: {json.dumps(event)}")

    try:
        finding = parse_finding(event)
        finding_id = finding["id"]
        finding_type = finding["type"]
        severity = finding["severity"]

        logger.info(f"Processing finding: {finding_type} | Severity: {severity} | ID: {finding_id}")

        # 1. Store raw finding in S3
        store_finding(finding_id, event)

        # 2. Record in DynamoDB for state tracking
        record_incident(finding)

        # 3. Enrich finding with threat intel
        enriched = invoke_enrichment(finding)

        # 4. Route to appropriate playbook
        playbook_result = route_to_playbook(finding, enriched)

        # 5. Send notification
        invoke_notifier(finding, enriched, playbook_result)

        logger.info(f"Successfully processed finding {finding_id}")
        return {
            "statusCode": 200,
            "finding_id": finding_id,
            "playbook_invoked": playbook_result.get("playbook"),
            "actions_taken": playbook_result.get("actions_taken", [])
        }

    except Exception as e:
        logger.error(f"Failed to process finding: {str(e)}", exc_info=True)
        raise


def parse_finding(event):
    """Normalize a GuardDuty finding from EventBridge event."""
    detail = event.get("detail", {})
    return {
        "id": detail.get("id", "unknown"),
        "type": detail.get("type", "unknown"),
        "severity": detail.get("severity", 0),
        "region": detail.get("region", "unknown"),
        "account_id": detail.get("accountId", ACCOUNT_ID),
        "title": detail.get("title", ""),
        "description": detail.get("description", ""),
        "resource": detail.get("resource", {}),
        "service": detail.get("service", {}),
        "created_at": detail.get("createdAt", datetime.utcnow().isoformat()),
        "updated_at": detail.get("updatedAt", datetime.utcnow().isoformat()),
        "raw": detail
    }


def store_finding(finding_id, raw_event):
    """Persist raw finding to S3 for forensic record keeping."""
    key = f"findings/{datetime.utcnow().strftime('%Y/%m/%d')}/{finding_id}.json"
    s3_client.put_object(
        Bucket=FINDINGS_BUCKET,
        Key=key,
        Body=json.dumps(raw_event, default=str),
        ContentType="application/json",
        ServerSideEncryption="AES256"
    )
    logger.debug(f"Stored finding to s3://{FINDINGS_BUCKET}/{key}")


def record_incident(finding):
    """Record incident state in DynamoDB."""
    table = dynamodb.Table(f"cognitive-soc-incidents-{ENVIRONMENT}")
    table.put_item(Item={
        "finding_id": finding["id"],
        "timestamp": finding["created_at"],
        "type": finding["type"],
        "severity": str(finding["severity"]),
        "status": "PROCESSING",
        "account_id": finding["account_id"],
        "region": finding["region"],
        "ttl": int(datetime.utcnow().timestamp()) + (90 * 24 * 3600)  # 90 day TTL
    })


def invoke_enrichment(finding):
    """Call enrichment Lambda to get threat intel context."""
    try:
        response = lambda_client.invoke(
            FunctionName=f"cognitive-soc-enrichment-{ENVIRONMENT}",
            InvocationType="RequestResponse",
            Payload=json.dumps(finding)
        )
        result = json.loads(response["Payload"].read())
        logger.info(f"Enrichment complete: {result.get('summary', 'no summary')}")
        return result
    except Exception as e:
        logger.warning(f"Enrichment failed (non-fatal): {str(e)}")
        return {"enriched": False, "reason": str(e)}


def route_to_playbook(finding, enriched):
    """Determine and invoke the correct response playbook."""
    finding_type = finding["type"]
    severity = finding["severity"]

    # Determine playbook
    playbook = PLAYBOOK_ROUTING.get(finding_type)

    # High severity findings without a specific playbook still get escalated
    if not playbook:
        if severity >= 7:
            logger.info(f"No specific playbook for {finding_type} — escalating via notifier")
        else:
            logger.info(f"No playbook configured for {finding_type} — logging only")
        return {"playbook": None, "actions_taken": ["logged", "stored"]}

    logger.info(f"Routing {finding_type} to playbook: {playbook}")

    try:
        response = lambda_client.invoke(
            FunctionName=f"cognitive-soc-{playbook}-{ENVIRONMENT}",
            InvocationType="RequestResponse",
            Payload=json.dumps({
                "finding": finding,
                "enriched": enriched
            })
        )
        result = json.loads(response["Payload"].read())
        logger.info(f"Playbook {playbook} completed: {result}")
        return {"playbook": playbook, "actions_taken": result.get("actions_taken", [])}

    except Exception as e:
        logger.error(f"Playbook {playbook} failed: {str(e)}", exc_info=True)
        return {"playbook": playbook, "actions_taken": ["playbook_failed"], "error": str(e)}


def invoke_notifier(finding, enriched, playbook_result):
    """Send alert notification."""
    lambda_client.invoke(
        FunctionName=f"cognitive-soc-notifier-{ENVIRONMENT}",
        InvocationType="Event",  # Async — don't wait
        Payload=json.dumps({
            "finding": finding,
            "enriched": enriched,
            "playbook_result": playbook_result,
            "escalate": finding["type"] in ALWAYS_ESCALATE or finding["severity"] >= 7
        })
    )
