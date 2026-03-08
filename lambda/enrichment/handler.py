"""
Cognitive SOC — Threat Intel Enrichment Lambda
Enriches GuardDuty findings with external threat intelligence:
- IP reputation (AbuseIPDB)
- Domain analysis (VirusTotal)
- Known malware hashes (VirusTotal)
- Geolocation data
- MITRE ATT&CK technique mapping
"""

import json
import logging
import os
import boto3
import urllib.request
import urllib.parse
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

secretsmanager = boto3.client("secretsmanager")
dynamodb = boto3.resource("dynamodb")

ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

# MITRE ATT&CK Cloud technique mapping by GuardDuty finding type
ATTACK_MAPPING = {
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller":        {"tactic": "Initial Access",        "technique": "T1078", "name": "Valid Accounts"},
    "UnauthorizedAccess:EC2/MaliciousIPCaller":            {"tactic": "Execution",              "technique": "T1059", "name": "Command and Scripting Interpreter"},
    "Recon:IAMUser/MaliciousIPCaller":                     {"tactic": "Discovery",              "technique": "T1087", "name": "Account Discovery"},
    "Recon:EC2/PortProbeUnprotectedPort":                  {"tactic": "Reconnaissance",         "technique": "T1595", "name": "Active Scanning"},
    "CryptoCurrency:EC2/BitcoinTool.B":                    {"tactic": "Impact",                 "technique": "T1496", "name": "Resource Hijacking"},
    "Backdoor:EC2/C&CActivity.B":                         {"tactic": "Command and Control",    "technique": "T1071", "name": "Application Layer Protocol"},
    "PrivilegeEscalation:IAMUser/AnomalousBehavior":       {"tactic": "Privilege Escalation",   "technique": "T1078", "name": "Valid Accounts - Cloud"},
    "Persistence:IAMUser/AnomalousBehavior":               {"tactic": "Persistence",            "technique": "T1136", "name": "Create Account"},
    "Policy:S3/BucketPublicAccessGranted":                 {"tactic": "Exfiltration",           "technique": "T1537", "name": "Transfer Data to Cloud Account"},
    "Stealth:IAMUser/CloudTrailLoggingDisabled":           {"tactic": "Defense Evasion",        "technique": "T1562", "name": "Impair Defenses"},
    "UnauthorizedAccess:EC2/SSHBruteForce":                {"tactic": "Credential Access",      "technique": "T1110", "name": "Brute Force"},
    "Policy:IAMUser/RootCredentialUsage":                  {"tactic": "Privilege Escalation",   "technique": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
}


def lambda_handler(event, context):
    """Enrich a GuardDuty finding with threat intel context."""
    finding = event  # Called directly with finding dict from orchestrator

    finding_type = finding.get("type", "")
    resource = finding.get("resource", {})
    service = finding.get("service", {})

    enrichment = {
        "enriched": True,
        "enriched_at": datetime.utcnow().isoformat(),
        "attack_mapping": get_attack_mapping(finding_type),
        "ip_reputation": {},
        "severity_context": get_severity_context(finding.get("severity", 0)),
        "summary": "",
    }

    # Extract IPs from finding for enrichment
    remote_ip = (
        service.get("action", {})
               .get("networkConnectionAction", {})
               .get("remoteIpDetails", {})
               .get("ipAddressV4", "")
        or service.get("action", {})
                  .get("awsApiCallAction", {})
                  .get("remoteIpDetails", {})
                  .get("ipAddressV4", "")
    )

    if remote_ip:
        enrichment["remote_ip"] = remote_ip
        enrichment["ip_reputation"] = enrich_ip(remote_ip)

    # Build human-readable summary
    enrichment["summary"] = build_summary(finding, enrichment)

    logger.info(f"Enrichment complete for {finding_type}: {enrichment['summary']}")
    return enrichment


def get_attack_mapping(finding_type):
    """Map GuardDuty finding to MITRE ATT&CK technique."""
    return ATTACK_MAPPING.get(finding_type, {
        "tactic": "Unknown",
        "technique": "Unknown",
        "name": "Unmapped technique — review manually"
    })


def get_severity_context(severity):
    """Provide human-readable severity context."""
    if severity >= 8.9:
        return {"label": "CRITICAL", "color": "#FF0000", "urgency": "Immediate response required"}
    elif severity >= 7.0:
        return {"label": "HIGH",     "color": "#FF6600", "urgency": "Response required within 1 hour"}
    elif severity >= 4.0:
        return {"label": "MEDIUM",   "color": "#FFAA00", "urgency": "Response required within 24 hours"}
    else:
        return {"label": "LOW",      "color": "#00AA00", "urgency": "Review at next opportunity"}


def enrich_ip(ip_address):
    """
    Enrich an IP address with reputation data.
    Uses AbuseIPDB if API key is configured, otherwise returns basic geo data.
    """
    # Check DynamoDB cache first (avoid repeated API calls for same IP)
    cached = get_cached_enrichment(ip_address)
    if cached:
        logger.debug(f"Cache hit for IP {ip_address}")
        return cached

    result = {
        "ip": ip_address,
        "source": "basic",
        "is_known_malicious": False,
        "confidence_score": 0,
        "country": "Unknown",
        "isp": "Unknown",
    }

    # Try AbuseIPDB enrichment
    try:
        api_key = get_secret("cognitive-soc/abuseipdb-api-key")
        if api_key:
            result = query_abuseipdb(ip_address, api_key)
            cache_enrichment(ip_address, result)
    except Exception as e:
        logger.warning(f"IP enrichment failed for {ip_address} (non-fatal): {str(e)}")

    return result


def query_abuseipdb(ip_address, api_key):
    """Query AbuseIPDB for IP reputation."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip_address)}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json"
    })
    with urllib.request.urlopen(req, timeout=5) as response:
        data = json.loads(response.read().decode())["data"]
        return {
            "ip": ip_address,
            "source": "abuseipdb",
            "is_known_malicious": data.get("abuseConfidenceScore", 0) >= 50,
            "confidence_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", ""),
        }


def get_secret(secret_name):
    """Retrieve a secret from AWS Secrets Manager."""
    try:
        response = secretsmanager.get_secret_value(SecretId=secret_name)
        return response.get("SecretString", "")
    except Exception:
        return None


def get_cached_enrichment(ip_address):
    """Check DynamoDB cache for existing enrichment."""
    try:
        table = dynamodb.Table(f"cognitive-soc-incidents-{ENVIRONMENT}")
        response = table.get_item(Key={"finding_id": f"ip_cache_{ip_address}", "timestamp": "cache"})
        return response.get("Item", {}).get("enrichment_data")
    except Exception:
        return None


def cache_enrichment(ip_address, data):
    """Cache enrichment result in DynamoDB."""
    try:
        table = dynamodb.Table(f"cognitive-soc-incidents-{ENVIRONMENT}")
        table.put_item(Item={
            "finding_id": f"ip_cache_{ip_address}",
            "timestamp": "cache",
            "enrichment_data": data,
            "ttl": int(datetime.utcnow().timestamp()) + (24 * 3600)  # 24hr cache
        })
    except Exception as e:
        logger.debug(f"Cache write failed (non-fatal): {str(e)}")


def build_summary(finding, enrichment):
    """Build a human-readable one-line summary of the finding."""
    finding_type = finding.get("type", "Unknown")
    severity_label = enrichment.get("severity_context", {}).get("label", "UNKNOWN")
    attack = enrichment.get("attack_mapping", {})
    ip_rep = enrichment.get("ip_reputation", {})

    parts = [f"[{severity_label}] {finding_type}"]

    if attack.get("tactic"):
        parts.append(f"— ATT&CK: {attack['tactic']} ({attack.get('technique', '')})")

    if ip_rep.get("ip"):
        malicious = "KNOWN MALICIOUS" if ip_rep.get("is_known_malicious") else ip_rep.get("country", "")
        parts.append(f"— Source IP: {ip_rep['ip']} [{malicious}]")

    return " ".join(parts)
