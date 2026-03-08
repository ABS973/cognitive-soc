"""
Cognitive SOC — Enrichment Lambda
Enriches findings with MITRE ATT&CK mapping + IP reputation.
"""
import json, logging, os, boto3, urllib.request, urllib.parse
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
secretsmanager = boto3.client("secretsmanager")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

ATTACK_MAPPING = {
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller":     {"tactic": "Initial Access",      "technique": "T1078"},
    "UnauthorizedAccess:EC2/MaliciousIPCaller":         {"tactic": "Execution",            "technique": "T1059"},
    "Recon:IAMUser/MaliciousIPCaller":                  {"tactic": "Discovery",            "technique": "T1087"},
    "Recon:EC2/PortProbeUnprotectedPort":               {"tactic": "Reconnaissance",       "technique": "T1595"},
    "CryptoCurrency:EC2/BitcoinTool.B":                 {"tactic": "Impact",               "technique": "T1496"},
    "Backdoor:EC2/C&CActivity.B":                       {"tactic": "Command and Control",  "technique": "T1071"},
    "PrivilegeEscalation:IAMUser/AnomalousBehavior":    {"tactic": "Privilege Escalation", "technique": "T1078"},
    "Persistence:IAMUser/AnomalousBehavior":            {"tactic": "Persistence",          "technique": "T1136"},
    "Policy:S3/BucketPublicAccessGranted":              {"tactic": "Exfiltration",         "technique": "T1537"},
    "Stealth:IAMUser/CloudTrailLoggingDisabled":        {"tactic": "Defense Evasion",      "technique": "T1562"},
    "UnauthorizedAccess:EC2/SSHBruteForce":             {"tactic": "Credential Access",    "technique": "T1110"},
    "Policy:IAMUser/RootCredentialUsage":               {"tactic": "Privilege Escalation", "technique": "T1078.004"},
}

def lambda_handler(event, context):
    finding_type = event.get("type", "")
    service      = event.get("service", {})

    remote_ip = (service.get("action", {}).get("networkConnectionAction", {})
                        .get("remoteIpDetails", {}).get("ipAddressV4", ""))

    enrichment = {
        "enriched":       True,
        "enriched_at":    datetime.utcnow().isoformat(),
        "attack_mapping": ATTACK_MAPPING.get(finding_type, {"tactic": "Unknown", "technique": "Unknown"}),
        "severity_context": get_severity_context(event.get("severity", 0)),
        "ip_reputation":  {},
        "summary":        "",
    }

    if remote_ip:
        enrichment["remote_ip"]     = remote_ip
        enrichment["ip_reputation"] = enrich_ip(remote_ip)

    enrichment["summary"] = build_summary(event, enrichment)
    return enrichment

def get_severity_context(severity):
    if severity >= 8.9: return {"label": "CRITICAL", "urgency": "Immediate response required"}
    if severity >= 7.0: return {"label": "HIGH",     "urgency": "Response within 1 hour"}
    if severity >= 4.0: return {"label": "MEDIUM",   "urgency": "Response within 24 hours"}
    return                     {"label": "LOW",      "urgency": "Review at next opportunity"}

def enrich_ip(ip):
    try:
        key = get_secret("cognitive-soc/abuseipdb-api-key")
        if not key:
            return {"ip": ip, "source": "none"}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read().decode())["data"]
            return {"ip": ip, "source": "abuseipdb",
                    "is_known_malicious": d.get("abuseConfidenceScore", 0) >= 50,
                    "confidence_score":   d.get("abuseConfidenceScore", 0),
                    "country":            d.get("countryCode", "Unknown"),
                    "isp":                d.get("isp", "Unknown")}
    except Exception as e:
        logger.warning(f"IP enrichment failed (non-fatal): {e}")
        return {"ip": ip, "source": "error"}

def get_secret(name):
    try:
        return secretsmanager.get_secret_value(SecretId=name).get("SecretString", "")
    except Exception:
        return None

def build_summary(finding, enrichment):
    label  = enrichment.get("severity_context", {}).get("label", "UNKNOWN")
    attack = enrichment.get("attack_mapping", {})
    ip_rep = enrichment.get("ip_reputation", {})
    parts  = [f"[{label}] {finding.get('type', 'Unknown')}"]
    if attack.get("tactic"):
        parts.append(f"— ATT&CK: {attack['tactic']} ({attack.get('technique','')})")
    if ip_rep.get("ip"):
        flag = "KNOWN MALICIOUS" if ip_rep.get("is_known_malicious") else ip_rep.get("country","")
        parts.append(f"— Source IP: {ip_rep['ip']} [{flag}]")
    return " ".join(parts)
