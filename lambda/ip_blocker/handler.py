"""
Cognitive SOC — IP Blocker Playbook
Adds malicious IPs to WAF IP set deny list.
"""
import json, logging, os, boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
wafv2_client = boto3.client("wafv2")
WAF_ACL_ID  = os.environ.get("WAF_ACL_ID", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

def lambda_handler(event, context):
    finding = event.get("finding", {})
    service = finding.get("service", {})
    remote_ip = (service.get("action", {}).get("networkConnectionAction", {})
                        .get("remoteIpDetails", {}).get("ipAddressV4", ""))
    if not remote_ip:
        return {"actions_taken": ["no_ip_found"], "success": False}

    if not WAF_ACL_ID:
        logger.warning("WAF_ACL_ID not configured")
        return {"success": False, "actions_taken": [f"ip_logged:{remote_ip}"],
                "note": "Set WAF_ACL_ID env var to enable auto-blocking"}

    try:
        ip_set_id = get_or_create_ip_set()
        r = wafv2_client.get_ip_set(Name=f"cognitive-soc-blocked-ips-{ENVIRONMENT}",
                                     Scope="REGIONAL", Id=ip_set_id)
        addresses = r["IPSet"]["Addresses"]
        cidr = f"{remote_ip}/32"
        if cidr not in addresses:
            addresses.append(cidr)
            wafv2_client.update_ip_set(Name=f"cognitive-soc-blocked-ips-{ENVIRONMENT}",
                Scope="REGIONAL", Id=ip_set_id, Addresses=addresses, LockToken=r["LockToken"])
            return {"success": True, "ip": remote_ip, "actions_taken": [f"ip_blocked:{remote_ip}"]}
        return {"success": True, "ip": remote_ip, "actions_taken": [f"already_blocked:{remote_ip}"]}
    except Exception as e:
        logger.error(f"IP block failed: {e}", exc_info=True)
        return {"success": False, "error": str(e)}

def get_or_create_ip_set():
    name = f"cognitive-soc-blocked-ips-{ENVIRONMENT}"
    for ip_set in wafv2_client.list_ip_sets(Scope="REGIONAL").get("IPSets", []):
        if ip_set["Name"] == name:
            return ip_set["Id"]
    r = wafv2_client.create_ip_set(Name=name, Scope="REGIONAL",
        IPAddressVersion="IPV4", Addresses=[],
        Description="CognitiveSoc auto-blocked malicious IPs")
    return r["Summary"]["Id"]
