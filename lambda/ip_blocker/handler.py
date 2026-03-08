"""
Cognitive SOC — IP Blocker Playbook
Adds malicious source IPs to WAF IP set deny list.
Falls back to logging + alert if WAF ACL is not configured.
"""

import json
import logging
import os
import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

wafv2_client = boto3.client("wafv2")
WAF_ACL_ID = os.environ.get("WAF_ACL_ID", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")


def lambda_handler(event, context):
    finding = event.get("finding", {})
    service = finding.get("service", {})

    # Extract remote IP from finding
    remote_ip = (
        service.get("action", {})
               .get("networkConnectionAction", {})
               .get("remoteIpDetails", {})
               .get("ipAddressV4", "")
        or service.get("action", {})
                  .get("portProbeAction", {})
                  .get("portProbeDetails", [{}])[0]
                  .get("remoteIpDetails", {})
                  .get("ipAddressV4", "")
    )

    if not remote_ip:
        logger.warning("No remote IP found in finding")
        return {"actions_taken": ["no_ip_found"], "success": False}

    logger.info(f"Blocking IP: {remote_ip}")
    actions_taken = []

    if not WAF_ACL_ID:
        logger.warning("WAF_ACL_ID not configured — logging IP block only")
        actions_taken.append(f"ip_logged_for_manual_block:{remote_ip}")
        return {"success": False, "ip": remote_ip, "actions_taken": actions_taken,
                "note": "Configure WAF_ACL_ID to enable automatic IP blocking"}

    try:
        # Get existing IP set or create one
        ip_set_id = get_or_create_ip_set()

        # Get current IP set to obtain lock token (required for WAF updates)
        ip_set_response = wafv2_client.get_ip_set(
            Name=f"cognitive-soc-blocked-ips-{ENVIRONMENT}",
            Scope="REGIONAL",
            Id=ip_set_id
        )

        current_addresses = ip_set_response["IPSet"]["Addresses"]
        cidr = f"{remote_ip}/32"

        if cidr not in current_addresses:
            current_addresses.append(cidr)
            wafv2_client.update_ip_set(
                Name=f"cognitive-soc-blocked-ips-{ENVIRONMENT}",
                Scope="REGIONAL",
                Id=ip_set_id,
                Addresses=current_addresses,
                LockToken=ip_set_response["LockToken"]
            )
            actions_taken.append(f"ip_blocked_in_waf:{remote_ip}")
            logger.info(f"Blocked IP {remote_ip} in WAF IP set")
        else:
            actions_taken.append(f"ip_already_blocked:{remote_ip}")
            logger.info(f"IP {remote_ip} already in WAF block list")

        return {"success": True, "ip": remote_ip, "actions_taken": actions_taken}

    except Exception as e:
        logger.error(f"Failed to block IP {remote_ip}: {str(e)}", exc_info=True)
        return {"success": False, "ip": remote_ip, "actions_taken": actions_taken, "error": str(e)}


def get_or_create_ip_set():
    """Get existing Cognitive SOC IP set or create one."""
    ip_set_name = f"cognitive-soc-blocked-ips-{ENVIRONMENT}"

    try:
        response = wafv2_client.list_ip_sets(Scope="REGIONAL")
        for ip_set in response.get("IPSets", []):
            if ip_set["Name"] == ip_set_name:
                return ip_set["Id"]
    except Exception:
        pass

    # Create new IP set
    response = wafv2_client.create_ip_set(
        Name=ip_set_name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=[],
        Description="CognitiveSoc auto-blocked malicious IPs",
        Tags=[{"Key": "CognitiveSoc:Purpose", "Value": "ip-blocking"}]
    )
    return response["Summary"]["Id"]
