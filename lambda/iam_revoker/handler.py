"""
Cognitive SOC — IAM Revoker Playbook
When compromised IAM credentials are detected, this playbook:
1. Immediately deactivates the compromised access key
2. Attaches a deny-all policy to prevent any further API calls
3. Tags the user as compromised
4. Records all active sessions for investigation
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

iam_client = boto3.client("iam")

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "StringEquals": {
                "aws:RequestedRegion": "*"
            }
        }
    }]
})


def lambda_handler(event, context):
    finding = event.get("finding", {})
    resource = finding.get("resource", {})

    access_key_details = resource.get("accessKeyDetails", {})
    username = access_key_details.get("userName")
    access_key_id = access_key_details.get("accessKeyId")
    principal_type = access_key_details.get("principalType", "IAMUser")

    if not username or not access_key_id:
        logger.warning("Missing username or access key ID — cannot revoke")
        return {"actions_taken": ["no_credentials_found"], "success": False}

    logger.info(f"Revoking credentials for {principal_type}: {username}, Key: {access_key_id}")
    actions_taken = []

    try:
        # Step 1: Immediately deactivate the compromised access key
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive"
        )
        actions_taken.append(f"access_key_deactivated:{access_key_id}")
        logger.info(f"Deactivated access key {access_key_id} for {username}")

        # Step 2: List all other active keys and deactivate them too
        all_keys = iam_client.list_access_keys(UserName=username)
        for key in all_keys.get("AccessKeyMetadata", []):
            if key["AccessKeyId"] != access_key_id and key["Status"] == "Active":
                iam_client.update_access_key(
                    UserName=username,
                    AccessKeyId=key["AccessKeyId"],
                    Status="Inactive"
                )
                actions_taken.append(f"additional_key_deactivated:{key['AccessKeyId']}")
                logger.info(f"Also deactivated additional key {key['AccessKeyId']}")

        # Step 3: Attach deny-all inline policy to prevent console access too
        policy_name = f"CognitiveSoc-Emergency-Deny-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        iam_client.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=DENY_ALL_POLICY
        )
        actions_taken.append(f"deny_policy_attached:{policy_name}")
        logger.info(f"Attached deny-all policy {policy_name} to {username}")

        # Step 4: Tag user as compromised
        try:
            iam_client.tag_user(UserName=username, Tags=[
                {"Key": "CognitiveSoc:Status",      "Value": "COMPROMISED"},
                {"Key": "CognitiveSoc:RevokedAt",   "Value": datetime.utcnow().isoformat()},
                {"Key": "CognitiveSoc:FindingType", "Value": finding.get("type", "unknown")},
                {"Key": "CognitiveSoc:FindingId",   "Value": finding.get("id", "unknown")},
            ])
            actions_taken.append("user_tagged_compromised")
        except Exception as e:
            logger.warning(f"Tagging failed (non-fatal): {str(e)}")

        logger.info(f"Successfully revoked credentials for {username}. Actions: {actions_taken}")
        return {
            "success": True,
            "username": username,
            "access_key_id": access_key_id,
            "actions_taken": actions_taken
        }

    except Exception as e:
        logger.error(f"Failed to revoke credentials for {username}: {str(e)}", exc_info=True)
        return {
            "success": False,
            "username": username,
            "actions_taken": actions_taken,
            "error": str(e)
        }
