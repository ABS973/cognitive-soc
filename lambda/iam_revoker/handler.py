"""
Cognitive SOC — IAM Revoker Playbook
1. Deactivates compromised access key
2. Deactivates all other active keys
3. Attaches deny-all inline policy
4. Tags user as compromised
"""
import json, logging, os, boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
iam_client = boto3.client("iam")

DENY_ALL = json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]})

def lambda_handler(event, context):
    finding = event.get("finding", {})
    key_details = finding.get("resource", {}).get("accessKeyDetails", {})
    username = key_details.get("userName")
    access_key_id = key_details.get("accessKeyId")

    if not username or not access_key_id:
        return {"actions_taken": ["no_credentials_found"], "success": False}

    logger.info(f"Revoking credentials for: {username}")
    actions_taken = []

    iam_client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status="Inactive")
    actions_taken.append(f"key_deactivated:{access_key_id}")

    for key in iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
        if key["AccessKeyId"] != access_key_id and key["Status"] == "Active":
            iam_client.update_access_key(UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive")
            actions_taken.append(f"additional_key_deactivated:{key['AccessKeyId']}")

    policy_name = f"CognitiveSoc-Deny-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    iam_client.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=DENY_ALL)
    actions_taken.append(f"deny_policy_attached:{policy_name}")

    try:
        iam_client.tag_user(UserName=username, Tags=[
            {"Key": "CognitiveSoc:Status",    "Value": "COMPROMISED"},
            {"Key": "CognitiveSoc:RevokedAt", "Value": datetime.utcnow().isoformat()},
        ])
        actions_taken.append("user_tagged")
    except Exception as e:
        logger.warning(f"Tagging failed (non-fatal): {e}")

    return {"success": True, "username": username, "actions_taken": actions_taken}
