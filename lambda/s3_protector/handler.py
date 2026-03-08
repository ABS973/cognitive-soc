"""
Cognitive SOC — S3 Protector Playbook
1. Re-applies Block Public Access
2. Removes public bucket policy statements
3. Enforces encryption
"""
import json, logging, os, boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
s3_client = boto3.client("s3")

def lambda_handler(event, context):
    finding = event.get("finding", {})
    buckets = finding.get("resource", {}).get("s3BucketDetails", [])
    bucket_name = buckets[0].get("name") if buckets else None
    if not bucket_name:
        return {"actions_taken": ["no_bucket_found"], "success": False}

    logger.info(f"Protecting bucket: {bucket_name}")
    actions_taken = []

    s3_client.put_public_access_block(Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True
        })
    actions_taken.append("block_public_access_applied")

    try:
        policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"])
        clean = [s for s in policy["Statement"]
                 if not (s.get("Principal") in ["*", {"AWS": "*"}] and s.get("Effect") == "Allow")]
        if clean:
            policy["Statement"] = clean
            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        else:
            s3_client.delete_bucket_policy(Bucket=bucket_name)
        actions_taken.append("public_policy_removed")
    except Exception:
        pass

    try:
        s3_client.put_bucket_encryption(Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        actions_taken.append("encryption_enforced")
    except Exception as e:
        logger.warning(f"Encryption failed (non-fatal): {e}")

    return {"success": True, "bucket_name": bucket_name, "actions_taken": actions_taken}
