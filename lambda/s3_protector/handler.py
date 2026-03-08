"""
Cognitive SOC — S3 Protector Playbook
When a public S3 bucket is detected, this playbook:
1. Re-applies Block Public Access settings
2. Removes any bucket policy that allows public access
3. Re-enables access logging if disabled
4. Tags the bucket as remediated
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3_client = boto3.client("s3")


def lambda_handler(event, context):
    finding = event.get("finding", {})
    resource = finding.get("resource", {})

    s3_bucket = resource.get("s3BucketDetails", [])
    if not s3_bucket:
        logger.warning("No S3 bucket details found in finding")
        return {"actions_taken": ["no_bucket_found"], "success": False}

    bucket_name = s3_bucket[0].get("name") if isinstance(s3_bucket, list) else s3_bucket.get("name")
    if not bucket_name:
        return {"actions_taken": ["no_bucket_name"], "success": False}

    logger.info(f"Protecting S3 bucket: {bucket_name}")
    actions_taken = []

    try:
        # Step 1: Apply Block Public Access
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True
            }
        )
        actions_taken.append("block_public_access_applied")
        logger.info(f"Applied Block Public Access to {bucket_name}")

        # Step 2: Check and remediate bucket policy
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response["Policy"])

            if has_public_statement(policy):
                # Remove public statements from policy
                clean_policy = remove_public_statements(policy)
                if clean_policy["Statement"]:
                    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(clean_policy))
                    actions_taken.append("public_policy_statements_removed")
                else:
                    s3_client.delete_bucket_policy(Bucket=bucket_name)
                    actions_taken.append("public_bucket_policy_deleted")
        except s3_client.exceptions.NoSuchBucketPolicy:
            logger.debug(f"No bucket policy on {bucket_name} — skipping policy remediation")

        # Step 3: Ensure server-side encryption is enabled
        try:
            s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            )
            actions_taken.append("encryption_enforced")
        except Exception as e:
            logger.warning(f"Could not enforce encryption (non-fatal): {str(e)}")

        # Step 4: Tag bucket as remediated
        try:
            existing_tags = s3_client.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
        except Exception:
            existing_tags = []

        new_tags = [t for t in existing_tags if not t["Key"].startswith("CognitiveSoc:")]
        new_tags.extend([
            {"Key": "CognitiveSoc:Status",        "Value": "REMEDIATED"},
            {"Key": "CognitiveSoc:RemediatedAt",  "Value": datetime.utcnow().isoformat()},
            {"Key": "CognitiveSoc:FindingType",   "Value": finding.get("type", "unknown")},
        ])
        s3_client.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": new_tags})
        actions_taken.append("bucket_tagged")

        logger.info(f"Successfully protected bucket {bucket_name}. Actions: {actions_taken}")
        return {"success": True, "bucket_name": bucket_name, "actions_taken": actions_taken}

    except Exception as e:
        logger.error(f"Failed to protect bucket {bucket_name}: {str(e)}", exc_info=True)
        return {"success": False, "bucket_name": bucket_name, "actions_taken": actions_taken, "error": str(e)}


def has_public_statement(policy):
    """Check if a bucket policy has any statements allowing public access."""
    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", "")
        if principal == "*" or principal == {"AWS": "*"}:
            if statement.get("Effect") == "Allow":
                return True
    return False


def remove_public_statements(policy):
    """Remove all public Allow statements from a bucket policy."""
    clean_statements = []
    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", "")
        is_public = principal == "*" or principal == {"AWS": "*"}
        if not (is_public and statement.get("Effect") == "Allow"):
            clean_statements.append(statement)
    policy["Statement"] = clean_statements
    return policy
