"""
Cognitive SOC — GuardDuty Ingestor
Normalizes and validates incoming GuardDuty findings
before they enter the SOAR pipeline.
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def lambda_handler(event, context):
    """Validate and normalize a GuardDuty finding."""
    logger.debug(f"Raw event: {json.dumps(event)}")

    detail = event.get("detail", {})
    if not detail:
        logger.error("No detail in event — not a valid GuardDuty finding")
        return {"valid": False, "reason": "no_detail"}

    required_fields = ["id", "type", "severity", "accountId", "region"]
    missing = [f for f in required_fields if f not in detail]
    if missing:
        logger.error(f"Missing required fields: {missing}")
        return {"valid": False, "reason": f"missing_fields:{missing}"}

    normalized = {
        "id":          detail["id"],
        "type":        detail["type"],
        "severity":    float(detail["severity"]),
        "account_id":  detail["accountId"],
        "region":      detail["region"],
        "title":       detail.get("title", ""),
        "description": detail.get("description", ""),
        "resource":    detail.get("resource", {}),
        "service":     detail.get("service", {}),
        "created_at":  detail.get("createdAt", datetime.utcnow().isoformat()),
        "updated_at":  detail.get("updatedAt", datetime.utcnow().isoformat()),
    }

    logger.info(f"Normalized finding: {normalized['type']} | Severity: {normalized['severity']}")
    return {"valid": True, "finding": normalized}
