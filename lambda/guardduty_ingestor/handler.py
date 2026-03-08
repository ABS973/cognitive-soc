"""
Cognitive SOC — GuardDuty Ingestor
Validates and normalizes incoming GuardDuty findings.
"""
import json, logging, os
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

def lambda_handler(event, context):
    detail = event.get("detail", {})
    if not detail:
        return {"valid": False, "reason": "no_detail"}
    missing = [f for f in ["id","type","severity","accountId","region"] if f not in detail]
    if missing:
        return {"valid": False, "reason": f"missing_fields:{missing}"}
    return {"valid": True, "finding": {
        "id":          detail["id"],
        "type":        detail["type"],
        "severity":    float(detail["severity"]),
        "account_id":  detail["accountId"],
        "region":      detail["region"],
        "title":       detail.get("title",""),
        "description": detail.get("description",""),
        "resource":    detail.get("resource",{}),
        "service":     detail.get("service",{}),
        "created_at":  detail.get("createdAt", datetime.utcnow().isoformat()),
    }}
