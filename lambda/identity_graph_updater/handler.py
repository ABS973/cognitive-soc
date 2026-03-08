"""
Cognitive SOC Phase 2 — Identity Graph Updater
Maintains the Living Identity Graph in Amazon Neptune.
Tracks relationships between entities, resources, and behaviors.

Graph Schema:
  Nodes:  Entity (IAMUser, IAMRole, EC2, Lambda, S3Bucket)
  Edges:  accessed(entity→resource), assumed_by(role→entity),
          called_from(entity→ip), used_service(entity→service)

This graph enables:
- Lateral movement detection (entity suddenly accessing new resource clusters)
- Blast radius analysis (what did a compromised entity touch?)
- Relationship anomalies (entity accessing resources outside its normal cluster)
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

NEPTUNE_ENDPOINT = os.environ.get("NEPTUNE_ENDPOINT", "")
ENVIRONMENT      = os.environ.get("ENVIRONMENT", "dev")
dynamodb         = boto3.resource("dynamodb")
GRAPH_TABLE      = f"cognitive-soc-graph-{ENVIRONMENT}"  # DynamoDB fallback when Neptune not configured


def lambda_handler(event, context):
    """Update the identity graph with a new behavioral event."""
    identity = event.get("identity", {})
    signal   = event.get("signal", {})
    ct_event = event.get("event", {})

    entity_id = identity.get("entity_id")
    if not entity_id:
        return {"updated": False, "reason": "no_entity_id"}

    # Use DynamoDB as graph store (Neptune alternative for dev/low cost)
    # In production, replace with Neptune Gremlin queries
    update_graph(entity_id, identity, signal, ct_event)

    return {"updated": True, "entity_id": entity_id}


def update_graph(entity_id, identity, signal, ct_event):
    """
    Update graph relationships. Uses DynamoDB adjacency list pattern.
    Each item represents an edge: entity → related_node.
    """
    table     = dynamodb.Table(GRAPH_TABLE)
    timestamp = datetime.utcnow().isoformat()

    # Edge 1: Entity used this service
    if signal.get("service"):
        upsert_edge(table, entity_id, f"service:{signal['service']}", "used_service", timestamp)

    # Edge 2: Entity called from this region
    if signal.get("aws_region"):
        upsert_edge(table, entity_id, f"region:{signal['aws_region']}", "called_from_region", timestamp)

    # Edge 3: Entity called from this IP (track last 10 unique IPs)
    if signal.get("source_ip") and not signal["source_ip"].startswith("AWS"):
        upsert_edge(table, entity_id, f"ip:{signal['source_ip']}", "called_from_ip", timestamp)

    # Edge 4: Entity performed this action
    if signal.get("action"):
        upsert_edge(table, entity_id, f"action:{signal['action']}", "performed_action", timestamp)

    # Edge 5: Entity accessed these resources
    for resource_arn in signal.get("resources", []):
        if resource_arn:
            resource_type = extract_resource_type(resource_arn)
            upsert_edge(table, entity_id, f"resource:{resource_arn[:100]}", f"accessed_{resource_type}", timestamp)


def upsert_edge(table, from_node, to_node, edge_type, timestamp):
    """Create or update a graph edge in DynamoDB."""
    edge_id = f"{from_node}|{edge_type}|{to_node}"
    try:
        table.update_item(
            Key={"edge_id": edge_id},
            UpdateExpression=(
                "SET from_node = :fn, to_node = :tn, edge_type = :et, "
                "last_seen = :ls, #cnt = if_not_exists(#cnt, :zero) + :one"
            ),
            ExpressionAttributeNames={"#cnt": "traversal_count"},
            ExpressionAttributeValues={
                ":fn":   from_node,
                ":tn":   to_node,
                ":et":   edge_type,
                ":ls":   timestamp,
                ":zero": 0,
                ":one":  1,
            }
        )
    except Exception as e:
        logger.debug(f"Graph edge upsert failed (non-fatal): {str(e)}")


def extract_resource_type(arn):
    """Extract resource type from ARN for edge labeling."""
    if not arn or ":" not in arn:
        return "resource"
    parts = arn.split(":")
    if len(parts) >= 3:
        service = parts[2]
        return service
    return "resource"


def query_entity_neighbors(entity_id, edge_type=None):
    """
    Query all nodes connected to an entity.
    Used for blast radius analysis during incident response.
    """
    table = dynamodb.Table(GRAPH_TABLE)
    try:
        from boto3.dynamodb.conditions import Key, Attr
        if edge_type:
            response = table.scan(
                FilterExpression=Attr("from_node").eq(entity_id) & Attr("edge_type").eq(edge_type)
            )
        else:
            response = table.scan(
                FilterExpression=Attr("from_node").eq(entity_id)
            )
        return response.get("Items", [])
    except Exception as e:
        logger.error(f"Graph query failed: {str(e)}")
        return []


def get_blast_radius(entity_id):
    """
    Get everything a compromised entity has touched.
    Called during incident response to assess impact.
    """
    edges    = query_entity_neighbors(entity_id)
    resources = [e for e in edges if e.get("edge_type", "").startswith("accessed_")]
    services  = [e for e in edges if e.get("edge_type") == "used_service"]
    ips       = [e for e in edges if e.get("edge_type") == "called_from_ip"]

    return {
        "entity_id":       entity_id,
        "total_edges":     len(edges),
        "resources_touched": [e["to_node"] for e in resources],
        "services_used":   [e["to_node"] for e in services],
        "source_ips":      [e["to_node"] for e in ips],
        "blast_radius":    len(resources),
    }
