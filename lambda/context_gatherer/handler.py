"""
Cognitive SOC Phase 3 — Context Gatherer
Assembles the full investigation context package for the Bedrock AI agent.

Runs 4 parallel data fetches:
  A. Neptune   — entity behavioral baseline (Phase 1/2 data)
  B. Athena    — 90-day CloudTrail forensic history
  C. DynamoDB  — entity triage history and past incidents
  D. IOC Enrichment — VirusTotal + AbuseIPDB + AlienVault for all IPs/domains

All results are merged into a single context package handed to bedrock_investigator.
Parallel execution via Python threading — target: full context in under 15 seconds.
"""

import json
import logging
import os
import boto3
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

dynamodb       = boto3.resource("dynamodb")
athena_client  = boto3.client("athena")
secretsmanager = boto3.client("secretsmanager")

ENVIRONMENT       = os.environ.get("ENVIRONMENT", "dev")
ATHENA_DB         = os.environ.get("ATHENA_DB", "cognitive_soc_cloudtrail")
ATHENA_OUTPUT     = os.environ.get("ATHENA_OUTPUT_BUCKET", "")
BASELINE_TABLE    = f"cognitive-soc-baselines-{ENVIRONMENT}"
INCIDENTS_TABLE   = f"cognitive-soc-incidents-{ENVIRONMENT}"
IOC_CACHE_TABLE   = f"cognitive-soc-ioc-cache-{ENVIRONMENT}"

CLOUDTRAIL_LOOKBACK_DAYS = int(os.environ.get("CLOUDTRAIL_LOOKBACK_DAYS", "90"))
MAX_CLOUDTRAIL_EVENTS    = int(os.environ.get("MAX_CLOUDTRAIL_EVENTS", "200"))


def lambda_handler(event, context):
    """
    Gather all investigation context for the entity in this finding.
    Called by Step Functions as step 3.
    """
    logger.info("Context Gatherer triggered")

    finding   = event
    entity_id = finding.get("entity_id", "unknown")
    region    = finding.get("region", "")

    # Extract all IPs from the finding for IOC enrichment
    iocs = extract_iocs(finding)
    logger.info(f"Gathering context for entity={entity_id}, IOCs={iocs}")

    # Run all data fetches in parallel
    results = {}
    tasks = {
        "behavioral_baseline": lambda: fetch_behavioral_baseline(entity_id),
        "cloudtrail_events":   lambda: fetch_cloudtrail_events(entity_id, region),
        "entity_history":      lambda: fetch_entity_history(entity_id),
        "ioc_enrichment":      lambda: enrich_all_iocs(iocs),
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures, timeout=55):
            name = futures[future]
            try:
                results[name] = future.result()
                logger.info(f"Context task completed: {name}")
            except Exception as e:
                logger.warning(f"Context task failed ({name}): {str(e)} — using empty fallback")
                results[name] = {"error": str(e), "available": False}

    # Build peer comparison summary from behavioral baseline
    peer_comparison = build_peer_comparison(results.get("behavioral_baseline", {}), entity_id)

    # Assemble the full context package
    context_package = {
        **finding,
        "context_gathered_at":  datetime.utcnow().isoformat(),
        "entity_id":            entity_id,
        "behavioral_baseline":  results.get("behavioral_baseline", {}),
        "cloudtrail_events":    results.get("cloudtrail_events", []),
        "entity_history":       results.get("entity_history", {}),
        "ioc_enrichment":       results.get("ioc_enrichment", {}),
        "peer_comparison":      peer_comparison,
        "context_summary": {
            "cloudtrail_event_count":  len(results.get("cloudtrail_events", [])),
            "ioc_count":               len(iocs),
            "has_behavioral_baseline": bool(results.get("behavioral_baseline", {}).get("entity_id")),
            "past_incidents":          results.get("entity_history", {}).get("incident_count", 0),
        }
    }

    logger.info(
        f"Context assembled for {entity_id}: "
        f"{context_package['context_summary']['cloudtrail_event_count']} CloudTrail events, "
        f"{context_package['context_summary']['ioc_count']} IOCs enriched"
    )
    return context_package


# ── A. Behavioral Baseline (DynamoDB — Phase 1/2) ────────────────────────────

def fetch_behavioral_baseline(entity_id):
    """Fetch entity's behavioral baseline from Phase 1/2 DynamoDB table."""
    try:
        table    = dynamodb.Table(BASELINE_TABLE)
        response = table.get_item(Key={"entity_id": entity_id})
        item     = response.get("Item")
        if not item:
            logger.info(f"No baseline found for {entity_id}")
            return {"available": False, "entity_id": entity_id}

        # Convert Decimal to float for JSON serialisation
        return json.loads(json.dumps(item, default=decimal_to_float))
    except Exception as e:
        logger.warning(f"Baseline fetch failed for {entity_id}: {str(e)}")
        return {"available": False, "entity_id": entity_id, "error": str(e)}


# ── B. CloudTrail History (Athena) ───────────────────────────────────────────

def fetch_cloudtrail_events(entity_id, region):
    """
    Query 90-day CloudTrail history for this entity via Athena.
    Returns up to MAX_CLOUDTRAIL_EVENTS most recent events.
    """
    if not ATHENA_OUTPUT:
        logger.warning("ATHENA_OUTPUT_BUCKET not configured — skipping CloudTrail query")
        return []

    query = build_cloudtrail_query(entity_id)
    try:
        execution_id = start_athena_query(query)
        events       = wait_for_athena_results(execution_id)
        logger.info(f"CloudTrail query returned {len(events)} events for {entity_id}")
        return events
    except Exception as e:
        logger.warning(f"CloudTrail Athena query failed (non-fatal): {str(e)}")
        return []


def build_cloudtrail_query(entity_id):
    """Build the Athena SQL query for CloudTrail events."""
    # Escape entity_id to prevent SQL injection
    safe_entity = entity_id.replace("'", "''")
    return f"""
        SELECT
            eventtime,
            eventname,
            eventsource,
            sourceipaddress,
            awsregion,
            errorcode,
            errormessage,
            requestparameters,
            responseelements,
            useridentity.type        AS identity_type,
            useridentity.arn         AS identity_arn,
            useridentity.accountid   AS identity_account
        FROM {ATHENA_DB}.cloudtrail_logs
        WHERE (
            useridentity.arn LIKE '%{safe_entity}%'
            OR useridentity.username = '{safe_entity}'
            OR useridentity.principalid LIKE '%{safe_entity}%'
        )
        AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '{CLOUDTRAIL_LOOKBACK_DAYS}' day
        ORDER BY eventtime DESC
        LIMIT {MAX_CLOUDTRAIL_EVENTS}
    """


def start_athena_query(query):
    """Submit Athena query and return execution ID."""
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": ATHENA_DB},
        ResultConfiguration={
            "OutputLocation": f"s3://{ATHENA_OUTPUT}/phase3-investigations/",
            "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"},
        },
        WorkGroup=os.environ.get("ATHENA_WORKGROUP", "primary"),
    )
    return response["QueryExecutionId"]


def wait_for_athena_results(execution_id, max_wait=50, poll_interval=2):
    """
    Poll Athena until query completes, then return results.
    max_wait seconds total — Lambda timeout is 60s so we stay well within it.
    """
    import time
    waited = 0
    while waited < max_wait:
        status = athena_client.get_query_execution(QueryExecutionId=execution_id)
        state  = status["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            return parse_athena_results(execution_id)
        if state in ("FAILED", "CANCELLED"):
            reason = status["QueryExecution"]["Status"].get("StateChangeReason", "Unknown")
            raise Exception(f"Athena query {state}: {reason}")

        time.sleep(poll_interval)
        waited += poll_interval

    raise Exception(f"Athena query timed out after {max_wait}s")


def parse_athena_results(execution_id):
    """Parse Athena ResultSet into a list of event dicts."""
    response = athena_client.get_query_results(
        QueryExecutionId=execution_id,
        MaxResults=MAX_CLOUDTRAIL_EVENTS
    )
    rows      = response["ResultSet"]["Rows"]
    if not rows:
        return []

    # First row is column headers
    headers = [col["VarCharValue"] for col in rows[0]["Data"]]
    events  = []
    for row in rows[1:]:
        values = [cell.get("VarCharValue", "") for cell in row["Data"]]
        events.append(dict(zip(headers, values)))

    return events


# ── C. Entity History (DynamoDB) ─────────────────────────────────────────────

def fetch_entity_history(entity_id):
    """Fetch past incidents and triage decisions for this entity."""
    try:
        table    = dynamodb.Table(INCIDENTS_TABLE)
        response = table.query(
            IndexName="entity_id-index",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("entity_id").eq(entity_id),
            ScanIndexForward=False,
            Limit=10,
        )
        items          = response.get("Items", [])
        incident_count = len(items)
        confirmed      = sum(1 for i in items if i.get("status") == "CONFIRMED_THREAT")

        return {
            "available":      True,
            "incident_count": incident_count,
            "confirmed_threats": confirmed,
            "recent_incidents":  [
                {
                    "finding_type": i.get("type", ""),
                    "severity":     i.get("severity", ""),
                    "status":       i.get("status", ""),
                    "created_at":   i.get("created_at", ""),
                }
                for i in items[:5]
            ]
        }
    except Exception as e:
        logger.debug(f"Entity history lookup failed (non-fatal): {str(e)}")
        return {"available": False, "incident_count": 0, "confirmed_threats": 0, "error": str(e)}


# ── D. IOC Enrichment ────────────────────────────────────────────────────────

def extract_iocs(finding):
    """
    Extract all IP addresses, domains, and hashes from the finding.
    Checks both the raw finding and the Phase 1 enrichment.
    """
    iocs = {"ips": [], "domains": [], "hashes": []}

    # From Phase 1 enrichment
    enrichment = finding.get("enrichment", {})
    remote_ip  = enrichment.get("remote_ip", "")
    if remote_ip:
        iocs["ips"].append(remote_ip)

    # From raw GuardDuty service block
    service = finding.get("raw_service", {})
    action  = service.get("action", {})

    # Network connection action
    net_action = action.get("networkConnectionAction", {})
    net_ip     = net_action.get("remoteIpDetails", {}).get("ipAddressV4", "")
    if net_ip and net_ip not in iocs["ips"]:
        iocs["ips"].append(net_ip)

    # API call action
    api_action = action.get("awsApiCallAction", {})
    api_ip     = api_action.get("remoteIpDetails", {}).get("ipAddressV4", "")
    if api_ip and api_ip not in iocs["ips"]:
        iocs["ips"].append(api_ip)

    # Deduplicate and filter out private/local IPs
    iocs["ips"] = [ip for ip in iocs["ips"] if ip and not is_private_ip(ip)]
    return iocs


def enrich_all_iocs(iocs):
    """Enrich all extracted IOCs using available threat intel APIs."""
    enriched = {"ips": {}, "domains": {}, "enriched_count": 0}

    for ip in iocs.get("ips", []):
        result = enrich_ip_cached(ip)
        enriched["ips"][ip] = result
        if result.get("source") != "cache_miss":
            enriched["enriched_count"] += 1

    return enriched


def enrich_ip_cached(ip):
    """Check DynamoDB cache before calling external APIs."""
    # Check cache first
    cached = get_ioc_cache(ip)
    if cached:
        logger.debug(f"IOC cache hit for {ip}")
        return {**cached, "from_cache": True}

    result = {"ip": ip, "source": "cache_miss", "is_known_malicious": False, "confidence_score": 0}

    # Try AbuseIPDB
    try:
        api_key = get_secret("cognitive-soc/abuseipdb-api-key")
        if api_key:
            result = query_abuseipdb(ip, api_key)
    except Exception as e:
        logger.debug(f"AbuseIPDB failed for {ip}: {str(e)}")

    # Try VirusTotal if AbuseIPDB didn't confirm
    if not result.get("is_known_malicious"):
        try:
            vt_key = get_secret("cognitive-soc/virustotal-api-key")
            if vt_key:
                vt_result = query_virustotal_ip(ip, vt_key)
                if vt_result.get("malicious_votes", 0) > 3:
                    result["virustotal"] = vt_result
                    result["is_known_malicious"] = True
                    result["confidence_score"]   = min(100, result.get("confidence_score", 0) + 30)
        except Exception as e:
            logger.debug(f"VirusTotal failed for {ip}: {str(e)}")

    # Cache the result for 24 hours
    cache_ioc_result(ip, result)
    return result


def query_abuseipdb(ip, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.loads(resp.read().decode())["data"]
        return {
            "ip":                  ip,
            "source":              "abuseipdb",
            "is_known_malicious":  data.get("abuseConfidenceScore", 0) >= 50,
            "confidence_score":    data.get("abuseConfidenceScore", 0),
            "country":             data.get("countryCode", ""),
            "isp":                 data.get("isp", ""),
            "total_reports":       data.get("totalReports", 0),
            "last_reported":       data.get("lastReportedAt", ""),
        }


def query_virustotal_ip(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    with urllib.request.urlopen(req, timeout=8) as resp:
        data    = json.loads(resp.read().decode())
        stats   = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious_votes":  stats.get("malicious", 0),
            "harmless_votes":   stats.get("harmless", 0),
            "suspicious_votes": stats.get("suspicious", 0),
        }


# ── IOC Cache ────────────────────────────────────────────────────────────────

def get_ioc_cache(ip):
    try:
        table    = dynamodb.Table(IOC_CACHE_TABLE)
        response = table.get_item(Key={"ioc_value": ip})
        return response.get("Item", {}).get("enrichment_data")
    except Exception:
        return None


def cache_ioc_result(ip, data):
    try:
        table = dynamodb.Table(IOC_CACHE_TABLE)
        table.put_item(Item={
            "ioc_value":        ip,
            "enrichment_data":  data,
            "ttl":              int(datetime.utcnow().timestamp()) + (24 * 3600),
        })
    except Exception:
        pass


# ── Peer Comparison ──────────────────────────────────────────────────────────

def build_peer_comparison(baseline, entity_id):
    """Build a peer comparison summary from the behavioral baseline."""
    if not baseline.get("entity_id"):
        return {"available": False}

    peer_group = baseline.get("peer_group", "Unknown")
    peer_similarity = float(baseline.get("peer_similarity_score", 0.5))

    return {
        "available":        True,
        "peer_group":       peer_group,
        "similarity_score": peer_similarity,
        "interpretation":   interpret_peer_similarity(peer_similarity),
    }


def interpret_peer_similarity(score):
    if score < 0.2:  return "Entity behavior is highly unusual compared to peer group"
    if score < 0.4:  return "Entity behavior shows significant deviation from peer group"
    if score < 0.6:  return "Entity behavior is somewhat unusual compared to peer group"
    return "Entity behavior is consistent with peer group"


# ── Utilities ────────────────────────────────────────────────────────────────

def is_private_ip(ip):
    """Return True if IP is RFC1918 private or loopback."""
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "169.254.")
    return any(ip.startswith(p) for p in private_prefixes)


def decimal_to_float(obj):
    from decimal import Decimal
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def get_secret(secret_name):
    try:
        response = secretsmanager.get_secret_value(SecretId=secret_name)
        return response.get("SecretString", "")
    except Exception:
        return None
