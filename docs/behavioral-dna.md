# Phase 2 — Behavioral DNA Fingerprinting

## Overview

Phase 2 adds a self-learning behavioral layer on top of Phase 1's reactive SOAR pipeline.
Every entity in your AWS account gets a unique behavioral fingerprint built from their
historical API call patterns. Deviations from this fingerprint trigger alerts — even when
GuardDuty sees nothing suspicious.

## Architecture

```
CloudTrail (all API calls)
         │
         ▼
Kinesis Data Stream
         │
         ▼
CloudTrail Processor Lambda
    ├──► Behavioral Baseline Lambda  →  DynamoDB (Baselines Table)
    ├──► Anomaly Scorer Lambda       →  Score 0-100 → Alert if >= 70
    └──► Identity Graph Updater      →  DynamoDB (Graph Table)
                                              │
                                         Blast Radius
                                         Analysis
```

## The 8 Behavioral Dimensions

| Dimension | What It Tracks | Example Baseline |
|---|---|---|
| Temporal | Hour/day activity distribution | Active Mon-Fri, 09-17 UTC only |
| Geographic | AWS regions used | us-east-1 only (99% of calls) |
| Service | Which AWS services called | S3, EC2, RDS — never IAM |
| Action | Specific API calls made | GetObject, PutObject, DescribeInstances |
| Volume | Calls per hour/day | ~50 calls/hour average |
| Sequence | Order of API calls | Always S3 before RDS |
| Privilege | Permissions used vs granted | Never uses iam:* despite having it |
| Resource | Specific resources touched | Only accesses prod-bucket-* |

## Anomaly Scoring

Every new API call is scored against 5 models simultaneously:

```
New API Call
     │
     ├── Temporal Score   (0-100) — Is this an unusual time?
     ├── Geographic Score (0-100) — Is this an unusual region?
     ├── Service Score    (0-100) — Is this an unusual service?
     ├── Action Score     (0-100) — Is this an unusual action?
     └── Sequence Score   (0-100) — Is this an unusual pattern?
           │
           ▼
     Composite Score (weighted average)
           │
           ├── >= 95 → CRITICAL alert
           ├── >= 85 → HIGH alert
           ├── >= 70 → MEDIUM alert
           └── < 70  → Normal (logged only)
```

## Multi-Dimension Boost

If 3+ dimensions are simultaneously anomalous, the composite score is boosted by 30%.
This catches sophisticated attackers who try to stay under the radar on any single dimension.

## Living Identity Graph

Every entity's relationships are tracked in a graph:
- `entity → service` (which services does this entity use?)
- `entity → region` (which regions does this entity operate in?)
- `entity → resource` (which specific resources has this entity touched?)
- `entity → ip` (which source IPs does this entity use?)

This enables **blast radius analysis**: when a compromise is detected,
instantly query everything the entity has ever touched.

## Phase 2 New Files

```
lambda/
├── cloudtrail_processor/   Entry point — fans out to all Phase 2 engines
├── behavioral_baseline/    Updates 8-dimension fingerprint per entity
├── anomaly_scorer/         Scores new events against baseline
├── identity_graph_updater/ Maintains Living Identity Graph
└── behavioral_alert/       Formats and sends behavioral anomaly alerts

terraform/modules/
├── kinesis/    Kinesis stream + CloudTrail integration
└── neptune/    DynamoDB tables (baselines, graph, anomaly scores)
```

## Minimum Observations

The anomaly scorer requires **100 API calls** before scoring an entity.
This prevents false positives on new users/roles that have no baseline yet.
Adjust `MIN_OBSERVATIONS` in `anomaly_scorer/handler.py` to change this.
