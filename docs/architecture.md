# Architecture Deep Dive — Cognitive SOC

## Overview

Cognitive SOC uses an event-driven, serverless architecture on AWS. Every component is
loosely coupled through EventBridge, meaning each layer can be upgraded independently
without rebuilding the entire system.

## Data Flow

```
GuardDuty Finding Generated
         │
         ▼
EventBridge Rule (severity >= 4.0)
         │
         ▼
SOAR Orchestrator Lambda
    ├── Store raw finding → S3
    ├── Record state → DynamoDB
    ├── Invoke Enrichment Lambda
    │       └── Query AbuseIPDB / VirusTotal
    │       └── Map to MITRE ATT&CK
    ├── Route to Playbook Lambda
    │       ├── EC2 Isolator
    │       ├── IAM Revoker
    │       ├── S3 Protector
    │       └── IP Blocker
    └── Invoke Notifier Lambda (async)
            ├── SNS → Email
            ├── Slack Webhook
            └── PagerDuty (Critical only)
```

## Phase Roadmap

| Phase | Features | AWS Services Added |
|---|---|---|
| **1 (Current)** | GuardDuty + SOAR + Alerting | GuardDuty, EventBridge, Lambda, SNS, DynamoDB, S3 |
| **2** | Behavioral DNA Fingerprinting | Neptune, Kinesis, CloudTrail |
| **3** | AI Investigation Agent | Bedrock (Claude), Athena, Step Functions |
| **4** | Deception Orchestration | Lambda, API Gateway, CloudFront |
| **5** | Federated Threat Intel | EventBridge cross-account, Organizations |

## Security Controls

- All Lambda functions use least-privilege IAM roles
- All S3 buckets have Block Public Access enabled + AES256 encryption
- All DynamoDB tables have encryption at rest + point-in-time recovery
- All Lambda functions have X-Ray tracing enabled
- CloudWatch log groups with 30-day retention
- Secrets stored in AWS Secrets Manager (never in environment variables)
