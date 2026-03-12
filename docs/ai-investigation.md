# Cognitive SOC — Phase 03: Autonomous AI Investigation

## Overview

Phase 03 replaces Tier-1 SOC analysts with an autonomous AI investigation agent powered by Claude claude-sonnet-4-6 via AWS Bedrock. When a High or Critical security alert fires — from either Phase 01 (GuardDuty) or Phase 02 (Behavioral DNA) — Phase 03 investigates it fully in under 60 seconds and produces a complete incident report.

**Status:** ⚡ In Progress  
**Preceded by:** Phase 02 — Attacker Intent Prediction  
**Followed by:** Phase 04 — Deception Orchestration

---

## Architecture

```
GuardDuty Finding (Phase 01)          Behavioral Anomaly (Phase 02)
         │                                        │
         └──────────────┬─────────────────────────┘
                        ▼
              alert_ingestor (Lambda)
              ┌─────────────────────┐
              │ • Normalise finding  │
              │ • Severity gate      │
              │ • Phase 1 enrichment │
              │ • Trigger SFN        │
              └──────────┬──────────┘
                         │
                         ▼
              ┌── Step Functions ──────────────────────────────────────┐
              │                                                         │
              │  triage_engine ──► [DISMISS] ──► End (suppressed)      │
              │       │                                                 │
              │  [INVESTIGATE]                                          │
              │       │                                                 │
              │  context_gatherer (parallel)                            │
              │  ├── Neptune behavioral baseline                        │
              │  ├── Athena 90-day CloudTrail history                   │
              │  ├── DynamoDB entity history                            │
              │  └── IOC enrichment (VirusTotal + AbuseIPDB)            │
              │       │                                                 │
              │  bedrock_investigator                                   │
              │  └── Claude claude-sonnet-4-6 reasons over full context │
              │       │                                                 │
              │  report_generator                                       │
              │  ├── Technical report (Markdown → S3)                  │
              │  └── Executive summary (Markdown → S3)                 │
              │       │                                                 │
              │  investigation_delivery                                 │
              │  ├── Slack notification                                 │
              │  ├── SNS email (Critical only)                         │
              │  └── SOAR auto-trigger (if auto_response_safe=true)    │
              └─────────────────────────────────────────────────────────┘
```

---

## New Files (Phase 03)

| File | Purpose |
|---|---|
| `lambda/alert_ingestor/handler.py` | Entry point — normalises GuardDuty and behavioral alerts, triggers Step Functions |
| `lambda/triage_engine/handler.py` | False positive classifier — INVESTIGATE / MONITOR / DISMISS |
| `lambda/context_gatherer/handler.py` | Assembles full investigation context: Neptune + Athena + IOC enrichment |
| `lambda/bedrock_investigator/handler.py` | Claude AI investigation agent via AWS Bedrock |
| `lambda/report_generator/handler.py` | Formats investigation JSON into technical + executive reports, stores in S3 |
| `lambda/investigation_delivery/handler.py` | Delivers reports via Slack/SNS, triggers SOAR if auto_response_safe |
| `terraform/modules/stepfunctions/main.tf` | Step Functions Express Workflow orchestrating the 6-step pipeline |
| `terraform/modules/athena/main.tf` | Athena workgroup, Glue database, CloudTrail table, named forensic queries |
| `docs/ai-investigation.md` | This file |

---

## AWS Services (Phase 03)

| Service | Role |
|---|---|
| AWS Bedrock (Claude claude-sonnet-4-6) | AI investigation agent — reasoning, timeline reconstruction, report generation |
| AWS Step Functions (Express) | Investigation workflow orchestration, retry logic, state management |
| Amazon Athena | SQL queries over 90-day CloudTrail history in S3 |
| AWS Glue | CloudTrail log schema catalog for Athena |
| Amazon S3 | CloudTrail logs (existing) + investigation reports archive |
| Amazon Neptune | Behavioral baseline lookup (Phase 01/02 data) |
| Amazon DynamoDB | Investigation records, triage history, IOC cache |
| AWS Secrets Manager | API keys for AbuseIPDB, VirusTotal, Slack webhook |
| Amazon SNS | Email notifications for Critical findings |
| AWS Lambda | All 6 processing functions |
| Amazon CloudWatch | Lambda logs, Step Functions execution traces, Bedrock call metrics |

---

## Investigation Report Schema

Every investigation produces a structured JSON report with these fields:

```json
{
  "triage_decision": "CONFIRMED_THREAT | PROBABLE_THREAT | FALSE_POSITIVE",
  "confidence_score": 0-100,
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "executive_summary": "2-3 sentence plain English summary",
  "what_happened": "Detailed narrative of the incident",
  "attack_timeline": [{"time": "...", "action": "...", "significance": "..."}],
  "affected_resources": [{"resource": "...", "risk": "...", "action_taken": "..."}],
  "mitre_chain": [{"tactic": "...", "technique": "...", "technique_name": "...", "evidence": "..."}],
  "behavioral_evidence": [{"dimension": "...", "anomaly": "...", "score": 0}],
  "ioc_findings": [{"ioc": "...", "reputation": "...", "confidence": 0, "detail": "..."}],
  "recommended_actions": [{"priority": "...", "action": "...", "rationale": "...", "soar_playbook": "..."}],
  "false_positive_indicators": ["..."],
  "investigation_notes": "Caveats and limitations",
  "requires_human_review": true,
  "auto_response_safe": false
}
```

---

## Auto-Response Safety Rules

`auto_response_safe: true` requires ALL of the following:
1. `triage_decision` = `CONFIRMED_THREAT`
2. `confidence_score` ≥ 85
3. Claude judges the SOAR action as safe and reversible
4. Hard enforcement layer in `bedrock_investigator.py` overrides Claude if rules not met

---

## SOAR Integration (Phase 01 ↔ Phase 03)

Phase 03 can trigger Phase 01 SOAR playbooks automatically:

| AI Recommendation | Phase 01 Playbook |
|---|---|
| `ec2_isolator` | Isolate EC2 instance — remove from security group |
| `iam_revoker` | Revoke IAM credentials + active sessions |
| `ip_blocker` | Block source IP in WAF |
| `s3_protector` | Re-apply S3 bucket protections |

---

## DynamoDB Tables (Phase 03)

| Table | Purpose |
|---|---|
| `cognitive-soc-investigations-{env}` | Investigation records: status, triage decision, report S3 paths |
| `cognitive-soc-triage-history-{env}` | Per-entity false positive learning: repeat alert counts |
| `cognitive-soc-ioc-cache-{env}` | IOC reputation cache (24hr TTL) |

---

## Environment Variables

### alert_ingestor
| Variable | Description | Default |
|---|---|---|
| `INVESTIGATION_SFN_ARN` | Step Functions state machine ARN | Required |
| `MIN_SEVERITY_GUARDDUTY` | Minimum GuardDuty severity (0-10) | `7.0` |
| `MIN_SCORE_BEHAVIORAL` | Minimum behavioral anomaly score (0-100) | `85.0` |

### context_gatherer
| Variable | Description | Default |
|---|---|---|
| `ATHENA_DB` | Glue/Athena database name | `cognitive_soc_cloudtrail` |
| `ATHENA_OUTPUT_BUCKET` | S3 bucket for Athena results | Required |
| `CLOUDTRAIL_LOOKBACK_DAYS` | Days of CloudTrail history to query | `90` |

### bedrock_investigator
| Variable | Description | Default |
|---|---|---|
| `BEDROCK_MODEL` | Bedrock model ID | `anthropic.claude-sonnet-4-20250514-v2:0` |
| `BEDROCK_REGION` | AWS region for Bedrock | `us-east-1` |
| `BEDROCK_MAX_TOKENS` | Max tokens in investigation response | `4096` |
| `BEDROCK_TEMPERATURE` | Temperature (low = consistent) | `0.1` |

### report_generator
| Variable | Description | Default |
|---|---|---|
| `REPORTS_BUCKET` | S3 bucket for investigation reports | `cognitive-soc-reports-{env}` |

---

## Performance Targets

| Metric | Target | Minimum |
|---|---|---|
| End-to-end investigation time | < 60 seconds | < 90 seconds |
| False positive filter accuracy | ≥ 85% | ≥ 75% |
| Bedrock JSON schema compliance | 100% | 95% |
| IOC enrichment coverage | ≥ 90% of IPs | ≥ 75% |
| SOAR auto-trigger precision | ≥ 95% | ≥ 90% |

---

## Getting Started in GitHub Codespaces

### 1. Enable Bedrock Model Access
Go to AWS Console → Bedrock → Model Access → Request access for:
- `Anthropic Claude claude-sonnet-4-6`

### 2. Store Secrets
```bash
aws secretsmanager create-secret --name cognitive-soc/abuseipdb-api-key --secret-string "YOUR_KEY"
aws secretsmanager create-secret --name cognitive-soc/virustotal-api-key --secret-string "YOUR_KEY"
aws secretsmanager create-secret --name cognitive-soc/slack-webhook --secret-string "https://hooks.slack.com/..."
```

### 3. Deploy Terraform
```bash
cd terraform/environments/dev
terraform init
terraform plan
terraform apply
```

### 4. Test the Pipeline
```bash
# Invoke alert_ingestor with a test GuardDuty finding
aws lambda invoke \
  --function-name cognitive-soc-alert_ingestor-dev \
  --payload file://tests/fixtures/guardduty_high_finding.json \
  response.json
cat response.json
```
