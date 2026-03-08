# Architecture — Cognitive SOC

## Data Flow
```
GuardDuty Finding
→ EventBridge (severity >= 4)
→ SOAR Orchestrator Lambda
  ├── Store to S3
  ├── Record in DynamoDB
  ├── Enrich (MITRE ATT&CK + AbuseIPDB)
  ├── Route to Playbook
  │   ├── EC2 Isolator
  │   ├── IAM Revoker
  │   ├── S3 Protector
  │   └── IP Blocker
  └── Notify (SNS + Slack + PagerDuty)
```

## Phase Roadmap
| Phase | Feature | Status |
|---|---|---|
| 1 | GuardDuty + SOAR + Alerting | ✅ Complete |
| 2 | Behavioral DNA (Neptune) | 🔜 Next |
| 3 | AI Investigation (Bedrock) | 🔜 Planned |
| 4 | Deception Orchestration | 🔜 Planned |
| 5 | Federated Threat Intel | 🔜 Planned |
