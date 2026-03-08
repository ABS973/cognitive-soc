# 🧠 Cognitive SOC
### The World's First Self-Learning, Predictive, AI-Augmented Cloud Security Operations Platform

[![AWS](https://img.shields.io/badge/AWS-Powered-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Terraform](https://img.shields.io/badge/Terraform-IaC-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)](https://terraform.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase%201%20Active-blue?style=for-the-badge)]()

> **Built by [Ahmed](https://github.com/ahmed) | SecureOps Labs Inc. 🇧🇭**

---

## ⚡ What Is Cognitive SOC?

Cognitive SOC gives any AWS-based organization a **fully autonomous, AI-powered Security Operations Center** — deployed in under 30 minutes, requiring zero full-time security staff to operate.

Most companies can't afford a real SOC. A traditional enterprise SOC costs **$2–5M/year** in headcount alone. Cognitive SOC changes that.

```
Traditional SOC:  Alert fires → Human investigates (hours) → Human responds (more hours)
Cognitive SOC:    Alert fires → AI investigates (60 seconds) → Auto-response (instant)
```

---

## 🔬 The 5 Innovations

| Innovation | What It Does | Status |
|---|---|---|
| 🧬 **Behavioral DNA Fingerprinting** | Per-entity micro-baselines detecting insider threats & account compromise | 🔜 Phase 2 |
| 🔮 **Attacker Intent Prediction** | MITRE ATT&CK kill chain modeling — predicts next attack step, pre-hardens defenses | 🔜 Phase 3 |
| 🕵️ **Deception Orchestration** | Feeds attackers convincing fake environments while profiling their TTPs | 🔜 Phase 4 |
| 🤖 **Autonomous AI Investigation** | LLM-powered agent delivers full incident report in 60 seconds | 🔜 Phase 3 |
| 🌐 **Federated Threat Intelligence** | Novel attacks seen anywhere auto-harden all accounts in the network | 🔜 Phase 5 |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA SOURCES LAYER                          │
│  CloudTrail │ VPC Flow Logs │ GuardDuty │ Security Hub │ WAF   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     INGESTION LAYER                             │
│         EventBridge Rules → Kinesis Firehose → S3              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                   SOAR ORCHESTRATION LAYER                      │
│     Lambda Orchestrator → Step Functions → Playbook Lambdas    │
│   [EC2 Isolator] [IAM Revoker] [S3 Protector] [IP Blocker]    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                   INTELLIGENCE LAYER                            │
│    Enrichment Lambda → VirusTotal / AbuseIPDB / AlienVault     │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                   NOTIFICATION LAYER                            │
│              SNS → Slack / PagerDuty / Email                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
cognitive-soc/
├── README.md
├── terraform/
│   ├── environments/
│   │   └── dev/                  # Dev environment config
│   └── modules/
│       ├── guardduty/            # GuardDuty enablement
│       ├── eventbridge/          # Event routing rules
│       ├── lambda/               # Lambda deployments
│       ├── iam/                  # IAM roles & policies
│       └── sns/                  # Notification topics
├── lambda/
│   ├── guardduty_ingestor/       # Ingests & normalizes GuardDuty findings
│   ├── soar_orchestrator/        # Routes findings to correct playbook
│   ├── ec2_isolator/             # Isolates compromised EC2 instances
│   ├── iam_revoker/              # Revokes compromised IAM credentials
│   ├── s3_protector/             # Re-applies S3 security controls
│   ├── ip_blocker/               # Adds malicious IPs to WAF deny list
│   ├── enrichment/               # Threat intel enrichment
│   └── notifier/                 # Slack/email/PagerDuty alerts
├── docs/
│   ├── architecture.md
│   ├── behavioral-dna.md         # Phase 2
│   ├── threat-prediction.md      # Phase 3
│   ├── deception-layer.md        # Phase 4
│   ├── ai-investigation.md       # Phase 3
│   └── federated-intel.md        # Phase 5
├── playbooks/
│   └── README.md
└── tests/
    └── unit/
```

---

## 🚀 Quick Start

### Prerequisites
- AWS Account with admin access
- Terraform >= 1.5
- Python 3.11+
- AWS CLI configured

### Deploy in 3 Steps

```bash
# 1. Clone the repo
git clone https://github.com/ahmed/cognitive-soc.git
cd cognitive-soc

# 2. Configure your environment
cp terraform/environments/dev/terraform.tfvars.example \
   terraform/environments/dev/terraform.tfvars
# Edit terraform.tfvars with your values

# 3. Deploy
cd terraform/environments/dev
terraform init
terraform plan
terraform apply
```

### What Gets Deployed
- GuardDuty enabled across your account
- EventBridge rules routing all findings
- 7 Lambda functions (SOAR playbooks)
- SNS topics for alerting
- IAM roles with least-privilege policies
- S3 bucket for finding storage

---

## 🛡️ Phase 1 — SOAR Playbooks

These playbooks execute automatically when GuardDuty fires a matching finding:

| Threat Type | GuardDuty Finding | Automated Response |
|---|---|---|
| Compromised EC2 | `UnauthorizedAccess:EC2/MaliciousIPCaller` | Isolate EC2 — replace SG with deny-all |
| Exposed Credentials | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | Revoke access key immediately |
| Crypto Mining | `CryptoCurrency:EC2/BitcoinTool` | Snapshot + terminate instance |
| S3 Public Exposure | `Policy:S3/BucketPublicAccessGranted` | Re-apply Block Public Access |
| Brute Force | `UnauthorizedAccess:EC2/SSHBruteForce` | Block source IP in WAF |
| Recon Activity | `Recon:IAMUser/MaliciousIPCaller` | Alert + increase logging verbosity |
| Root Account Login | `Policy:IAMUser/RootCredentialUsage` | Immediate SNS alert to all admins |

---

## 📊 Roadmap

- [x] **Phase 1** — GuardDuty + SOAR Pipeline + Terraform IaC
- [ ] **Phase 2** — Behavioral DNA Fingerprinting (Amazon Neptune)
- [ ] **Phase 3** — AI Investigation Agent (AWS Bedrock)
- [ ] **Phase 4** — Deception Orchestration Layer
- [ ] **Phase 5** — Federated Threat Intelligence Network
- [ ] **Phase 6** — SaaS Multi-Tenancy + Customer Dashboard

---

## 🔧 Tech Stack

| Layer | Service | Purpose |
|---|---|---|
| Detection | Amazon GuardDuty | ML-powered threat detection |
| Aggregation | AWS Security Hub | Centralized finding management |
| Routing | Amazon EventBridge | Event-driven SOAR triggering |
| Compute | AWS Lambda (Python) | Playbook execution |
| Orchestration | AWS Step Functions | Multi-step response workflows |
| Storage | Amazon S3 + DynamoDB | Finding storage + state management |
| Notifications | Amazon SNS | Multi-channel alerting |
| IaC | Terraform | Infrastructure as Code |
| Graph DB | Amazon Neptune | Behavioral DNA (Phase 2) |
| AI | AWS Bedrock (Claude) | Autonomous investigation (Phase 3) |

---

## 📄 Documentation

- [Architecture Deep Dive](docs/architecture.md)
- [Behavioral DNA Theory](docs/behavioral-dna.md)
- [Threat Prediction Engine](docs/threat-prediction.md)
- [Deception Layer](docs/deception-layer.md)
- [AI Investigation Agent](docs/ai-investigation.md)
- [Federated Threat Intel](docs/federated-intel.md)

---

## ⚠️ Disclaimer

This project is designed for **authorized security testing and defensive purposes only**. Deploy only in AWS accounts you own or have explicit written authorization to test. The deception layer features must comply with applicable computer fraud laws in your jurisdiction.

---

## 📬 Contact

**Ahmed** — Founder, SecureOps Labs Inc.
- 🌐 Website: *Coming Soon*
- 💼 LinkedIn: *Coming Soon*
- 🐦 Twitter/X: *Coming Soon*

---

<p align="center">
  <strong>Built with 🔐 from Bahrain 🇧🇭</strong><br/>
  <em>SecureOps Labs Inc. © 2025</em>
</p>
