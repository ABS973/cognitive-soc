<div align="center">

![CognitiveSOC](https://img.shields.io/badge/SecureOps_Labs-CognitiveSOC-C00000?style=for-the-badge&logoColor=white)

# 🔵 CognitiveSOC
### The World's First Self-Learning, Predictive, AI-Augmented Cloud Security Operations Platform

[![AWS](https://img.shields.io/badge/AWS-Powered-FF9900?style=flat-square&logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=flat-square&logo=terraform&logoColor=white)](https://terraform.io)
[![Status](https://img.shields.io/badge/Status-Phase_03_In_Progress-orange?style=flat-square)](https://github.com/ABS973/cognitive-soc)
[![Progress](https://img.shields.io/badge/Phases_Complete-2%2F5-C00000?style=flat-square)](https://github.com/ABS973/cognitive-soc)

*Built by Ahmed | SecureOps Labs Inc. 🇧🇭*

</div>

---

## ⚡ What Is CognitiveSOC?

CognitiveSOC gives any AWS-based organization a **fully autonomous, AI-powered Security Operations Center** — deployed in under 30 minutes, requiring zero full-time security staff to operate.

Most companies can't afford a real SOC. A traditional enterprise SOC costs **$2–5M/year** in headcount alone. CognitiveSOC changes that.

```
Traditional SOC:  Alert fires → Human investigates (hours)   → Human responds (more hours)
CognitiveSOC:     Alert fires → AI investigates (60 seconds) → Auto-response (instant)
```

---

## 🗺️ Roadmap — 5 Phases

```
Phase 01 ████████████████████ 100% ✅  Behavioral DNA Engine
Phase 02 ████████████████████ 100% ✅  Attacker Intent Prediction
Phase 03 ▓▓░░░░░░░░░░░░░░░░░░       ⚡  Autonomous AI Investigation  ← CURRENT
Phase 04 ░░░░░░░░░░░░░░░░░░░░   0% 📋  Deception Orchestration
Phase 05 ░░░░░░░░░░░░░░░░░░░░   0% 📋  Federated Threat Intelligence
```

---

## 🔬 The 5 Innovations

| Innovation | What It Does | Status |
|-----------|--------------|--------|
| 🧬 **Behavioral DNA Fingerprinting** | Per-entity micro-baselines detecting insider threats & account compromise | ✅ Phase 01 |
| 🔮 **Attacker Intent Prediction** | MITRE ATT&CK kill chain modeling — predicts next attack step, pre-hardens defenses | ✅ Phase 02 |
| 🤖 **Autonomous AI Investigation** | LLM-powered agent delivers full incident report in 60 seconds | ⚡ Phase 03 |
| 🕵️ **Deception Orchestration** | Feeds attackers convincing fake environments while profiling their TTPs | 📋 Phase 04 |
| 🌐 **Federated Threat Intelligence** | Novel attacks seen anywhere auto-harden all accounts in the network | 📋 Phase 05 |

---

## ✅ Phase 01 — Behavioral DNA Engine *(Complete)*
> **Goal:** Detect compromised identities and abnormal behavior

<details>
<summary><b>View Features</b></summary>

### 🧬 Behavior Profiling
- User behavior baselines
- Service baselines
- API usage patterns
- Login location tracking
- Time-of-day activity patterns

### ⚠️ Anomaly Detection
- Impossible travel detection
- Unusual API usage
- Abnormal resource creation
- Suspicious access patterns

### 🕸️ Security Graph
- Asset inventory
- Identity-resource mapping
- Knowledge graph foundation (Amazon Neptune)

### 📊 Risk Scoring
- Entity risk score
- User risk score
- Service risk score

</details>

---

## ✅ Phase 02 — Attacker Intent Prediction *(Complete)*
> **Goal:** Predict attacker behavior before it happens

<details>
<summary><b>View Features</b></summary>

### 🔮 Attack Modeling
- MITRE ATT&CK mapping
- Attack stage classification
- Behavior pattern detection

### 🗺️ Attack Path Analysis
- Privilege escalation prediction
- Lateral movement prediction
- Data exfiltration paths

### 🛡️ Security Posture
- Environment risk score
- Asset risk ranking
- Attack path risk analysis

### 🔍 Threat Hunting
- Proactive anomaly queries
- Suspicious activity discovery

</details>

---

## ⚡ Phase 03 — Autonomous AI Investigation *(In Progress)*
> **Goal:** Replace Tier-1 SOC analysts entirely

<details>
<summary><b>View Features</b></summary>

### 🤖 Alert Triage
- Alert prioritization
- False positive filtering

### 🔬 Incident Analysis
- Event correlation
- Automated log searches
- Investigation queries

### 📅 Incident Reconstruction
- Attack timeline generation
- Attacker activity mapping

### 💬 AI Security Advisor
- Conversational investigation interface (AWS Bedrock / Claude)
- Auto incident report generation
- Executive summaries

</details>

---

## 📋 Phase 04 — Deception Orchestration *(Planned)*
> **Goal:** Detect attackers early using traps

<details>
<summary><b>View Features</b></summary>

### 🕵️ Honey Tokens
- Fake AWS keys
- Fake credentials
- Canary tokens

### 🏗️ Decoy Infrastructure
- Decoy EC2 instances
- Decoy S3 buckets
- Decoy IAM roles

### 👤 Attacker Profiling
- Capture attacker commands
- Record attacker tools
- Log IP behavior

### 🟣 Purple Team Simulation
- Integration with CognitivePentest (Red Team)
- Validate detection coverage

</details>

---

## 📋 Phase 05 — Federated Threat Intelligence *(Planned)*
> **Goal:** Shared global defense network

<details>
<summary><b>View Features</b></summary>

### 🌐 Global Threat Sharing
- Malicious IP database
- Exploit indicators
- Attack pattern sharing

### 🔗 Cross-Customer Detection
- Multi-account correlation
- Global attack campaign detection

### 🚫 Automatic Defense
- Global IP blocking
- IOC distribution

### ☁️ Multi-Cloud + Compliance
- AWS monitoring
- Azure monitoring
- GCP monitoring
- SOC2 / ISO27001 / CIS reports

</details>

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

## 🛡️ SOAR Playbooks (Phase 01)

These playbooks execute automatically when GuardDuty fires a matching finding:

| Threat Type | GuardDuty Finding | Automated Response |
|-------------|------------------|-------------------|
| Compromised EC2 | `UnauthorizedAccess:EC2/MaliciousIPCaller` | Isolate EC2 — replace SG with deny-all |
| Exposed Credentials | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | Revoke access key immediately |
| Crypto Mining | `CryptoCurrency:EC2/BitcoinTool` | Snapshot + terminate instance |
| S3 Public Exposure | `Policy:S3/BucketPublicAccessGranted` | Re-apply Block Public Access |
| Brute Force | `UnauthorizedAccess:EC2/SSHBruteForce` | Block source IP in WAF |
| Recon Activity | `Recon:IAMUser/MaliciousIPCaller` | Alert + increase logging verbosity |
| Root Account Login | `Policy:IAMUser/RootCredentialUsage` | Immediate SNS alert to all admins |

---

## 🔧 Tech Stack

| Layer | Service | Purpose |
|-------|---------|---------|
| Detection | Amazon GuardDuty | ML-powered threat detection |
| Aggregation | AWS Security Hub | Centralized finding management |
| Routing | Amazon EventBridge | Event-driven SOAR triggering |
| Compute | AWS Lambda (Python) | Playbook execution |
| Orchestration | AWS Step Functions | Multi-step response workflows |
| Storage | Amazon S3 + DynamoDB | Finding storage + state management |
| Notifications | Amazon SNS | Multi-channel alerting |
| IaC | Terraform | Infrastructure as Code |
| Graph DB | Amazon Neptune | Behavioral DNA (Phase 01) |
| AI | AWS Bedrock (Claude) | Autonomous investigation (Phase 03) |

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
│   ├── behavioral-dna.md         # Phase 01
│   ├── threat-prediction.md      # Phase 02
│   ├── ai-investigation.md       # Phase 03
│   ├── deception-layer.md        # Phase 04
│   └── federated-intel.md        # Phase 05
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
git clone https://github.com/ABS973/cognitive-soc.git
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

## 🔗 SecureOps Labs Ecosystem

| Platform | Type | Phases | Status |
|----------|------|--------|--------|
| 🔵 **CognitiveSOC** | Blue Team — Autonomous AI SOC | 5 Phases | **Active** |
| 🔴 **CognitivePentest** | Red Team — Autonomous Pentesting | 10 Phases | Planned |

> Both platforms are designed to feed each other — CognitivePentest attack paths validate CognitiveSOC detection coverage via Purple Team simulation in Phase 04.


## 📄 Documentation

- [Architecture Deep Dive](docs/architecture.md)
- [Behavioral DNA Engine](docs/behavioral-dna.md)
- [Attacker Intent Prediction](docs/threat-prediction.md)
- [Autonomous AI Investigation](docs/ai-investigation.md)
- [Deception Orchestration](docs/deception-layer.md)
- [Federated Threat Intelligence](docs/federated-intel.md)

---

## ⚠️ Disclaimer

This project is designed for authorized security testing and defensive purposes only. Deploy only in AWS accounts you own or have explicit written authorization to secure. The deception layer features must comply with applicable computer fraud laws in your jurisdiction.

---

## 📬 Contact

**Ahmed** — Founder, SecureOps Labs Inc.

- 🌐 Website: Coming Soon
- 💼 LinkedIn: Coming Soon
- 🐦 Twitter/X: Coming Soon

---

<div align="center">

Built with 🔐 from Bahrain 🇧🇭

`AI-Native` · `Autonomous` · `AWS-First` · `SOC Replacement`

**SecureOps Labs Inc. © 2025**

</div>
