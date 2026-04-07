<p align="center">
  <img src="docs/assets/logo.png" alt="ShieldIaC Logo" width="140" />
</p>

<h1 align="center">ShieldIaC</h1>

<p align="center">
  <strong>Catch security misconfigurations in your Infrastructure-as-Code before they reach production.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT" />
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/Rules-100+-red.svg" alt="Rules: 100+" />
  <img src="https://img.shields.io/badge/Compliance-9_Frameworks-purple.svg" alt="Compliance: 9 Frameworks" />
  <img src="https://img.shields.io/badge/AI_Fixes-GPT--4.1--mini-orange.svg" alt="AI Fixes: GPT-4.1-mini" />
</p>

<p align="center">
  <a href="#why-shieldiac">Why ShieldIaC?</a> &bull;
  <a href="#demo">Demo</a> &bull;
  <a href="#supported-formats">Formats</a> &bull;
  <a href="#compliance-frameworks">Compliance</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#feature-highlights">Features</a> &bull;
  <a href="#comparison">Comparison</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

## Why ShieldIaC?

Security misconfigurations in infrastructure code are the #1 cause of cloud breaches. Most teams discover them *after* deployment -- when the damage is already done.

<table>
<tr>
<td width="50%" valign="top">

### Without ShieldIaC

- Deploy first, get breached, scramble to fix
- Security reviews are manual and inconsistent
- Compliance audits are painful, retroactive exercises
- No visibility into security posture across repos
- Developers wait days for security team feedback

</td>
<td width="50%" valign="top">

### With ShieldIaC

- Every PR scanned, every finding explained, every fix suggested by AI
- 100+ rules run automatically on every push
- Continuous compliance mapping across 9 frameworks
- Real-time security scoring with trend tracking
- Developers get instant, actionable feedback

</td>
</tr>
</table>

> **Shift security left.** Stop treating infrastructure security as an afterthought. ShieldIaC makes it part of your development workflow.

---

## Demo

Here is what a ShieldIaC PR comment looks like when it finds security issues in your infrastructure code:

```
===================================================================
  ShieldIaC Security Scan Results
  Scan ID: shld-a8f3c901    |    Security Score: D (52/100)
  3 CRITICAL  |  2 HIGH  |  1 MEDIUM  |  0 LOW
===================================================================

  CRITICAL  SHLD-S3-001  S3 bucket without server-side encryption
  ---------------------------------------------------------------
  File:       infra/storage.tf  (line 14)
  Resource:   aws_s3_bucket.user_uploads
  Framework:  CIS AWS 2.1.1 | SOC 2 CC6.1 | HIPAA 164.312(a)(1)

  AI Fix Suggestion:
  resource "aws_s3_bucket_server_side_encryption_configuration" "user_uploads" {
    bucket = aws_s3_bucket.user_uploads.id
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  ---

  HIGH  SHLD-EC2-001  Security group allows unrestricted ingress (0.0.0.0/0)
  --------------------------------------------------------------------------
  File:       infra/network.tf  (line 38)
  Resource:   aws_security_group.web_sg  (port 22)
  Framework:  CIS AWS 4.1 | PCI-DSS 1.3.1 | NIST AC-4

  AI Fix Suggestion:
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]   # Restrict to internal VPN range
    description = "SSH from corporate VPN only"
  }

  ---

  MEDIUM  SHLD-RDS-003  RDS instance without automated backups enabled
  --------------------------------------------------------------------
  File:       infra/database.tf  (line 22)
  Resource:   aws_db_instance.primary
  Framework:  CIS AWS 2.3.1 | SOC 2 A1.2 | ISO 27001 A.12.3

  AI Fix Suggestion:
  resource "aws_db_instance" "primary" {
    ...
    backup_retention_period = 7
    backup_window           = "03:00-04:00"
    copy_tags_to_snapshot   = true
  }

===================================================================
  View full report: https://github.com/nirbhays/shieldiac
  PDF compliance report: https://github.com/nirbhays/shieldiac
===================================================================
```

Every finding includes the severity, exact file location, compliance framework mapping, and an AI-generated fix you can apply directly.

---

## Supported Formats

ShieldIaC scans four major IaC formats from a single platform. Drop in any of these file types and scanning begins automatically.

<table>
<tr>
<td align="center" width="25%">
<h3>Terraform</h3>
<code>.tf</code> <code>.tf.json</code>
<br/><br/>
<strong>50+ rules</strong>
<br/><br/>
AWS S3, IAM, EC2, RDS, VPC<br/>
GCP Compute, IAM, Storage<br/>
HCL and JSON formats
</td>
<td align="center" width="25%">
<h3>Kubernetes</h3>
<code>.yaml</code> <code>.yml</code>
<br/><br/>
<strong>25+ rules</strong>
<br/><br/>
Pods, Deployments, RBAC<br/>
NetworkPolicy, Resources<br/>
Security contexts
</td>
<td align="center" width="25%">
<h3>Dockerfile</h3>
<code>Dockerfile</code>
<br/><br/>
<strong>20 rules</strong>
<br/><br/>
Base images, USER directive<br/>
Secret exposure, packages<br/>
Health checks, ports
</td>
<td align="center" width="25%">
<h3>CloudFormation</h3>
<code>.yaml</code> <code>.json</code>
<br/><br/>
<strong>10+ rules</strong>
<br/><br/>
S3, EC2, RDS, VPC<br/>
Maps to Terraform rules<br/>
Write once, scan both
</td>
</tr>
</table>

---

## Compliance Frameworks

Every rule is mapped to one or more compliance controls. ShieldIaC covers **9 industry frameworks** out of the box.

<table>
<tr>
<td align="center" width="33%">
<img src="https://img.shields.io/badge/CIS-Benchmarks-blue.svg" alt="CIS" /><br/>
<strong>CIS Foundations</strong><br/>
AWS, GCP, and Kubernetes benchmarks
</td>
<td align="center" width="33%">
<img src="https://img.shields.io/badge/SOC_2-Type_II-blue.svg" alt="SOC 2" /><br/>
<strong>SOC 2 Type II</strong><br/>
Trust Services Criteria
</td>
<td align="center" width="33%">
<img src="https://img.shields.io/badge/HIPAA-Compliant-blue.svg" alt="HIPAA" /><br/>
<strong>HIPAA</strong><br/>
Health data protection safeguards
</td>
</tr>
<tr>
<td align="center">
<img src="https://img.shields.io/badge/PCI--DSS-v4.0-blue.svg" alt="PCI-DSS" /><br/>
<strong>PCI-DSS v4.0</strong><br/>
Payment card data security
</td>
<td align="center">
<img src="https://img.shields.io/badge/NIST-800--53-blue.svg" alt="NIST" /><br/>
<strong>NIST 800-53</strong><br/>
Federal information systems
</td>
<td align="center">
<img src="https://img.shields.io/badge/ISO-27001-blue.svg" alt="ISO 27001" /><br/>
<strong>ISO 27001</strong><br/>
Information security management
</td>
</tr>
<tr>
<td align="center">
<img src="https://img.shields.io/badge/GDPR-EU-blue.svg" alt="GDPR" /><br/>
<strong>GDPR</strong><br/>
EU data protection regulation
</td>
<td align="center">
<img src="https://img.shields.io/badge/AWS-Well--Architected-blue.svg" alt="AWS Well-Architected" /><br/>
<strong>AWS Well-Architected</strong><br/>
Security pillar best practices
</td>
<td align="center">
<img src="https://img.shields.io/badge/GCP-Security-blue.svg" alt="GCP Security" /><br/>
<strong>GCP Security</strong><br/>
Google Cloud security foundations
</td>
</tr>
</table>

---

## Quick Start

Get ShieldIaC running in three steps. No configuration files. No CLI tools to install. Just connect and go.

### Step 1 -- Install the GitHub App

Install the [ShieldIaC GitHub App](https://github.com/apps/shieldiac) on your repositories. Grant read access to code and write access to pull requests and checks.

### Step 2 -- Push IaC Code

Push a commit or open a pull request containing any supported IaC file (`.tf`, `.yaml`, `Dockerfile`, or CloudFormation template). ShieldIaC detects the file types automatically.

### Step 3 -- Get Your Security Report

Within seconds, ShieldIaC posts a detailed comment on your PR with:
- Findings grouped by severity (CRITICAL / HIGH / MEDIUM / LOW)
- AI-generated fix suggestions for critical and high findings
- A security score (A through F) with compliance framework mapping
- A link to the full report on the ShieldIaC dashboard

That's it. Every subsequent PR is scanned automatically.

---

## Feature Highlights

<table>
<tr>
<td width="50%" valign="top">

### AI Fix Suggestions
For every CRITICAL and HIGH finding, ShieldIaC uses GPT-4.1-mini to generate **production-ready code fixes** tailored to your specific configuration. Fixes are context-aware -- they read the surrounding code to produce suggestions you can apply directly. Results are cached for 24 hours to keep costs low.

</td>
<td width="50%" valign="top">

### Security Scoring
Every scan produces a **security score from 0 to 100** with a letter grade (A through F). Scores are severity-weighted: CRITICAL findings cost 15 points, HIGH costs 8, MEDIUM costs 3, LOW costs 1. Normalized by file count for fair comparison across repos. Track trends over time -- improving, declining, or stable.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### PDF Compliance Reports
Generate **audit-ready PDF reports** with a single click. Each report includes an executive summary, per-framework control status (pass / fail / partial), detailed findings with remediation steps, and professional formatting designed for auditor review. Export for SOC 2, HIPAA, PCI-DSS, and more.

</td>
<td width="50%" valign="top">

### Web Dashboard
A full-featured dashboard to **track security posture across all repositories**. View organization-level overviews, per-repo scan history with trend charts, finding drill-downs with severity and framework filtering, and a compliance dashboard showing framework-level pass rates. Built with Next.js 14.

</td>
</tr>
</table>

---

## Comparison

How ShieldIaC compares to popular IaC security tools:

| Feature | ShieldIaC | Checkov | tfsec | Snyk IaC |
|---------|:---------:|:-------:|:-----:|:--------:|
| **PR comments with findings** | Yes | Partial (CI) | Partial (CI) | Yes |
| **AI-powered fix suggestions** | Yes (GPT-4.1-mini) | No | No | No |
| **Security scoring (A-F)** | Yes | No | No | No |
| **Terraform scanning** | 50+ rules | 1000+ | 200+ | 300+ |
| **Kubernetes scanning** | 25+ rules | 200+ | N/A | 100+ |
| **Dockerfile scanning** | 20 rules | 30+ | N/A | 20+ |
| **CloudFormation scanning** | 10+ rules | 400+ | N/A | 200+ |
| **Compliance mapping (9 frameworks)** | Yes | Yes | Partial | Yes |
| **PDF compliance reports** | Yes | No | No | Paid |
| **Web dashboard** | Yes | Paid (Prisma) | No | Paid |
| **Self-hosted option** | Yes | Yes | Yes | No |
| **Setup complexity** | Zero-config (GitHub App) | CI pipeline setup | CI pipeline setup | App install |
| **Pricing** | Free tier available | Open source / Paid | Open source | Free tier / Paid |

> **ShieldIaC's advantage:** Zero-config GitHub App install with AI-generated fix suggestions and security scoring built in. No CI pipeline configuration required.

---

## Architecture

```
                            ShieldIaC Scanning Pipeline
  ============================================================================

  Developer        GitHub           ShieldIaC             AI Engine
  ---------        ------           ---------             ---------
      |                |                 |                     |
      |  git push /    |                 |                     |
      |  open PR       |                 |                     |
      |--------------->|                 |                     |
      |                |  webhook event  |                     |
      |                |---------------->|                     |
      |                |                 |                     |
      |                |                 |  Verify HMAC-SHA256 |
      |                |                 |  signature          |
      |                |                 |                     |
      |                |                 |  Detect IaC files   |
      |                |                 |  (.tf .yaml         |
      |                |                 |   Dockerfile .json) |
      |                |                 |                     |
      |                |   fetch files   |                     |
      |                |<----------------|                     |
      |                |---------------->|                     |
      |                |                 |                     |
      |                |                 |  +-----------------+|
      |                |                 |  | Scanning Engine ||
      |                |                 |  |                 ||
      |                |                 |  | Terraform  50+  ||
      |                |                 |  | Kubernetes 25+  ||
      |                |                 |  | Dockerfile 20   ||
      |                |                 |  | CloudForm. 10+  ||
      |                |                 |  +-----------------+|
      |                |                 |                     |
      |                |                 |  CRITICAL/HIGH      |
      |                |                 |  findings?          |
      |                |                 |-------------------->|
      |                |                 |    AI fix           |
      |                |                 |<--------------------|
      |                |                 |  (GPT-4.1-mini)     |
      |                |                 |                     |
      |                |                 |  Calculate score    |
      |                |                 |  Map compliance     |
      |                |                 |  Generate report    |
      |                |                 |                     |
      |                |  PR comment +   |                     |
      |                |  check run      |                     |
      |                |<----------------|                     |
      |                |                 |                     |
      |  view results  |                 |  store in           |
      |<---------------|                 |  PostgreSQL + Redis  |
      |                |                 |                     |


  Infrastructure:
  +-----------------+  +------------+  +------------+  +-----------+
  | Cloud Run       |  | PostgreSQL |  | Redis      |  | Vercel    |
  | (Python/FastAPI)|  | (Supabase) |  | (Upstash)  |  | (Next.js) |
  | Backend API     |  | Scan data  |  | Job queue  |  | Dashboard |
  +-----------------+  +------------+  +------------+  +-----------+
```

### Pipeline Steps

| Step | Description |
|------|-------------|
| **1. Webhook** | GitHub sends a `push` or `pull_request` event to the Cloud Run endpoint |
| **2. Verification** | HMAC-SHA256 signature validation ensures the webhook is genuine |
| **3. Detection** | File type detector identifies IaC files in the changeset (`.tf`, `.yaml`, `Dockerfile`, `.json`) |
| **4. Fetching** | Changed IaC files are downloaded from the repository via GitHub API |
| **5. Parsing** | Each file is parsed using the appropriate parser (HCL, YAML, Dockerfile instruction parser) |
| **6. Scanning** | Parsed resources are evaluated against all matching rules from the rule registry |
| **7. AI Fixes** | For CRITICAL and HIGH findings, GPT-4.1-mini generates context-aware code fixes |
| **8. Scoring** | Security score (0-100) computed with severity-weighted formula, normalized by file count |
| **9. Compliance** | Findings are mapped to CIS, SOC 2, HIPAA, PCI-DSS, NIST, ISO 27001, and GDPR controls |
| **10. Reporting** | Formatted Markdown comment posted on the PR; results stored in PostgreSQL for the dashboard |

### Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Backend | Python / FastAPI on Cloud Run | Webhook handling, scanning, API |
| Frontend | Next.js 14 on Vercel | Security dashboard and reports |
| Database | PostgreSQL (Supabase) | Scan results, user data, audit trail |
| Queue | Redis (Upstash) | Async scan job processing |
| AI | OpenAI GPT-4.1-mini | Fix suggestions (~$0.006/scan) |
| Auth | Clerk (GitHub OAuth) | User authentication |
| Payments | Stripe Billing | Subscription management |

---

## Project Structure

```
shieldiac/
├── backend/                        # Python/FastAPI backend
│   ├── api/                        # API route handlers
│   ├── models/                     # Pydantic data models
│   │   ├── scan.py                 # Scan request/result models
│   │   ├── finding.py              # Finding response models
│   │   ├── rule.py                 # Rule & custom rule models
│   │   ├── compliance.py           # Compliance framework models
│   │   ├── billing.py              # Subscription & billing models
│   │   └── github.py               # GitHub webhook models
│   ├── rules/                      # Security rule definitions
│   │   ├── base.py                 # BaseRule class + RuleRegistry
│   │   ├── loader.py               # Dynamic rule discovery
│   │   ├── terraform/              # 50+ Terraform rules (AWS + GCP)
│   │   ├── kubernetes/             # 25+ Kubernetes rules
│   │   └── docker/                 # 20 Dockerfile rules
│   ├── services/                   # Business logic
│   │   ├── scanner_engine.py       # Main scan orchestrator
│   │   ├── terraform_scanner.py    # HCL/JSON parser + scanner
│   │   ├── kubernetes_scanner.py   # K8s manifest scanner
│   │   ├── dockerfile_scanner.py   # Dockerfile instruction scanner
│   │   ├── cloudformation_scanner.py
│   │   ├── ai_fix_generator.py     # GPT-4.1-mini integration
│   │   ├── github_service.py       # GitHub API (comments, checks)
│   │   ├── scoring_engine.py       # Security score calculation
│   │   ├── compliance_mapper.py    # Finding-to-framework mapping
│   │   ├── billing_service.py      # Stripe integration
│   │   ├── queue_service.py        # Redis job queue
│   │   └── report_generator.py     # PDF compliance reports
│   ├── utils/                      # Parsing utilities
│   ├── main.py                     # FastAPI application entry
│   ├── config.py                   # Pydantic settings
│   └── requirements.txt            # Python dependencies
├── frontend/                       # Next.js 14 dashboard
│   └── src/
│       ├── app/                    # App Router pages
│       └── components/             # React components
├── database/                       # SQL schemas & migrations
├── infra/                          # Terraform deployment IaC
├── tests/                          # Test suite & fixtures
├── docs/                           # Documentation
└── .github/workflows/              # CI/CD pipelines
```

---

## Pricing

| Plan | Price | Scans/month | Repos | Key Features |
|------|-------|-------------|-------|--------------|
| **Free** | $0 | 50 | 3 | Core rules, PR comments, security score |
| **Pro** | $49/mo | Unlimited | 10 | All rules, AI fixes, dashboard, Slack alerts |
| **Business** | $199/mo | Unlimited | Unlimited | Custom rules (OPA/Rego), PDF reports, RBAC |
| **Enterprise** | $499/mo | Unlimited | Unlimited | SSO/SAML, self-hosted scanner, SLA, audit logs |

---

## Contributing

We welcome contributions -- especially new security rules. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the full guide.

### Adding a New Rule

Adding a rule is a three-step process: create a class, define metadata, and register it. The registry discovers new rules automatically.

```python
from backend.rules.base import (
    BaseRule, Severity, ResourceType,
    registry, ComplianceMapping, ComplianceFramework
)

@registry.register
class S3BucketLoggingRule(BaseRule):
    id = "SHLD-S3-010"
    description = "S3 bucket does not have access logging enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Enable access logging by adding a logging configuration block"
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.3", "Ensure S3 access logging"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.2", "System monitoring"),
    ]
    tags = ["logging", "s3", "monitoring"]

    def evaluate(self, resource, context):
        findings = []
        if not resource.get("logging"):
            findings.append(self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
            ))
        return findings
```

Drop the file into `backend/rules/terraform/` and ShieldIaC picks it up on the next scan. No configuration changes needed.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/shieldiac.git
cd shieldiac

# Set up environment variables
cp .env.example .env
# Edit .env with your GitHub App credentials and (optional) OpenAI API key

# Start infrastructure services
docker-compose up -d   # PostgreSQL + Redis

# Start backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Start frontend (separate terminal)
cd frontend
npm install
npm run dev
# Dashboard at http://localhost:3000
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, scanning pipeline, data flow |
| [API Reference](docs/API.md) | Endpoint documentation |
| [Deployment Guide](docs/DEPLOYMENT.md) | Production deployment walkthrough |
| [Security](docs/SECURITY.md) | Security model and data handling |
| [Contributing](docs/CONTRIBUTING.md) | How to contribute and add new rules |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [Checkov](https://www.checkov.io/) and [tfsec](https://github.com/aquasecurity/tfsec) for inspiration on rule patterns and scanning approaches.
- [CIS Benchmarks](https://www.cisecurity.org/) for compliance framework definitions.
- [OWASP](https://owasp.org/) for security best practices.

---

<p align="center">
  <strong>Built for DevSecOps teams who believe security belongs in the PR, not the post-mortem.</strong>
</p>

<p align="center">
  <a href="https://shieldiac.dev">Website</a> &bull;
  <a href="https://docs.shieldiac.dev">Docs</a> &bull;
  <a href="https://github.com/your-org/shieldiac/issues">Issues</a> &bull;
  <a href="https://discord.gg/shieldiac">Discord</a>
</p>
