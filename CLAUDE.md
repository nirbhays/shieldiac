# CLAUDE.md — ShieldIaC

## What This Project Does

ShieldIaC is an IaC (Infrastructure-as-Code) security scanner delivered as a zero-config GitHub App. When a developer opens a pull request containing Terraform (`.tf`, `.tf.json`), Kubernetes (`.yaml`/`.yml`), Dockerfile, or CloudFormation files, ShieldIaC automatically fetches those files, runs them through a registry of 100+ security rules, maps every finding to up to 9 compliance frameworks (CIS, SOC 2, HIPAA, PCI-DSS, NIST 800-53, ISO 27001, GDPR, AWS Well-Architected, GCP Security), generates AI-powered fix suggestions via GPT-4.1-mini for CRITICAL/HIGH findings, computes a severity-weighted security score (A–F, 0–100), and posts a detailed Markdown comment directly on the PR. No CLI tools to install, no CI pipelines to configure — install the GitHub App and every subsequent push is covered.

---

## Owner Context

**Owner:** Nirbhay Singh — Cloud & AI Architect
**Career goal:** $800K USD total compensation as a Staff+/Principal AI Infrastructure Architect.
ShieldIaC is a **portfolio project** demonstrating enterprise-grade DevSecOps capabilities. It is intentionally designed to be production-quality: real rule engine, compliance mapping, AI integration, Stripe billing, multi-tenant dashboard. It must look and behave like a funded startup product, because the target audience (Staff+ hiring managers and technical interviewers) will scrutinize the code.

**Related repos in the portfolio (same owner: nirbhays):**
| Repo | What it does |
|---|---|
| `tokenmeter` | LLM cost intelligence — drop-in import replacement, tracks every token |
| `infracents` | GitHub App: Terraform cost estimates on every PR |
| `agent-loom` | Multi-agent orchestration framework |
| `airlock` | API gateway with rate limiting and auth for AI services |
| `model-ledger` | Audit trail and lineage tracking for ML models |
| `tune-forge` | Fine-tuning pipeline manager |
| `data-mint` | Synthetic data generation for LLM training |

These repos are intentionally complementary. ShieldIaC secures the infrastructure; infracents prices it; tokenmeter costs the AI layer. They are all part of the same portfolio story.

---

## Complete File Structure

```
shieldiac/
├── .env.example                    # All environment variables with comments
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # Run tests + lint on every PR
│   │   ├── deploy.yml              # Deploy to Cloud Run on push to main
│   │   └── rule-tests.yml          # Dedicated workflow: run rule-specific tests
├── backend/                        # Python 3.11 / FastAPI application
│   ├── __init__.py
│   ├── main.py                     # FastAPI app factory, router registration, lifespan
│   ├── config.py                   # Pydantic BaseSettings — all config from env vars (SHIELDIAC_ prefix)
│   ├── Dockerfile                  # Multi-stage build: builder + slim runtime
│   ├── docker-compose.yml          # Local dev: PostgreSQL + Redis services
│   ├── requirements.txt            # Production dependencies
│   ├── requirements-dev.txt        # Dev/test dependencies (pytest, ruff, coverage)
│   ├── api/                        # FastAPI route handlers (thin — delegate to services)
│   │   ├── __init__.py
│   │   ├── webhooks.py             # POST /webhooks/github — main entry point for GitHub events
│   │   ├── scans.py                # GET /scans — scan history and results for dashboard
│   │   ├── rules.py                # GET /rules — list rules, custom rule CRUD
│   │   ├── reports.py              # GET /reports/{scan_id}/pdf — PDF compliance report generation
│   │   ├── dashboard.py            # GET /dashboard — org-level stats, trend data
│   │   ├── billing.py              # POST /billing/webhook — Stripe webhook handler
│   │   └── health.py               # GET /health — liveness probe
│   ├── models/                     # Pydantic v2 data models (request/response shapes)
│   │   ├── __init__.py
│   │   ├── scan.py                 # ScanRequest, ScanResult, ScanStatus
│   │   ├── finding.py              # Finding, FindingSeverity, FindingLocation
│   │   ├── rule.py                 # Rule, CustomRule, RuleMetadata
│   │   ├── compliance.py           # ComplianceFramework, ComplianceMapping, FrameworkReport
│   │   ├── billing.py              # Subscription, Plan, BillingEvent
│   │   └── github.py               # WebhookPayload, PushEvent, PullRequestEvent
│   ├── rules/                      # Security rule definitions — the heart of the scanner
│   │   ├── __init__.py
│   │   ├── base.py                 # BaseRule, Severity, ResourceType, RuleRegistry, ComplianceMapping
│   │   ├── loader.py               # Dynamic rule discovery: scans subdirs, imports modules, registers rules
│   │   ├── terraform/              # Terraform HCL/JSON rules
│   │   │   ├── __init__.py
│   │   │   ├── aws_s3.py           # S3: encryption, versioning, public access, logging (10+ rules)
│   │   │   ├── aws_ec2.py          # EC2: security groups, IMDSv2, EBS encryption (10+ rules)
│   │   │   ├── aws_iam.py          # IAM: overly permissive policies, root usage (10+ rules)
│   │   │   ├── aws_rds.py          # RDS: backups, encryption, public access (10+ rules)
│   │   │   ├── aws_vpc.py          # VPC: flow logs, default VPC usage, NACLs (5+ rules)
│   │   │   ├── gcp_compute.py      # GCP Compute Engine rules (10+ rules)
│   │   │   ├── gcp_iam.py          # GCP IAM: service accounts, bindings (5+ rules)
│   │   │   └── gcp_storage.py      # GCP Cloud Storage: public access, versioning (5+ rules)
│   │   ├── kubernetes/             # Kubernetes manifest rules
│   │   │   ├── __init__.py
│   │   │   ├── pod_security.py     # Privileged containers, runAsRoot, securityContext (10+ rules)
│   │   │   ├── rbac.py             # ClusterAdmin bindings, wildcard permissions (5+ rules)
│   │   │   ├── network_policy.py   # Missing NetworkPolicy, default deny (5+ rules)
│   │   │   └── resources.py        # Missing resource limits/requests (5+ rules)
│   │   └── docker/                 # Dockerfile rules
│   │       ├── __init__.py
│   │       └── best_practices.py   # Root USER, latest tags, exposed secrets, health checks (20 rules)
│   ├── services/                   # Business logic layer
│   │   ├── __init__.py
│   │   ├── scanner_engine.py       # Orchestrator: receives files, dispatches to format-specific scanners, aggregates
│   │   ├── terraform_scanner.py    # HCL/JSON parser (python-hcl2 + json) + rule evaluation
│   │   ├── kubernetes_scanner.py   # YAML multi-doc parser + rule evaluation
│   │   ├── dockerfile_scanner.py   # Dockerfile instruction parser + rule evaluation
│   │   ├── cloudformation_scanner.py # CloudFormation YAML/JSON parser + maps to Terraform rules
│   │   ├── ai_fix_generator.py     # GPT-4.1-mini integration: generates fix snippets, caches 24h in Redis
│   │   ├── github_service.py       # GitHub API: fetch files, post PR comments, create check runs
│   │   ├── scoring_engine.py       # Security score calculation (weighted: CRIT=15, HIGH=8, MED=3, LOW=1)
│   │   ├── compliance_mapper.py    # Maps finding IDs to framework controls, generates per-framework reports
│   │   ├── billing_service.py      # Stripe: create customers, manage subscriptions, check plan limits
│   │   ├── queue_service.py        # Redis-backed async job queue for scan processing
│   │   └── report_generator.py     # PDF compliance report generation (ReportLab or WeasyPrint)
│   └── utils/                      # Shared parsing utilities
├── frontend/                       # Next.js 14 (App Router) dashboard
│   └── src/
│       ├── app/                    # App Router pages and layouts
│       └── components/             # React components (charts, tables, findings)
├── database/                       # SQL schemas and migrations
│   ├── migrations/
│   │   └── 001_initial.sql         # Initial schema: scans, findings, repos, users, subscriptions
│   └── seed.sql                    # Sample data for local dev
├── infra/                          # Terraform IaC for ShieldIaC's own infrastructure
│   └── terraform/
│       ├── main.tf                 # Google Cloud project, provider config
│       ├── cloud-run.tf            # Cloud Run service for the backend
│       ├── iam.tf                  # Service account, IAM bindings
│       ├── redis.tf                # Upstash Redis (or Memorystore)
│       ├── variables.tf            # Input variables
│       └── outputs.tf              # Outputs: API URL, service account email
├── tests/                          # pytest test suite
│   ├── __init__.py
│   ├── conftest.py                 # Shared fixtures: test client, mock GitHub, sample IaC files
│   ├── fixtures/                   # Sample IaC files for testing
│   │   ├── terraform/
│   │   │   ├── insecure_s3.tf      # S3 without encryption — should trigger SHLD-S3-001
│   │   │   ├── insecure_ec2.tf     # Open security group on port 22 — triggers SHLD-EC2-001
│   │   │   └── secure_vpc.tf       # VPC with flow logs — should pass all VPC rules
│   │   ├── kubernetes/
│   │   │   ├── insecure_pod.yaml   # Privileged pod, no resource limits
│   │   │   └── secure_deployment.yaml
│   │   └── docker/
│   │       ├── insecure_dockerfile # Running as root, using latest tag
│   │       └── secure_dockerfile
│   ├── test_terraform_scanner.py   # Unit tests for Terraform parsing + rule evaluation
│   ├── test_kubernetes_scanner.py
│   ├── test_dockerfile_scanner.py
│   ├── test_scoring_engine.py      # Score calculation edge cases
│   ├── test_compliance_mapper.py   # Framework mapping correctness
│   ├── test_ai_fix_generator.py    # AI fix generation (mocked OpenAI)
│   └── test_webhooks.py            # Webhook signature verification + end-to-end scan flow
├── docs/                           # Documentation (architecture, API, contributing)
│   └── CONTRIBUTING.md             # How to add new rules
├── Makefile                        # Developer commands (see below)
├── pyproject.toml                  # Ruff, pytest, coverage configuration
├── LICENSE
└── README.md
```

---

## Environment Variables

All backend variables use the `SHIELDIAC_` prefix (configured in `backend/config.py` using Pydantic `BaseSettings`). Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|---|:---:|---|
| `SHIELDIAC_DATABASE_URL` | Yes | PostgreSQL async URL (`postgresql+asyncpg://...`) |
| `SHIELDIAC_REDIS_URL` | Yes | Redis URL for queue and cache |
| `SHIELDIAC_GITHUB_APP_ID` | Yes | GitHub App numeric ID |
| `SHIELDIAC_GITHUB_APP_PRIVATE_KEY` | Yes | PEM private key (escape `\n`) |
| `SHIELDIAC_GITHUB_WEBHOOK_SECRET` | Yes | HMAC-SHA256 webhook verification secret |
| `SHIELDIAC_OPENAI_API_KEY` | No | GPT-4.1-mini for AI fix suggestions (~$0.006/scan) |
| `SHIELDIAC_OPENAI_MODEL` | No | Default: `gpt-4.1-mini` |
| `SHIELDIAC_AI_FIX_ENABLED` | No | `true` to enable AI fixes (default: `true`) |
| `SHIELDIAC_CLERK_SECRET_KEY` | Yes (prod) | Clerk auth for dashboard |
| `SHIELDIAC_STRIPE_SECRET_KEY` | Yes (prod) | Stripe billing |
| `SHIELDIAC_STRIPE_WEBHOOK_SECRET` | Yes (prod) | Stripe webhook verification |
| `NEXT_PUBLIC_API_URL` | Yes (frontend) | Backend API URL for Next.js |

---

## How to Develop Locally

```bash
# 1. Clone and enter the repo
git clone https://github.com/nirbhays/shieldiac.git
cd shieldiac

# 2. Copy and configure environment variables
cp .env.example .env
# Edit .env — minimum required: DATABASE_URL, REDIS_URL, GITHUB_APP_ID,
# GITHUB_APP_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET

# 3. Start PostgreSQL and Redis via Docker
make docker-up

# 4. Install backend Python dependencies
make install-backend

# 5. Run database migration
make db-migrate

# 6. Start the backend (auto-reload)
make run-backend
# API available at http://localhost:8000
# Swagger docs at http://localhost:8000/docs

# 7. (Optional) Start the frontend dashboard
make install-frontend
make run-frontend
# Dashboard at http://localhost:3000
```

To expose the local webhook endpoint to GitHub during development, use [smee.io](https://smee.io/) or `ngrok`:
```bash
ngrok http 8000
# Set the ngrok URL as your GitHub App's webhook URL in GitHub App settings
```

---

## How to Run Tests

```bash
# Run the full test suite
make test

# Run only Terraform scanner tests
make test-tf

# Run only Kubernetes scanner tests
make test-k8s

# Run only Dockerfile scanner tests
make test-docker

# Run with coverage report (outputs HTML to htmlcov/)
make test-cov

# Run a single test file
python -m pytest tests/test_terraform_scanner.py -v

# Run a single test by name
python -m pytest tests/test_terraform_scanner.py::test_s3_without_encryption -v
```

Tests use `pytest`. Fixtures are in `tests/conftest.py`. Sample IaC files live in `tests/fixtures/`. The GitHub API is mocked in tests — no real GitHub credentials needed.

---

## How to Add a New Security Rule

Adding a rule is a 3-step process. The `RuleRegistry` in `backend/rules/base.py` discovers rules automatically via the `@registry.register` decorator.

### Step 1: Choose the correct rules subdirectory

| IaC Type | Directory |
|---|---|
| Terraform AWS | `backend/rules/terraform/aws_*.py` |
| Terraform GCP | `backend/rules/terraform/gcp_*.py` |
| Kubernetes | `backend/rules/kubernetes/` |
| Dockerfile | `backend/rules/docker/` |
| CloudFormation | Uses Terraform rules via `cloudformation_scanner.py` mapping |

### Step 2: Create the rule class

```python
# backend/rules/terraform/aws_s3.py (add to existing file, or create aws_s3_new.py)

from backend.rules.base import (
    BaseRule, Severity, ResourceType,
    registry, ComplianceMapping, ComplianceFramework
)

@registry.register
class S3BucketLoggingRule(BaseRule):
    id = "SHLD-S3-010"           # Format: SHLD-{SERVICE}-{NUMBER}
    description = "S3 bucket does not have access logging enabled"
    severity = Severity.MEDIUM   # CRITICAL | HIGH | MEDIUM | LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Enable access logging by adding a logging {} block to the aws_s3_bucket resource."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.3", "Ensure S3 bucket logging is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.2", "System monitoring and logging"),
        ComplianceMapping(ComplianceFramework.ISO27001, "A.12.4.1", "Event logging"),
    ]
    tags = ["logging", "s3", "monitoring", "aws"]

    def evaluate(self, resource: dict, context) -> list:
        """
        Args:
            resource: Parsed Terraform resource dict (keys: name, type, config, file_path, line)
            context:  ScanContext with file_path, repo_name, etc.
        Returns:
            List of Finding objects (empty list = resource passes this rule)
        """
        findings = []
        config = resource.get("config", {})
        if not config.get("logging"):
            findings.append(self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line=resource.get("line"),
                details="No logging block found. Add: logging { target_bucket = ... }",
            ))
        return findings
```

### Step 3: Add a test

```python
# tests/test_terraform_scanner.py

def test_s3_without_logging(scanner, fixtures_dir):
    results = scanner.scan_file(fixtures_dir / "terraform/insecure_s3.tf")
    rule_ids = [f.rule_id for f in results.findings]
    assert "SHLD-S3-010" in rule_ids

def test_s3_with_logging_passes(scanner, fixtures_dir):
    results = scanner.scan_file(fixtures_dir / "terraform/secure_s3_with_logging.tf")
    rule_ids = [f.rule_id for f in results.findings]
    assert "SHLD-S3-010" not in rule_ids
```

Add a corresponding fixture file in `tests/fixtures/terraform/`. No other configuration changes are needed — the loader discovers new rules automatically.

---

## Severity Scoring Formula

The scoring engine in `backend/services/scoring_engine.py` uses:

```
penalty = (critical * 15) + (high * 8) + (medium * 3) + (low * 1)
raw_score = max(0, 100 - penalty)
normalized_score = raw_score * sqrt(file_count) / (sqrt(file_count) + normalization_factor)
```

Grades: A = 90–100, B = 75–89, C = 60–74, D = 40–59, F = 0–39.

---

## How to Build and Release

```bash
# Lint all code before releasing
make lint

# Run full test suite
make test

# Build Docker image for backend
make build-backend
# Produces: shieldiac-backend:latest

# Build frontend for production
make build-frontend
# Outputs to frontend/.next/

# Deploy (CI/CD via GitHub Actions on push to main)
# .github/workflows/deploy.yml runs:
#   1. make lint
#   2. make test
#   3. docker build + push to Google Artifact Registry
#   4. gcloud run deploy shieldiac-api
```

For a manual production deploy:
```bash
# Authenticate to GCP
gcloud auth configure-docker

# Build and push
docker build -t gcr.io/YOUR_PROJECT/shieldiac-api:latest backend/
docker push gcr.io/YOUR_PROJECT/shieldiac-api:latest

# Deploy to Cloud Run
gcloud run deploy shieldiac-api \
  --image gcr.io/YOUR_PROJECT/shieldiac-api:latest \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars="SHIELDIAC_ENVIRONMENT=production"
```

---

## Key Coding Patterns

1. **All config via Pydantic `BaseSettings`** — `backend/config.py` defines `Settings` with `SHIELDIAC_` prefix. Access via `from config import settings`.

2. **Rule registry is a singleton** — `registry` in `backend/rules/base.py` is a module-level instance. `@registry.register` decorates rule classes. `loader.py` imports all rule modules at startup so decorators fire.

3. **Scanners return `ScanResult` objects** — defined in `backend/models/scan.py`. Each scanner (`terraform_scanner.py`, etc.) returns a `ScanResult` with a list of `Finding` objects. The `scanner_engine.py` orchestrates multiple scanners and merges results.

4. **AI fixes are cached in Redis** — `ai_fix_generator.py` uses a cache key of `ai_fix:{rule_id}:{resource_hash}` with 24h TTL. This keeps GPT-4.1-mini costs low (~$0.006/scan on average).

5. **Webhook verification is mandatory** — `backend/api/webhooks.py` verifies HMAC-SHA256 signatures before processing any event. Never bypass this.

6. **Async throughout** — FastAPI with `async def` handlers, `asyncpg` for PostgreSQL, `aioredis` for Redis, `httpx` for GitHub API calls.

7. **Rule IDs follow a strict format** — `SHLD-{SERVICE}-{NUMBER}` where SERVICE is AWS service (S3, EC2, IAM, RDS, VPC) or K8S, DOCKER, CFN. Numbers are padded to 3 digits: SHLD-S3-001.

8. **Compliance mappings are exhaustive** — every rule should map to at least 2 frameworks. This is a selling point. Check `backend/models/compliance.py` for `ComplianceFramework` enum values.

9. **Linting: ruff** — configured in `pyproject.toml`. Run `make format` before committing.

10. **Frontend is Next.js 14 App Router** — all dashboard pages use server components where possible. The dashboard is secondary to the GitHub App functionality.

---

## Common Development Tasks

### Scan a local IaC file manually (no GitHub webhook)

```python
# From the backend directory:
from services.scanner_engine import ScannerEngine
from services.terraform_scanner import TerraformScanner

engine = ScannerEngine()
result = engine.scan_file("path/to/your.tf", content=open("your.tf").read())
for finding in result.findings:
    print(f"{finding.severity}: {finding.rule_id} — {finding.description}")
```

### Test a webhook locally

```bash
# Send a mock pull_request event
curl -X POST http://localhost:8000/webhooks/github \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: sha256=COMPUTED_HMAC" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/webhook_pr_event.json
```

### Add a compliance framework

1. Add the new framework to `ComplianceFramework` enum in `backend/models/compliance.py`
2. Update `compliance_mapper.py` to include the new framework in report generation
3. Update existing rules to add mappings to the new framework
4. Update the README comparison table

### Run linting

```bash
make lint           # Check only
make format         # Auto-fix and format
```

---

## Architecture Summary

```
GitHub Push/PR
      |
      v
POST /webhooks/github  (backend/api/webhooks.py)
      |
      |- Verify HMAC-SHA256 signature
      |- Parse event (push or pull_request)
      |- Enqueue scan job (queue_service.py -> Redis)
      |
      v
Worker picks up job
      |
      |- Fetch changed IaC files (github_service.py -> GitHub API)
      |- Detect file types (.tf, .yaml, Dockerfile, .json)
      |- For each file -> scanner_engine.py dispatches to:
      |     terraform_scanner.py   (python-hcl2 or json parser)
      |     kubernetes_scanner.py  (PyYAML multi-doc)
      |     dockerfile_scanner.py  (instruction parser)
      |     cloudformation_scanner.py (maps to terraform rules)
      |
      |- scanner_engine aggregates all findings
      |- scoring_engine.py computes security score
      |- compliance_mapper.py maps findings to frameworks
      |- ai_fix_generator.py calls GPT-4.1-mini for CRITICAL/HIGH
      |     (results cached in Redis for 24h)
      |
      |- github_service.py posts PR comment + check run
      |- Store scan result in PostgreSQL
```

**Infrastructure:** Cloud Run (backend) + Vercel (frontend) + Supabase PostgreSQL + Upstash Redis
