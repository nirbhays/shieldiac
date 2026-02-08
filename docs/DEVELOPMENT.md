# ShieldIaC — Development Guide

## Prerequisites

- Python 3.10+
- Node.js 18+ (frontend)
- PostgreSQL 15+ (or Docker)
- Redis 7+ (or Docker)
- Git

## Quick Start

### 1. Clone and Set Up

```bash
git clone https://github.com/your-org/shieldiac.git
cd shieldiac
cp .env.example .env
```

### 2. Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start Dependencies

```bash
docker-compose up -d postgres redis
```

### 4. Run Database Migrations

```bash
psql $DATABASE_URL < ../database/schema.sql
psql $DATABASE_URL < ../database/seed.sql
```

### 5. Start Backend

```bash
uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Swagger docs at `/docs`.

### 6. Frontend Setup

```bash
cd ../frontend
npm install
npm run dev
```

Dashboard at `http://localhost:3000`.

## Project Structure

```
shieldiac/
├── backend/
│   ├── api/              # FastAPI route handlers
│   │   ├── scans.py      # Scan CRUD + trigger
│   │   ├── rules.py      # Rule listing + search
│   │   ├── reports.py    # Compliance report generation
│   │   ├── webhooks.py   # GitHub webhook handler
│   │   ├── dashboard.py  # Dashboard aggregation
│   │   ├── billing.py    # Stripe subscription management
│   │   └── health.py     # Health + readiness probes
│   ├── models/           # Pydantic data models
│   ├── rules/            # Security rule definitions
│   │   ├── base.py       # BaseRule, RuleRegistry, Finding
│   │   ├── loader.py     # Auto-discovery of rule modules
│   │   ├── terraform/    # Terraform HCL rules (AWS, GCP)
│   │   ├── kubernetes/   # K8s manifest rules
│   │   └── docker/       # Dockerfile rules
│   ├── services/         # Business logic
│   │   ├── scanner_engine.py      # Orchestrator
│   │   ├── terraform_scanner.py   # TF file processing
│   │   ├── kubernetes_scanner.py  # K8s YAML processing
│   │   ├── dockerfile_scanner.py  # Dockerfile processing
│   │   ├── cloudformation_scanner.py
│   │   ├── ai_fix_generator.py    # GPT-4.1-mini integration
│   │   ├── scoring_engine.py      # 0-100 score + grade
│   │   ├── compliance_mapper.py   # Framework mapping
│   │   ├── report_generator.py    # PDF export
│   │   ├── github_service.py      # PR comments + checks
│   │   ├── queue_service.py       # Redis BLPOP queue
│   │   └── billing_service.py     # Stripe integration
│   ├── utils/            # Helpers
│   │   ├── hcl_parser.py # HCL → dict parser
│   │   ├── yaml_parser.py
│   │   ├── formatting.py # PR comment markdown
│   │   ├── pdf_generator.py
│   │   └── security.py   # HMAC, rate limiting
│   ├── config.py         # Pydantic settings
│   ├── main.py           # FastAPI app factory
│   └── Dockerfile
├── frontend/             # Next.js 14 dashboard
│   └── src/
│       ├── app/          # App router pages
│       ├── components/   # React components
│       └── lib/          # API client, utils
├── database/
│   ├── schema.sql        # Full DDL
│   ├── migrations/       # Incremental SQL
│   └── seed.sql          # Dev fixtures
├── infra/terraform/      # GCP Cloud Run deployment
├── tests/                # pytest suite
└── docs/                 # You are here
```

## Environment Variables

Key variables (see `.env.example` for full list):

| Variable | Description | Default |
|----------|-------------|---------|
| `SHIELDIAC_DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://...localhost/shieldiac` |
| `SHIELDIAC_REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `SHIELDIAC_GITHUB_WEBHOOK_SECRET` | GitHub webhook HMAC secret | `change-me-in-production` |
| `SHIELDIAC_OPENAI_API_KEY` | OpenAI API key for AI fixes | — |
| `SHIELDIAC_OPENAI_MODEL` | Model for fix generation | `gpt-4.1-mini` |
| `SHIELDIAC_STRIPE_SECRET_KEY` | Stripe billing key | — |

## Testing

```bash
# Run all tests
cd backend && python -m pytest ../tests/ -v

# Run specific test file
python -m pytest ../tests/test_terraform_scanner.py -v

# Run with coverage
python -m pytest ../tests/ --cov=backend --cov-report=html

# Run only fast unit tests (skip integration)
python -m pytest ../tests/ -v -m "not integration"
```

### Test Structure
- `tests/conftest.py` — shared fixtures (mock findings, sample configs)
- `tests/fixtures/` — sample IaC files for scanning
  - `terraform/` — insecure and secure `.tf` files
  - `kubernetes/` — insecure and secure YAML manifests
  - `docker/` — insecure and secure Dockerfiles
- `tests/test_*.py` — test modules matching `backend/services/` and `backend/rules/`

## Writing New Rules

See [RULES-ENGINE.md](./RULES-ENGINE.md) for the complete guide. Quick version:

```python
# backend/rules/terraform/aws_lambda.py
from backend.rules.base import BaseRule, Finding, Severity, ResourceType, ComplianceMapping, ComplianceFramework, RuleContext

class LambdaNoVPCRule(BaseRule):
    rule_id = "SHLD-LAMBDA-001"
    title = "Lambda function not attached to VPC"
    description = "Lambda functions processing sensitive data should run inside a VPC."
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.9", "Lambda VPC configuration"),
    ]

    def evaluate(self, context: RuleContext) -> list[Finding]:
        findings = []
        for name, config in context.resources.get("aws_lambda_function", {}).items():
            if "vpc_config" not in config:
                findings.append(self.make_finding(
                    resource=f"aws_lambda_function.{name}",
                    message="Lambda function is not attached to a VPC",
                    file_path=context.file_path,
                ))
        return findings
```

The rule is auto-discovered when its module is in `backend/rules/terraform/`.

## Code Style

- **Python:** Black formatter, isort, flake8 (config in `pyproject.toml`)
- **TypeScript:** ESLint + Prettier (config in frontend)
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`)
- **Branches:** `main` (production), `develop` (staging), `feat/*`, `fix/*`

## Common Development Tasks

### Add a New Compliance Framework

1. Add enum value to `ComplianceFramework` in `backend/rules/base.py`
2. Add control catalog to `backend/services/compliance_mapper.py`
3. Update existing rules with new `ComplianceMapping` entries
4. Add framework to frontend compliance dashboard

### Add a New IaC Format

1. Create scanner in `backend/services/{format}_scanner.py`
2. Add `ResourceType` enum value in `backend/rules/base.py`
3. Register in `ScannerEngine.FILE_TYPE_MAP`
4. Create rule directory `backend/rules/{format}/`
5. Add test fixtures in `tests/fixtures/{format}/`
