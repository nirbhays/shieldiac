# Changelog

All notable changes to ShieldIaC will be documented in this file.

## [1.0.0] - 2025-02-08

### Added
- **Scanner Engine**: Core IaC scanning orchestrator supporting Terraform, Kubernetes, Dockerfiles, and CloudFormation
- **200+ Security Rules**: Comprehensive rule set covering:
  - 53 Terraform rules (AWS S3, EC2, IAM, RDS, VPC + GCP Compute, Storage, IAM)
  - 30 Kubernetes rules (Pod Security, Network Policy, RBAC, Resource Limits)
  - 20 Dockerfile rules (USER, COPY vs ADD, pinning, secrets, healthcheck, SSH)
- **AI Fix Suggestions**: GPT-4.1-mini powered code fix generation with few-shot prompting
- **GitHub/GitLab Integration**: Webhook handlers for push and PR events
- **PR Comments**: Beautiful markdown formatting with severity badges and AI fixes
- **Compliance Mapping**: SOC 2, HIPAA, PCI-DSS control mapping for all findings
- **PDF Reports**: Automated compliance report generation with ReportLab
- **Security Scoring**: 0-100 score with A-F grading, normalized by file count
- **Dashboard**: Next.js 14 dashboard with security overview, repo drill-down, trends
- **Landing Page**: Marketing page with features, pricing, testimonials
- **Billing**: Stripe integration with Free/Pro/Enterprise tiers
- **Auth**: Clerk integration with GitHub OAuth
- **Infrastructure**: Terraform configs for Google Cloud Run + Redis
- **CI/CD**: GitHub Actions for testing, building, and deploying
- **Database**: PostgreSQL schema with full audit trail and compliance tracking
- **Redis Queue**: Async scan job processing
- **Docker**: Production Dockerfile with non-root user and health checks

### Security
- Webhook signature verification (GitHub HMAC-SHA256, GitLab token, Stripe)
- Input validation on all API endpoints
- File size limits and recursion depth controls
- Path traversal prevention
- Non-root Docker container
