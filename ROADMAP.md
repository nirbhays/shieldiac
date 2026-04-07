# ShieldIaC Roadmap

## Vision
Become the default zero-config IaC security layer for every GitHub repository — the way ESLint is for JavaScript.

## ✅ Shipped
- 100+ security rules (Terraform, Kubernetes, Dockerfile, CloudFormation)
- 9 compliance frameworks (CIS, SOC 2, HIPAA, PCI-DSS, NIST, ISO 27001, GDPR, AWS Well-Arch, GCP Security)
- AI-powered fix suggestions via GPT-4.1-mini
- Security scoring A–F per scan
- PDF compliance reports
- Web dashboard with trend tracking
- GitHub App — zero-config install

## 🔨 In Progress
- [ ] CLI mode for local scanning (`shieldiac scan ./infra`)
- [ ] ARM (Azure Resource Manager) template support
- [ ] Improved AI fix context (reads surrounding resources)

## 📋 Planned — Q2 2025
- [ ] GitLab CI integration
- [ ] Bitbucket Pipelines integration
- [ ] Slack / Teams notifications for CRITICAL findings
- [ ] Custom rule authoring (YAML DSL)
- [ ] Missing resource tag enforcement

## 📋 Planned — Q3 2025
- [ ] Drift detection (compare IaC to live cloud state)
- [ ] Multi-repo organisation dashboard
- [ ] SARIF output format for GitHub Security tab integration
- [ ] Terraform module scanning (registry modules)
- [ ] ISO 42001 compliance mapping

## 💡 Under Consideration
- Pulumi support
- CDK (AWS Cloud Development Kit) support
- VSCode extension for real-time scanning
- Self-hosted GitHub App deployment guide

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) — all roadmap items are open for community contributions.
