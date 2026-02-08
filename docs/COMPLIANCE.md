# ShieldIaC — Compliance Framework Reference

## Overview

ShieldIaC maps every security rule to one or more compliance framework controls. This enables teams to track their compliance posture across multiple standards simultaneously — without maintaining separate tooling for each framework.

## Supported Frameworks

| Framework | Version | Controls Mapped | Focus Area |
|-----------|---------|----------------|-----------|
| CIS AWS Foundations | v1.5.0 | 18 controls | AWS infrastructure hardening |
| CIS GCP Foundations | v2.0.0 | 12 controls | GCP infrastructure hardening |
| CIS Kubernetes | v1.7.0 | 15 controls | Kubernetes cluster security |
| SOC 2 Type II | 2017 | 6 controls | Service organization trust criteria |
| HIPAA | 2013 | 5 controls | Healthcare data protection |
| PCI-DSS | v3.2.1 | 13 controls | Payment card data security |
| NIST 800-53 | Rev. 5 | 10 controls | Federal information systems |
| ISO 27001 | 2022 | 8 controls | Information security management |
| GDPR | 2018 | 4 controls | EU data protection |

## How Compliance Mapping Works

### Rule → Control Mapping

Each security rule in the ShieldIaC rule engine declares its compliance mappings:

```python
class S3BucketEncryptionRule(BaseRule):
    rule_id = "SHLD-S3-001"
    severity = Severity.HIGH
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.1",
            "Ensure S3 bucket encryption is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1",
            "Logical and Physical Access Controls"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)",
            "Encryption and Decryption"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "3.4",
            "Render PAN Unreadable"),
    ]
```

### Compliance Score Calculation

For each framework, ShieldIaC calculates:

1. **Total applicable controls** — how many controls from this framework are covered by active rules
2. **Passing controls** — controls where all mapped rules passed (no findings)
3. **Failing controls** — controls where at least one mapped rule produced a finding
4. **Compliance percentage** — `passing / total × 100`

### Compliance Posture Dashboard

The dashboard shows:
- Per-framework compliance percentage with color coding (green ≥ 80%, yellow ≥ 60%, red < 60%)
- Drill-down into each framework's controls
- Historical trend (improving/declining/stable)
- Export to PDF for auditor handoff

## Framework Details

### CIS AWS Foundations Benchmark v1.5.0

Covers IAM, logging, monitoring, networking, and storage controls for AWS.

**Key Controls:**
| Control ID | Title | Mapped Rules |
|-----------|-------|-------------|
| 1.4 | Ensure no root access key exists | SHLD-IAM-001 |
| 1.16 | Ensure IAM policies not attached to users directly | SHLD-IAM-003 |
| 2.1.1 | Ensure S3 bucket encryption enabled | SHLD-S3-001 |
| 2.1.2 | Ensure S3 bucket policy denies HTTP requests | SHLD-S3-003 |
| 2.1.5 | Ensure S3 bucket has public access blocks | SHLD-S3-002 |
| 2.2.1 | Ensure EBS encryption enabled | SHLD-EC2-003 |
| 4.1 | Ensure no security groups allow 0.0.0.0/0 to port 22 | SHLD-EC2-001 |
| 4.2 | Ensure no security groups allow 0.0.0.0/0 to port 3389 | SHLD-EC2-002 |

### SOC 2 Type II

Covers trust service criteria: security, availability, processing integrity, confidentiality, privacy.

**Key Controls:**
| Control ID | Title | Mapped Rules |
|-----------|-------|-------------|
| CC6.1 | Logical and Physical Access Controls | SHLD-IAM-*, SHLD-S3-002, SHLD-EC2-001/002 |
| CC6.3 | Role-Based Access | SHLD-IAM-003, SHLD-K8S-RBAC-* |
| CC6.5 | Data Retention and Disposal | SHLD-S3-004 |
| CC7.1 | Monitoring Activities | SHLD-VPC-001 |
| CC7.2 | Change Management | (PR workflow = inherent control) |
| A1.2 | Availability | SHLD-RDS-002, SHLD-K8S-RES-* |

### HIPAA

Covers technical and administrative safeguards for protected health information (PHI/ePHI).

**Key Controls:**
| Control ID | Title | Mapped Rules |
|-----------|-------|-------------|
| 164.312(a)(1) | Access Control | SHLD-IAM-*, SHLD-K8S-RBAC-* |
| 164.312(a)(2)(iv) | Encryption and Decryption | SHLD-S3-001, SHLD-RDS-001, SHLD-EC2-003 |
| 164.312(b) | Audit Controls | SHLD-VPC-001 |
| 164.312(e)(1) | Transmission Security | SHLD-S3-003 |
| 164.308(a)(7)(ii)(A) | Data Backup Plan | SHLD-RDS-002 |

### PCI-DSS v3.2.1

Covers payment card industry data security standards.

**Key Controls:**
| Control ID | Title | Mapped Rules |
|-----------|-------|-------------|
| 1.2.1 | Restrict Inbound/Outbound Traffic | SHLD-EC2-001/002, SHLD-VPC-*, SHLD-K8S-NET-* |
| 2.1 | Change Defaults | SHLD-RDS-003, SHLD-K8S-POD-001 |
| 3.4 | Render PAN Unreadable | SHLD-S3-001, SHLD-RDS-001 |
| 4.1 | Strong Cryptography | SHLD-S3-003, SHLD-EC2-003 |
| 7.1 | Limit Access | SHLD-IAM-003, SHLD-K8S-RBAC-* |
| 8.3 | MFA | SHLD-IAM-002 |
| 10.1 | Audit Trails | SHLD-VPC-001 |

## Generating Compliance Reports

### API Endpoint

```
GET /api/v1/reports/compliance?org_id={org}&framework=SOC2&format=pdf
```

### PDF Report Contents
1. Executive summary with overall compliance percentage
2. Per-control status (pass/fail/not-applicable)
3. Evidence: linked scan results and remediation timestamps
4. Trend chart showing compliance improvement over time
5. Appendix: full finding details for failing controls

### Auditor Handoff
Export reports as PDF for SOC 2 Type II audits, HIPAA assessments, or PCI-DSS self-assessment questionnaires. Each report includes scan timestamps, commit SHAs, and finding remediation history as evidence.
