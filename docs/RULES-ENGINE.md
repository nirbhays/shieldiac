# ShieldIaC — Rules Engine Reference

## Overview

The ShieldIaC rules engine is the core of the scanning pipeline. It defines a structured way to write, register, evaluate, and extend security rules across all supported IaC formats.

## Architecture

```
Rule Module (.py)
    └── BaseRule subclass
          ├── Metadata (rule_id, severity, description, compliance)
          ├── evaluate(context) → List[Finding]
          └── Auto-registered via RuleRegistry

RuleRegistry (singleton)
    ├── All rules indexed by rule_id
    ├── Filter by resource_type, severity, framework
    └── Instantiate + evaluate in ScannerEngine
```

## BaseRule API

Every rule inherits from `BaseRule` in `backend/rules/base.py`:

```python
class BaseRule(abc.ABC):
    # Required class-level attributes
    rule_id: str              # e.g. "SHLD-S3-001"
    title: str                # Human-readable title
    description: str          # What this rule checks
    severity: Severity        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    resource_type: ResourceType  # TERRAFORM | KUBERNETES | DOCKERFILE | CLOUDFORMATION
    compliance: list[ComplianceMapping] = []  # Framework control mappings

    @abc.abstractmethod
    def evaluate(self, context: RuleContext) -> list[Finding]:
        """Evaluate this rule against the given context. Return findings."""
        ...

    def make_finding(self, resource: str, message: str, file_path: str,
                     line_number: int = 0, remediation: str = "") -> Finding:
        """Helper to create a Finding with this rule's metadata."""
        ...
```

## RuleContext

The context object passed to `evaluate()`:

```python
@dataclass
class RuleContext:
    file_path: str                           # Path to the scanned file
    file_content: str                        # Raw file content
    resources: Dict[str, Any]                # Parsed resources (type → name → config)
    resource_type: ResourceType              # What format this is
    metadata: Dict[str, Any] = field(...)    # Extra context (repo, PR, org)
```

For **Terraform**, `resources` is structured as:
```python
{
    "aws_s3_bucket": {
        "my-bucket": {"bucket": "my-data", "acl": "private", ...},
    },
    "aws_instance": {
        "web": {"ami": "ami-123", "instance_type": "t3.micro", ...},
    },
}
```

For **Kubernetes**, `resources` contains the parsed YAML manifest with `kind`, `metadata`, `spec`.

For **Dockerfile**, `resources` contains parsed instructions as a list of `(instruction, arguments)` tuples.

## Finding

A finding represents a single security issue:

```python
@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    resource: str              # e.g. "aws_s3_bucket.my-bucket"
    file_path: str
    line_number: int = 0
    remediation: str = ""      # Suggested fix text
    compliance: list[ComplianceMapping] = []
    fingerprint: str = ""      # Dedup hash
    ai_fix: str | None = None  # AI-generated code fix (added post-eval)
```

## Rule ID Convention

```
SHLD-{CATEGORY}-{NUMBER}

Categories:
  S3      — AWS S3 rules
  IAM     — AWS/GCP IAM rules
  EC2     — AWS EC2/compute rules
  RDS     — AWS RDS/database rules
  VPC     — AWS VPC/networking rules
  GCP-*   — GCP-specific rules
  K8S-POD — Kubernetes pod security
  K8S-RBAC — Kubernetes RBAC
  K8S-NET — Kubernetes network policies
  K8S-RES — Kubernetes resource limits
  DOC     — Dockerfile rules
  CFN     — CloudFormation rules

Numbers: sequential within category (001, 002, ...)
```

## Writing a New Rule

### Step 1: Create the Rule File

Place it in the appropriate directory:
- Terraform AWS: `backend/rules/terraform/aws_{service}.py`
- Terraform GCP: `backend/rules/terraform/gcp_{service}.py`
- Kubernetes: `backend/rules/kubernetes/{area}.py`
- Dockerfile: `backend/rules/docker/{area}.py`

### Step 2: Define the Rule Class

```python
from backend.rules.base import (
    BaseRule, Finding, Severity, ResourceType,
    ComplianceMapping, ComplianceFramework, RuleContext,
)

class RDSPubliclyAccessibleRule(BaseRule):
    rule_id = "SHLD-RDS-004"
    title = "RDS instance is publicly accessible"
    description = (
        "RDS instances with publicly_accessible = true are reachable "
        "from the internet. This significantly increases attack surface."
    )
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.3.1",
            "Ensure RDS instances are not publicly accessible"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1",
            "Restrict inbound/outbound traffic"),
    ]

    def evaluate(self, context: RuleContext) -> list[Finding]:
        findings = []
        for name, config in context.resources.get("aws_db_instance", {}).items():
            if config.get("publicly_accessible", False):
                findings.append(self.make_finding(
                    resource=f"aws_db_instance.{name}",
                    message="RDS instance is publicly accessible",
                    file_path=context.file_path,
                    remediation='Set publicly_accessible = false',
                ))
        return findings
```

### Step 3: Write Tests

```python
# tests/test_rds_rules.py
from backend.rules.terraform.aws_rds import RDSPubliclyAccessibleRule
from backend.rules.base import RuleContext, ResourceType

def test_rds_publicly_accessible_detected():
    context = RuleContext(
        file_path="main.tf",
        file_content="",
        resources={"aws_db_instance": {"db": {"publicly_accessible": True}}},
        resource_type=ResourceType.TERRAFORM,
    )
    rule = RDSPubliclyAccessibleRule()
    findings = rule.evaluate(context)
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"

def test_rds_private_passes():
    context = RuleContext(
        file_path="main.tf",
        file_content="",
        resources={"aws_db_instance": {"db": {"publicly_accessible": False}}},
        resource_type=ResourceType.TERRAFORM,
    )
    rule = RDSPubliclyAccessibleRule()
    assert rule.evaluate(context) == []
```

### Step 4: Auto-Registration

No manual registration needed. The `loader.py` module imports all files in the rule directories, and `BaseRule.__init_subclass__` automatically registers each rule in the global `RuleRegistry`.

## Severity Guidelines

| Severity | When to Use | Examples |
|----------|------------|---------|
| **CRITICAL** | Immediate exploitation risk, data exposure | Public S3 bucket, open security group 0.0.0.0/0, no encryption on DB |
| **HIGH** | Significant risk, likely exploitable | No encryption at rest, overly permissive IAM, running as root |
| **MEDIUM** | Moderate risk, defense-in-depth gap | No VPC flow logs, missing resource limits, no health checks |
| **LOW** | Minor risk, best practice deviation | Missing tags, deprecated API versions, non-optimal config |
| **INFO** | Informational, no direct security impact | Recommendations, upcoming deprecations |

## Built-in Rule Summary

### Terraform — AWS (50+ rules)
- **S3:** Encryption, public access blocks, versioning, logging, SSL enforcement
- **IAM:** Wildcard policies, user-attached policies, MFA, password policy
- **EC2:** Open ports (SSH/RDP), unencrypted EBS, public IPs, IMDSv2
- **RDS:** Encryption, backups, multi-AZ, public access, deletion protection
- **VPC:** Flow logs, default security groups, unrestricted egress

### Terraform — GCP (15+ rules)
- **Compute:** Serial port, OS login, default service account, public IP
- **IAM:** Primitive roles, service account keys
- **Storage:** Uniform access, public access, versioning

### Kubernetes (25+ rules)
- **Pod Security:** Privileged containers, root user, capabilities, host namespaces
- **RBAC:** Cluster-admin bindings, wildcard permissions
- **Network:** Missing NetworkPolicy
- **Resources:** Missing CPU/memory limits and requests

### Dockerfile (20+ rules)
- **Base Image:** Latest tag, untrusted registries
- **Security:** Running as root, secrets in ENV, COPY vs ADD
- **Best Practices:** Health checks, multi-stage builds, apt-get cleanup
