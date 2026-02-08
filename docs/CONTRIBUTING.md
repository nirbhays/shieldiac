# Contributing to ShieldIaC

We welcome contributions, especially new security rules.

---

## How to Add a New Security Rule

Adding a rule is a 3-step process:

### Step 1: Create the Rule Class

Create a new file or add to an existing file in the appropriate `rules/` subdirectory:

```python
# backend/rules/terraform/aws_lambda.py

from backend.rules.base import (
    BaseRule, Finding, RuleContext, Severity, ResourceType,
    ComplianceMapping, ComplianceFramework, registry,
)
from typing import Any, Dict, List


@registry.register
class LambdaNoVpc(BaseRule):
    """Detect Lambda functions not attached to a VPC."""

    id = "SHLD-LAMBDA-001"
    description = "Lambda function is not configured to run in a VPC"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add vpc_config block with subnet_ids and security_group_ids"
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.8.1", "Lambda VPC config"),
    ]
    tags = ["lambda", "networking", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_lambda_function":
            return []

        config = resource.get("config", {})
        vpc_config = config.get("vpc_config")

        if not vpc_config:
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]

        return []
```

### Step 2: Verify Auto-Registration

The rule loader automatically discovers new modules. Just ensure your file is inside the correct package directory. Run the loader to verify:

```python
from backend.rules.loader import load_all_rules
load_all_rules()

from backend.rules.base import registry
print(registry.summary())  # Should show your new rule
```

### Step 3: Add Test Fixtures

Add sample IaC files to `tests/fixtures/` that trigger your rule:

```hcl
# tests/fixtures/terraform/lambda_no_vpc.tf
resource "aws_lambda_function" "bad" {
  function_name = "my-function"
  handler       = "index.handler"
  runtime       = "python3.12"
  # Missing vpc_config - should trigger SHLD-LAMBDA-001
}
```

---

## Development Setup

```bash
# Clone and install
git clone https://github.com/your-org/shieldiac.git
cd shieldiac/backend
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run linting
ruff check .
mypy .

# Start development server
uvicorn main:app --reload --port 8000
```

---

## Code Style

- Python 3.10+ with type hints
- `from __future__ import annotations` in all files
- Pydantic v2 for data models
- async/await for I/O operations
- Conventional Commits for commit messages

---

## PR Checklist

- [ ] New rule has unique `id` following `SHLD-{SERVICE}-{NUMBER}` convention
- [ ] Rule has `description`, `severity`, `remediation`, and `compliance` mappings
- [ ] Test fixtures added for positive and negative cases
- [ ] All existing tests pass (`pytest tests/`)
- [ ] Code passes linting (`ruff check .`)
- [ ] Documentation updated if adding a new feature
