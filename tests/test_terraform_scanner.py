"""
ShieldIaC — Terraform Scanner Tests

Tests all Terraform rules against known-insecure and known-secure fixtures.
"""
import pytest
from pathlib import Path

from backend.rules.base import RuleContext, Severity, registry
from backend.services.terraform_scanner import TerraformScanner


@pytest.fixture
def scanner():
    return TerraformScanner()


@pytest.fixture
def insecure_s3():
    return Path(__file__).parent / "fixtures" / "terraform" / "insecure_s3.tf"


@pytest.fixture
def insecure_ec2():
    return Path(__file__).parent / "fixtures" / "terraform" / "insecure_ec2.tf"


@pytest.fixture
def secure_vpc():
    return Path(__file__).parent / "fixtures" / "terraform" / "secure_vpc.tf"


@pytest.mark.asyncio
async def test_insecure_s3_finds_issues(scanner, insecure_s3):
    """Insecure S3 bucket should trigger multiple findings."""
    content = insecure_s3.read_text()
    findings = await scanner.scan("insecure_s3.tf", content)
    assert len(findings) > 0
    rule_ids = {f.rule_id for f in findings}
    # Should find public ACL issue
    assert "SHLD-S3-006" in rule_ids


@pytest.mark.asyncio
async def test_insecure_ec2_finds_ssh(scanner, insecure_ec2):
    """Insecure EC2 config should detect open SSH."""
    content = insecure_ec2.read_text()
    findings = await scanner.scan("insecure_ec2.tf", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-EC2-001" in rule_ids  # Unrestricted SSH


@pytest.mark.asyncio
async def test_insecure_ec2_finds_rdp(scanner, insecure_ec2):
    """Insecure EC2 config should detect open RDP."""
    content = insecure_ec2.read_text()
    findings = await scanner.scan("insecure_ec2.tf", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-EC2-002" in rule_ids  # Unrestricted RDP


@pytest.mark.asyncio
async def test_insecure_ec2_finds_secrets(scanner, insecure_ec2):
    """EC2 with secrets in user_data should be flagged."""
    content = insecure_ec2.read_text()
    findings = await scanner.scan("insecure_ec2.tf", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-EC2-008" in rule_ids  # Secrets in user data


@pytest.mark.asyncio
async def test_secure_vpc_minimal_findings(scanner, secure_vpc):
    """Secure VPC should have minimal or no findings."""
    content = secure_vpc.read_text()
    findings = await scanner.scan("secure_vpc.tf", content)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


def test_s3_encryption_rule_triggers():
    """Direct rule test: S3 bucket without encryption."""
    from backend.rules.terraform.aws_s3 import S3EncryptionAtRest
    rule = S3EncryptionAtRest()
    resource = {
        "type": "aws_s3_bucket",
        "name": "test_bucket",
        "config": {},
        "line": 1,
    }
    context = RuleContext(file_path="test.tf")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_s3_encryption_rule_passes():
    """Direct rule test: S3 bucket with encryption passes."""
    from backend.rules.terraform.aws_s3 import S3EncryptionAtRest
    rule = S3EncryptionAtRest()
    resource = {
        "type": "aws_s3_bucket",
        "name": "test_bucket",
        "config": {
            "server_side_encryption_configuration": {
                "rule": {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "aws:kms"
                    }
                }
            }
        },
        "line": 1,
    }
    context = RuleContext(file_path="test.tf")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 0


def test_ec2_imdsv2_rule():
    """Direct rule test: EC2 without IMDSv2."""
    from backend.rules.terraform.aws_ec2 import EC2IMDSv2
    rule = EC2IMDSv2()
    resource = {
        "type": "aws_instance",
        "name": "test_instance",
        "config": {},
        "line": 1,
    }
    context = RuleContext(file_path="test.tf")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1


def test_iam_wildcard_rule():
    """Direct rule test: IAM policy with wildcard actions."""
    from backend.rules.terraform.aws_iam import IAMWildcardActions
    rule = IAMWildcardActions()
    resource = {
        "type": "aws_iam_policy",
        "name": "admin_policy",
        "config": {
            "policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        },
        "line": 1,
    }
    context = RuleContext(file_path="test.tf")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_rds_public_access_rule():
    """Direct rule test: RDS publicly accessible."""
    from backend.rules.terraform.aws_rds import RDSPublicAccess
    rule = RDSPublicAccess()
    resource = {
        "type": "aws_db_instance",
        "name": "test_db",
        "config": {"publicly_accessible": True},
        "line": 1,
    }
    context = RuleContext(file_path="test.tf")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_vpc_flow_logs_rule():
    """Direct rule test: VPC without flow logs."""
    from backend.rules.terraform.aws_vpc import VPCFlowLogs
    rule = VPCFlowLogs()
    resource = {
        "type": "aws_vpc",
        "name": "test_vpc",
        "config": {},
        "line": 1,
    }
    context = RuleContext(file_path="test.tf", all_resources=[])
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1


def test_gcp_firewall_rule():
    """Direct rule test: GCP firewall allows all from 0.0.0.0/0."""
    from backend.rules.terraform.gcp_compute import GCPFirewallAllowAll
    rule = GCPFirewallAllowAll()
    resource = {
        "type": "google_compute_firewall",
        "name": "allow_all",
        "config": {
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "all"}],
        },
        "line": 1,
    }
    context = RuleContext(file_path="test.tf")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_rule_registry_has_terraform_rules():
    """Registry should contain all Terraform rules."""
    from backend.rules.base import ResourceType
    tf_rules = registry.by_resource_type(ResourceType.TERRAFORM)
    assert len(tf_rules) >= 50, f"Expected 50+ Terraform rules, got {len(tf_rules)}"
