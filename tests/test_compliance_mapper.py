"""
ShieldIaC — Compliance Mapper Tests
"""
import pytest

from backend.rules.base import ComplianceFramework, ComplianceMapping, Finding, Severity
from backend.services.compliance_mapper import ComplianceMapper


@pytest.fixture
def mapper():
    return ComplianceMapper()


@pytest.fixture
def sample_findings():
    return [
        Finding(
            rule_id="SHLD-S3-001",
            severity=Severity.HIGH,
            resource_type="terraform",
            resource_name="test_bucket",
            file_path="main.tf",
            line_number=5,
            description="S3 bucket no encryption",
            remediation="Enable encryption",
            compliance=[
                ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Data protection"),
                ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption"),
                ComplianceMapping(ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable"),
            ],
        ),
        Finding(
            rule_id="SHLD-EC2-001",
            severity=Severity.CRITICAL,
            resource_type="terraform",
            resource_name="test_sg",
            file_path="main.tf",
            line_number=20,
            description="Unrestricted SSH",
            remediation="Restrict SSH",
            compliance=[
                ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict traffic"),
                ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Access controls"),
            ],
        ),
    ]


def test_generate_soc2_report(mapper, sample_findings):
    report = mapper.generate_report(ComplianceFramework.SOC2, sample_findings)
    assert report.framework == "SOC2"
    assert report.summary.total_controls > 0
    assert report.summary.failing > 0
    # CC6.1 should be failing
    cc61 = next((c for c in report.controls if c.control_id == "CC6.1"), None)
    assert cc61 is not None
    assert cc61.status == "fail"


def test_generate_hipaa_report(mapper, sample_findings):
    report = mapper.generate_report(ComplianceFramework.HIPAA, sample_findings)
    assert report.framework == "HIPAA"
    enc_control = next((c for c in report.controls if c.control_id == "164.312(a)(2)(iv)"), None)
    assert enc_control is not None
    assert enc_control.status == "fail"


def test_generate_pci_report(mapper, sample_findings):
    report = mapper.generate_report(ComplianceFramework.PCI_DSS, sample_findings)
    assert report.framework == "PCI-DSS"
    assert report.summary.failing > 0


def test_compliance_dashboard(mapper, sample_findings):
    dashboard = mapper.generate_dashboard(sample_findings)
    assert len(dashboard.frameworks) == 3  # SOC2, HIPAA, PCI-DSS
    assert dashboard.overall_score >= 0


def test_empty_findings_all_pass(mapper):
    report = mapper.generate_report(ComplianceFramework.SOC2, [])
    assert report.summary.failing == 0
    assert report.summary.compliance_percentage == 100.0


def test_recommendations_generated(mapper, sample_findings):
    report = mapper.generate_report(ComplianceFramework.SOC2, sample_findings)
    assert len(report.recommendations) > 0
