"""
ShieldIaC — Compliance Mapper

Maps security findings to compliance framework controls and generates
compliance posture reports.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from backend.models.compliance import (
    ComplianceControl,
    ComplianceDashboard,
    ComplianceFrameworkSummary,
    ComplianceReport,
)
from backend.rules.base import ComplianceFramework, Finding

logger = logging.getLogger(__name__)


# ── Control Catalogs ─────────────────────────────────────────────────────

SOC2_CONTROLS = {
    "CC6.1": ComplianceControl(control_id="CC6.1", title="Logical and Physical Access Controls", description="The entity restricts logical access to information assets.", section="CC6 – Logical and Physical Access Controls"),
    "CC6.3": ComplianceControl(control_id="CC6.3", title="Role-Based Access", description="The entity creates, modifies, and removes access based on authorization.", section="CC6 – Logical and Physical Access Controls"),
    "CC6.5": ComplianceControl(control_id="CC6.5", title="Data Retention and Disposal", description="The entity disposes of data in accordance with retention policies.", section="CC6 – Logical and Physical Access Controls"),
    "CC7.1": ComplianceControl(control_id="CC7.1", title="Monitoring Activities", description="The entity monitors system components and operations.", section="CC7 – System Operations"),
    "CC7.2": ComplianceControl(control_id="CC7.2", title="Change Management", description="The entity manages changes to system components.", section="CC7 – System Operations"),
    "A1.2": ComplianceControl(control_id="A1.2", title="Availability", description="The entity maintains availability commitments and system requirements.", section="A1 – Availability"),
}

HIPAA_CONTROLS = {
    "164.312(a)(1)": ComplianceControl(control_id="164.312(a)(1)", title="Access Control", description="Implement policies for electronic access to ePHI.", section="Technical Safeguards"),
    "164.312(a)(2)(iv)": ComplianceControl(control_id="164.312(a)(2)(iv)", title="Encryption and Decryption", description="Implement mechanism to encrypt/decrypt ePHI.", section="Technical Safeguards"),
    "164.312(b)": ComplianceControl(control_id="164.312(b)", title="Audit Controls", description="Implement hardware/software/procedural mechanisms for audit.", section="Technical Safeguards"),
    "164.312(e)(1)": ComplianceControl(control_id="164.312(e)(1)", title="Transmission Security", description="Implement technical security measures for ePHI transmission.", section="Technical Safeguards"),
    "164.308(a)(7)(ii)(A)": ComplianceControl(control_id="164.308(a)(7)(ii)(A)", title="Data Backup Plan", description="Establish procedures for retrievable exact copies of ePHI.", section="Administrative Safeguards"),
}

PCI_DSS_CONTROLS = {
    "1.2.1": ComplianceControl(control_id="1.2.1", title="Restrict Inbound/Outbound Traffic", description="Restrict inbound and outbound traffic to that which is necessary.", section="Requirement 1 – Firewall Configuration"),
    "1.3.1": ComplianceControl(control_id="1.3.1", title="Prohibit Direct Public Access", description="Implement a DMZ to limit inbound traffic.", section="Requirement 1 – Firewall Configuration"),
    "2.1": ComplianceControl(control_id="2.1", title="Change Defaults", description="Always change vendor-supplied defaults.", section="Requirement 2 – Default Settings"),
    "2.2": ComplianceControl(control_id="2.2", title="Configuration Standards", description="Develop configuration standards for all system components.", section="Requirement 2 – Default Settings"),
    "3.4": ComplianceControl(control_id="3.4", title="Render PAN Unreadable", description="Render PAN unreadable anywhere it is stored.", section="Requirement 3 – Stored Data Protection"),
    "4.1": ComplianceControl(control_id="4.1", title="Strong Cryptography", description="Use strong cryptography and security protocols during transmission.", section="Requirement 4 – Transmission Encryption"),
    "7.1": ComplianceControl(control_id="7.1", title="Limit Access", description="Limit access to system components to only those individuals whose job requires it.", section="Requirement 7 – Access Restriction"),
    "8.2.3": ComplianceControl(control_id="8.2.3", title="Password Complexity", description="Passwords must meet complexity requirements.", section="Requirement 8 – Identification and Authentication"),
    "8.2.4": ComplianceControl(control_id="8.2.4", title="Change Passwords", description="Change user passwords at least every 90 days.", section="Requirement 8 – Identification and Authentication"),
    "8.2.5": ComplianceControl(control_id="8.2.5", title="Password Reuse", description="Do not allow submission of previously used password.", section="Requirement 8 – Identification and Authentication"),
    "8.3": ComplianceControl(control_id="8.3", title="MFA", description="Secure all individual non-console admin access with MFA.", section="Requirement 8 – Identification and Authentication"),
    "10.1": ComplianceControl(control_id="10.1", title="Audit Trails", description="Implement audit trails to link access to individual users.", section="Requirement 10 – Track and Monitor"),
    "10.7": ComplianceControl(control_id="10.7", title="Retain Audit History", description="Retain audit trail history for at least one year.", section="Requirement 10 – Track and Monitor"),
}

FRAMEWORK_CATALOGS = {
    ComplianceFramework.SOC2: ("SOC 2 Type II", "2017", SOC2_CONTROLS),
    ComplianceFramework.HIPAA: ("HIPAA", "2013", HIPAA_CONTROLS),
    ComplianceFramework.PCI_DSS: ("PCI DSS", "4.0", PCI_DSS_CONTROLS),
}


class ComplianceMapper:
    """Maps findings to compliance controls and generates reports."""

    def generate_report(
        self,
        framework: ComplianceFramework,
        findings: List[Finding],
        repo_url: str = "",
        scan_id: str = "",
    ) -> ComplianceReport:
        """Generate a compliance report for a specific framework."""
        catalog_entry = FRAMEWORK_CATALOGS.get(framework)
        if not catalog_entry:
            raise ValueError(f"Unsupported framework: {framework}")

        display_name, version, controls_catalog = catalog_entry

        # Build control status from findings
        controls = self._evaluate_controls(framework, controls_catalog, findings)

        passing = sum(1 for c in controls if c.status == "pass")
        failing = sum(1 for c in controls if c.status == "fail")
        na = sum(1 for c in controls if c.status == "not_applicable")
        unknown = sum(1 for c in controls if c.status == "unknown")
        total = len(controls)
        pct = (passing / total * 100) if total > 0 else 0

        summary = ComplianceFrameworkSummary(
            framework=framework.value,
            display_name=display_name,
            version=version,
            total_controls=total,
            passing=passing,
            failing=failing,
            not_applicable=na,
            unknown=unknown,
            compliance_percentage=round(pct, 1),
        )

        recommendations = self._generate_recommendations(controls, findings)

        return ComplianceReport(
            framework=framework.value,
            display_name=display_name,
            version=version,
            generated_at="",
            repo_url=repo_url,
            scan_id=scan_id,
            summary=summary,
            controls=controls,
            recommendations=recommendations,
        )

    def generate_dashboard(self, findings: List[Finding]) -> ComplianceDashboard:
        """Generate an aggregated compliance dashboard."""
        frameworks = []
        all_failing = []

        for fw in FRAMEWORK_CATALOGS:
            report = self.generate_report(fw, findings)
            frameworks.append(report.summary)
            all_failing.extend([c for c in report.controls if c.status == "fail"])

        overall = (
            sum(f.compliance_percentage for f in frameworks) / len(frameworks)
            if frameworks else 0
        )

        top_failing = sorted(all_failing, key=lambda c: c.finding_count, reverse=True)[:10]

        return ComplianceDashboard(
            frameworks=frameworks,
            overall_score=round(overall, 1),
            top_failing_controls=top_failing,
        )

    def _evaluate_controls(
        self,
        framework: ComplianceFramework,
        catalog: Dict[str, ComplianceControl],
        findings: List[Finding],
    ) -> List[ComplianceControl]:
        """Evaluate each control's status based on findings."""
        control_findings: Dict[str, List[str]] = {cid: [] for cid in catalog}

        for finding in findings:
            for mapping in finding.compliance:
                if mapping.framework == framework and mapping.control_id in control_findings:
                    control_findings[mapping.control_id].append(finding.rule_id)

        controls = []
        for cid, base_control in catalog.items():
            rule_ids = control_findings[cid]
            status = "pass" if not rule_ids else "fail"
            controls.append(ComplianceControl(
                control_id=base_control.control_id,
                title=base_control.title,
                description=base_control.description,
                section=base_control.section,
                status=status,
                finding_count=len(rule_ids),
                rule_ids=list(set(rule_ids)),
            ))

        return controls

    @staticmethod
    def _generate_recommendations(controls: List[ComplianceControl], findings: List[Finding]) -> List[str]:
        failing = [c for c in controls if c.status == "fail"]
        recs = []
        for control in failing[:5]:
            recs.append(
                f"[{control.control_id}] {control.title}: "
                f"{control.finding_count} finding(s) detected. "
                f"Review and remediate rules: {', '.join(control.rule_ids[:3])}"
            )
        return recs
