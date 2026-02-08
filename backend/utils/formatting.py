"""
ShieldIaC — PR Comment Formatting

Beautiful markdown formatting for GitHub/GitLab PR comments with
severity badges, finding counts, and AI fix suggestions.
"""
from __future__ import annotations

from typing import Any, Dict, List

from backend.rules.base import Finding, Severity


# Severity badge emojis and colors
SEVERITY_BADGES = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}


def format_pr_comment(findings: List[Finding], summary: Dict[str, Any]) -> str:
    """Format scan results as a beautiful PR comment."""
    lines: List[str] = []

    # Hidden marker for comment identification
    lines.append("<!-- shieldiac-scan -->")
    lines.append("")

    # Header
    score = summary.get("security_score", 0)
    grade = summary.get("grade", "?")
    total = summary.get("total_findings", 0)

    lines.append("## 🛡️ ShieldIaC Security Scan Results")
    lines.append("")

    # Score badge
    if score >= 90:
        score_emoji = "🟢"
    elif score >= 70:
        score_emoji = "🟡"
    elif score >= 50:
        score_emoji = "🟠"
    else:
        score_emoji = "🔴"

    lines.append(f"**Security Score:** {score_emoji} **{score:.0f}/100** (Grade: **{grade}**)")
    lines.append("")

    # Summary table
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(sev.lower(), 0)
        badge = SEVERITY_BADGES[sev]
        label = SEVERITY_LABELS[sev]
        lines.append(f"| {badge} {label} | {count} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    # Duration
    duration = summary.get("duration_seconds", 0)
    files_scanned = summary.get("total_files_scanned", 0)
    lines.append(f"📁 Scanned **{files_scanned}** files in **{duration:.1f}s**")
    lines.append("")

    if not findings:
        lines.append("✅ **No security issues found!** Your infrastructure code looks secure.")
        lines.append("")
        return "\n".join(lines)

    # Critical and High findings (expanded)
    critical_high = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH")]
    medium_low = [f for f in findings if f.severity.value in ("MEDIUM", "LOW")]
    info = [f for f in findings if f.severity.value == "INFO"]

    if critical_high:
        lines.append("### 🚨 Critical & High Severity Findings")
        lines.append("")
        for finding in critical_high[:20]:  # Limit to avoid huge comments
            lines.extend(_format_finding_detail(finding))

    if medium_low:
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary>⚠️ <b>Medium & Low Severity Findings ({len(medium_low)})</b></summary>")
        lines.append("")
        for finding in medium_low[:30]:
            lines.extend(_format_finding_compact(finding))
        lines.append("")
        lines.append("</details>")

    if info:
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary>ℹ️ <b>Informational Findings ({len(info)})</b></summary>")
        lines.append("")
        for finding in info[:20]:
            lines.extend(_format_finding_compact(finding))
        lines.append("")
        lines.append("</details>")

    # Footer
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Powered by [ShieldIaC](https://shieldiac.dev) — IaC Security Scanner*")
    lines.append(f"*Rule coverage: Terraform, Kubernetes, Dockerfile, CloudFormation*")

    return "\n".join(lines)


def _format_finding_detail(finding: Finding) -> List[str]:
    """Format a single finding with full details (for critical/high)."""
    lines = []
    badge = SEVERITY_BADGES.get(finding.severity.value, "⚪")

    lines.append(f"#### {badge} `{finding.rule_id}` — {finding.description}")
    lines.append("")
    lines.append(f"- **File:** `{finding.file_path}` (line {finding.line_number})")
    lines.append(f"- **Resource:** `{finding.resource_name}`")
    lines.append(f"- **Severity:** {finding.severity.value}")
    lines.append("")
    lines.append(f"**Remediation:** {finding.remediation}")

    if finding.ai_fix_suggestion:
        lines.append("")
        lines.append("**🤖 AI Fix Suggestion:**")
        lines.append("```")
        lines.append(finding.ai_fix_suggestion)
        lines.append("```")

    if finding.compliance:
        frameworks = ", ".join(f"`{c.framework.value}:{c.control_id}`" for c in finding.compliance[:3])
        lines.append(f"**Compliance:** {frameworks}")

    lines.append("")
    return lines


def _format_finding_compact(finding: Finding) -> List[str]:
    """Format a single finding in compact form."""
    badge = SEVERITY_BADGES.get(finding.severity.value, "⚪")
    lines = [
        f"- {badge} **`{finding.rule_id}`** — {finding.description}",
        f"  - 📄 `{finding.file_path}:{finding.line_number}` | Resource: `{finding.resource_name}`",
    ]
    if finding.ai_fix_suggestion:
        lines.append(f"  - 🤖 Fix available")
    return lines
