"""
ShieldIaC — Scoring Engine Tests
"""
import pytest

from backend.rules.base import Finding, Severity
from backend.services.scoring_engine import ScoringEngine


@pytest.fixture
def engine():
    return ScoringEngine()


def _make_finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="TEST-001",
        severity=severity,
        resource_type="terraform",
        resource_name="test",
        file_path="test.tf",
        line_number=1,
        description="Test finding",
        remediation="Fix it",
    )


def test_perfect_score_no_findings(engine):
    score, grade = engine.calculate([], 10)
    assert score == 100.0
    assert grade == "A"


def test_critical_finding_lowers_score(engine):
    findings = [_make_finding(Severity.CRITICAL)]
    score, grade = engine.calculate(findings, 1)
    assert score < 100


def test_many_findings_lower_score_more(engine):
    findings = [_make_finding(Severity.HIGH) for _ in range(10)]
    score, grade = engine.calculate(findings, 1)
    assert score < 50


def test_info_findings_minimal_impact(engine):
    findings = [_make_finding(Severity.INFO) for _ in range(5)]
    score, grade = engine.calculate(findings, 10)
    assert score >= 95


def test_grade_thresholds(engine):
    # A: 90+
    score, grade = engine.calculate([], 1)
    assert grade == "A"

    # F: < 60
    findings = [_make_finding(Severity.CRITICAL) for _ in range(10)]
    score, grade = engine.calculate(findings, 1)
    assert grade == "F"


def test_normalization_by_file_count(engine):
    """More files should reduce the per-file penalty impact."""
    findings = [_make_finding(Severity.HIGH) for _ in range(5)]
    score_few_files, _ = engine.calculate(findings, 2)
    score_many_files, _ = engine.calculate(findings, 100)
    assert score_many_files > score_few_files


def test_trend_stable(engine):
    assert engine.calculate_trend([80, 80, 80]) == "stable"


def test_trend_improving(engine):
    assert engine.calculate_trend([70, 75, 85]) == "improving"


def test_trend_declining(engine):
    assert engine.calculate_trend([90, 80, 70]) == "declining"


def test_trend_insufficient_data(engine):
    assert engine.calculate_trend([80]) == "stable"
