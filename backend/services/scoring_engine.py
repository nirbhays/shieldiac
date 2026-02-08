"""
ShieldIaC — Security Posture Scoring Engine

Calculates a 0-100 security score and A-F letter grade based on findings.
"""
from __future__ import annotations

from typing import List, Tuple

from backend.rules.base import Finding, Severity


class ScoringEngine:
    """Calculates security posture scores."""

    # Penalty points per finding by severity
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 15.0,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 3.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.2,
    }

    # Grade thresholds
    GRADE_THRESHOLDS = [
        (90, "A"),
        (80, "B"),
        (70, "C"),
        (60, "D"),
        (0, "F"),
    ]

    def calculate(
        self, findings: List[Finding], total_files: int = 1
    ) -> Tuple[float, str]:
        """Calculate security score (0-100) and letter grade.

        The score starts at 100 and is penalized by findings.
        The penalty is normalized by the number of files scanned to
        avoid penalizing large repos disproportionately.

        Returns (score, grade).
        """
        if not findings:
            return 100.0, "A"

        total_penalty = sum(
            self.SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings
        )

        # Normalize: more files = lower per-file impact
        normalization_factor = max(1, total_files * 0.5)
        normalized_penalty = total_penalty / normalization_factor

        # Apply diminishing returns for very high penalties
        if normalized_penalty > 50:
            normalized_penalty = 50 + (normalized_penalty - 50) * 0.3

        score = max(0, min(100, 100 - normalized_penalty))
        score = round(score, 1)

        grade = "F"
        for threshold, letter in self.GRADE_THRESHOLDS:
            if score >= threshold:
                grade = letter
                break

        return score, grade

    def calculate_trend(
        self, historical_scores: List[float]
    ) -> str:
        """Determine trend direction from historical scores.

        Returns 'improving', 'declining', or 'stable'.
        """
        if len(historical_scores) < 2:
            return "stable"

        recent = historical_scores[-3:]  # Last 3 data points
        if len(recent) < 2:
            return "stable"

        avg_change = (recent[-1] - recent[0]) / len(recent)

        if avg_change > 2:
            return "improving"
        elif avg_change < -2:
            return "declining"
        return "stable"
