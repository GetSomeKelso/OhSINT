"""Tests for the vendor risk scorecard scoring logic."""

from __future__ import annotations

import pytest

from src.models import IntelFinding, IntelType
from src.pipelines.vendor_risk import VendorRiskPipeline


def _f(t: IntelType, value: str, tags=None, severity=None):
    raw = {"severity": severity} if severity else None
    return IntelFinding(type=t, value=value, source_tool="test",
                        confidence=0.9, tags=tags or [], raw_data=raw)


def test_clean_vendor_scores_a():
    """No findings → perfect score, grade A."""
    pipe = VendorRiskPipeline()
    sc = pipe.score([])
    assert sc["score"] == 100
    assert sc["grade"] == "A"


def test_leaked_secrets_drag_grade_down():
    pipe = VendorRiskPipeline()
    findings = [_f(IntelType.LEAKED_SECRET, f"secret{i}") for i in range(3)]
    sc = pipe.score(findings)
    # 3 × 10 = 30 penalty → score 70 → grade C
    assert sc["score"] == 70
    assert sc["grade"] == "C"


def test_category_cap_limits_penalty():
    """A noisy category can't exceed its cap (secret_leakage cap=40)."""
    pipe = VendorRiskPipeline()
    findings = [_f(IntelType.LEAKED_SECRET, f"s{i}") for i in range(20)]  # 20×10=200 raw
    sc = pipe.score(findings)
    assert sc["breakdown"]["secret_leakage"]["penalty"] == 40  # capped
    assert sc["score"] == 60  # 100 - 40


def test_severity_multiplier_applied():
    pipe = VendorRiskPipeline()
    crit = pipe.score([_f(IntelType.VULNERABILITY, "v", severity="critical")])
    low = pipe.score([_f(IntelType.VULNERABILITY, "v", severity="low")])
    # critical (×2.0) penalises more than low (×0.5) → lower score
    assert crit["score"] < low["score"]


def test_top_risks_sorted_by_penalty():
    pipe = VendorRiskPipeline()
    findings = [_f(IntelType.LEAKED_SECRET, "s1"),
                _f(IntelType.TECHNOLOGY, "nginx")]
    sc = pipe.score(findings)
    assert sc["top_risks"][0]["label"] == "Leaked secrets"


def test_grade_thresholds():
    pipe = VendorRiskPipeline()
    assert pipe._grade_for(95) == "A"
    assert pipe._grade_for(85) == "B"
    assert pipe._grade_for(75) == "C"
    assert pipe._grade_for(65) == "D"
    assert pipe._grade_for(40) == "F"
