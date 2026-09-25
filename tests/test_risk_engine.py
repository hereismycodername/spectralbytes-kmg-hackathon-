import pytest

from app.certificate_checker import (
    build_risk_assessment,
    risk_level_for_score,
    status_from_days,
)


@pytest.mark.parametrize(
    ("days_left", "expected_score", "expected_level"),
    [
        (61, 0, "Low"),
        (60, 15, "Low"),
        (30, 40, "Medium"),
        (14, 70, "High"),
        (7, 85, "Critical"),
        (1, 95, "Critical"),
        (0, 100, "Critical"),
        (-10, 100, "Critical"),
    ],
)
def test_base_risk_from_days(days_left, expected_score, expected_level):
    result = build_risk_assessment(
        days_left=days_left,
        hostname_mismatch=False,
        untrusted_chain=False,
        is_self_signed=False,
        weak_signature=False,
        weak_key=False,
        owner_assigned=True,
    )
    assert result["risk_score"] == expected_score
    assert result["risk_level"] == expected_level


@pytest.mark.parametrize(
    ("score", "level"),
    [(0, "Low"), (20, "Low"), (21, "Medium"), (50, "Medium"), (51, "High"), (80, "High"), (81, "Critical"), (100, "Critical")],
)
def test_risk_level_boundaries(score, level):
    assert risk_level_for_score(score) == level


@pytest.mark.parametrize(
    ("days_left", "status"),
    [
        (61, "OK"),
        (60, "Information"),
        (31, "Information"),
        (30, "Warning"),
        (15, "Warning"),
        (14, "Critical"),
        (8, "Critical"),
        (7, "Critical"),
        (1, "Critical"),
        (0, "Expired"),
        (-1, "Expired"),
    ],
)
def test_status_day_thresholds(days_left, status):
    assert status_from_days(days_left)[0] == status


def test_security_penalties_are_added_and_capped():
    result = build_risk_assessment(
        days_left=90,
        hostname_mismatch=True,
        untrusted_chain=True,
        is_self_signed=True,
        weak_signature=True,
        weak_key=True,
        owner_assigned=False,
    )
    assert result["risk_score"] == 85
    assert result["risk_level"] == "Critical"


def test_reasons_and_recommendations_explain_findings():
    result = build_risk_assessment(
        days_left=5,
        hostname_mismatch=True,
        untrusted_chain=False,
        is_self_signed=True,
        weak_signature=False,
        weak_key=True,
        owner_assigned=False,
        key_type="RSA",
        key_size=1024,
    )
    reasons = " ".join(result["risk_reasons"])
    recommendations = " ".join(result["recommendations"])
    assert "5 дней" in reasons
    assert "Самоподписанный" in reasons
    assert "RSA 1024" in reasons
    assert "ответственный" in reasons
    assert "перевып" in recommendations.lower()
    assert "назначьте ответственного" in recommendations.lower()
