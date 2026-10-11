"""Risk scoring tests (Day 4 R6, spec section 16).

Covers: single weight, multi-category additive sum, external upload
modifier, the §16 example reproduced exactly (API_KEY + upload → 1.0),
capping at 1.0, the suspicious-behavior modifier, and zero when clean.
"""

from __future__ import annotations

import pytest

from app.services.risk_service import (
    CATEGORY_WEIGHTS,
    RiskResult,
    compute_base_risk,
    is_suspicious_behavior,
    score_risk,
)


# ------------------------------------------------------------ baseline weights


def test_single_category_weight():
    assert compute_base_risk(["EMAIL"]) == pytest.approx(0.10)
    assert compute_base_risk(["AADHAAR"]) == pytest.approx(0.70)
    assert compute_base_risk(["API_KEY"]) == pytest.approx(0.90)


def test_clean_request_zero_risk():
    result = score_risk([])
    assert result.base == 0.0
    assert result.modifiers == {}
    assert result.final == 0.0


def test_multi_category_additive_sum_below_cap():
    """Per unique category, additive (§16) — here under the cap."""
    risk = score_risk(["EMAIL", "PHONE"])
    assert risk.final == pytest.approx(0.10 + 0.20)


def test_multi_category_sum_is_capped_at_one():
    """AADHAAR 0.70 + API_KEY 0.90 = 1.60 → min(1.0, 1.60) = 1.0 (§16)."""
    risk = score_risk(["AADHAAR", "API_KEY"])
    assert risk.base == pytest.approx(1.60)
    assert risk.final == pytest.approx(1.0)


def test_spec16_weights_unchanged():
    assert CATEGORY_WEIGHTS == {
        "EMAIL": 0.10,
        "PHONE": 0.20,
        "AADHAAR": 0.70,
        "CREDIT_CARD": 0.80,
        "PASSWORD": 0.80,
        "API_KEY": 0.90,
        "SECRET": 0.90,
    }


# ------------------------------------------------------------ modifiers (§16)


def test_external_upload_modifier():
    risk = score_risk(["EMAIL"], external_upload=True)
    assert risk.modifiers == {"external_upload": pytest.approx(0.20)}
    assert risk.final == pytest.approx(0.30)


def test_spec16_example_reproduced_exactly():
    """§16: API_KEY 0.90 + external_upload 0.20 → min(1.0, 1.10) = 1.0."""
    risk = score_risk(["API_KEY"], external_upload=True)
    assert risk.base == pytest.approx(0.90)
    assert risk.modifiers["external_upload"] == pytest.approx(0.20)
    assert risk.final == pytest.approx(1.0)


def test_score_never_exceeds_one():
    """Worst case: SECRET + API_KEY + PASSWORD + upload + suspicious → 1.0."""
    risk = score_risk(
        ["SECRET", "API_KEY", "PASSWORD"],
        external_upload=True,
        suspicious_behavior=True,
    )
    assert risk.final == pytest.approx(1.0)
    assert risk.final <= 1.0


def test_suspicious_behavior_modifier():
    risk = score_risk(["PHONE"], suspicious_behavior=True)
    assert risk.modifiers == {"suspicious_behavior": pytest.approx(0.10)}
    assert risk.final == pytest.approx(0.30)


# -------------------------------------------- suspicious behavior via Redis


class _FakeRedis:
    def __init__(self, value=None, error=None):
        self._value = value
        self._error = error

    def get(self, key):
        if self._error:
            raise self._error
        return self._value


def test_security_event_counter_below_threshold_not_suspicious():
    from app.services.risk_service import security_event_count

    assert is_suspicious_behavior(_FakeRedis("4"), "1.2.3.4") is False
    assert is_suspicious_behavior(_FakeRedis("5"), "1.2.3.4") is True


def test_failed_redis_read_counts_as_zero():
    """A counter read failure must not silently raise anyone's risk."""
    from app.services.risk_service import security_event_count

    assert security_event_count(_FakeRedis(error=RuntimeError("boom")), "ip") == 0


def test_missing_client_or_ip_counts_as_zero():
    from app.services.risk_service import security_event_count

    assert security_event_count(None, "1.2.3.4") == 0
    assert security_event_count(_FakeRedis("99"), None) == 0


# --------------------------------------------------------------- breakdown


def test_breakdown_shape_for_audit_reason():
    """{base, modifiers: {name: value}, final} — feeds audit `reason` (§16)."""
    risk = score_risk(["AADHAAR"], external_upload=True, suspicious_behavior=True)
    assert isinstance(risk, RiskResult)
    breakdown = risk.to_dict()
    assert set(breakdown) == {"base", "modifiers", "final"}
    assert breakdown["base"] == pytest.approx(0.70)
    assert breakdown["modifiers"] == {
        "external_upload": pytest.approx(0.20),
        "suspicious_behavior": pytest.approx(0.10),
    }
    assert breakdown["final"] == pytest.approx(1.0)


def test_scoring_is_deterministic():
    kwargs = {
        "categories": ["AADHAAR", "API_KEY"],
        "external_upload": True,
        "suspicious_behavior": False,
    }
    first = score_risk(**kwargs)  # type: ignore[arg-type]
    second = score_risk(**kwargs)  # type: ignore[arg-type]
    assert first.to_dict() == second.to_dict()
