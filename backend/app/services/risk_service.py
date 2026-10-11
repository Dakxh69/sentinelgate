"""Risk scoring engine.

Calculates multi-factor risk scores deterministically:
  final = min(1.0, base_weight + sum(context_modifiers))

Baseline Category Weights:
  - EMAIL: 0.10
  - PHONE: 0.20
  - AADHAAR: 0.70
  - CREDIT_CARD: 0.80
  - PASSWORD: 0.80
  - API_KEY: 0.90
  - SECRET: 0.90

Context Modifiers:
  - external_upload (+0.20): Triggered on file and payload uploads
  - suspicious_behavior (+0.10): Triggered when IP security event count >= 5 within 10 min
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Baseline risk weights per sensitive data category.
CATEGORY_WEIGHTS: dict[str, float] = {
    "EMAIL": 0.10,
    "PHONE": 0.20,
    "AADHAAR": 0.70,
    "CREDIT_CARD": 0.80,
    "PASSWORD": 0.80,
    "API_KEY": 0.90,
    "SECRET": 0.90,
}

# Context modifiers applied on top of category base weights.
MODIFIER_EXTERNAL_UPLOAD = 0.20
MODIFIER_SUSPICIOUS_BEHAVIOR = 0.10

SUSPICIOUS_EVENT_THRESHOLD = 5  # security_events:{source_ip} >= 5
SUSPICIOUS_TTL_SECONDS = 600  # TTL for the per-IP security event counter (seconds)


def compute_base_risk(categories: list[str]) -> float:
    """Sum of baseline weights for each unique detected category."""
    return sum(
        weight
        for category, weight in CATEGORY_WEIGHTS.items()
        if category in set(categories)
    )


def security_event_count(redis_client, source_ip: str | None) -> int:
    """Read the per-IP suspicious-behavior counter from Redis (never raises).

    Key `security_events:{source_ip}` is incremented by middleware on
    401/403/429 responses. A missing or failed lookup returns 0 safely.
    """
    if redis_client is None or not source_ip:
        return 0
    try:
        value = redis_client.get(f"security_events:{source_ip}")
    except Exception:  # noqa: BLE001 - a counter read failure is not a signal
        return 0
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def is_suspicious_behavior(redis_client, source_ip: str | None) -> bool:
    return security_event_count(redis_client, source_ip) >= SUSPICIOUS_EVENT_THRESHOLD


@dataclass
class RiskResult:
    """Risk breakdown for explainability — base weight, context modifiers, and capped final score."""

    base: float
    modifiers: dict[str, float] = field(default_factory=dict)
    final: float = 0.0

    def to_dict(self) -> dict:
        return {
            "base": round(self.base, 2),
            "modifiers": {name: round(value, 2) for name, value in self.modifiers.items()},
            "final": round(self.final, 2),
        }


def score_risk(
    categories: list[str],
    *,
    external_upload: bool = False,
    suspicious_behavior: bool = False,
) -> RiskResult:
    """Compute deterministic risk score, capped at 1.0."""
    base = compute_base_risk(categories)
    modifiers: dict[str, float] = {}
    if external_upload:
        modifiers["external_upload"] = MODIFIER_EXTERNAL_UPLOAD
    if suspicious_behavior:
        modifiers["suspicious_behavior"] = MODIFIER_SUSPICIOUS_BEHAVIOR

    raw = base + sum(modifiers.values())
    return RiskResult(base=base, modifiers=modifiers, final=min(1.0, raw))
