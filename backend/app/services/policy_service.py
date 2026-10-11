"""Policy evaluation engine.

Evaluates security policies to determine final action (ALLOW, BLOCK, REVIEW):
  - Rule Matching: Role, HTTP method, URL pattern, sensitive detection state, minimum risk.
  - Conflict Resolution: Most restrictive action wins: BLOCK > REVIEW > ALLOW.
    Tie-breaking resolves via policy constraint specificity, then ID precedence.
  - Fail Closed: Unmatched requests with sensitive detections or unscanned bodies trigger BLOCK.
  - Malformed or corrupt policy actions safely default to BLOCK.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from app.models.decision import ALLOW, BLOCK, REVIEW

# Most restrictive first (BLOCK wins over REVIEW wins over ALLOW).
_RESTRICTIVENESS = {BLOCK: 0, REVIEW: 1, ALLOW: 2}

VALID_ACTIONS = frozenset({ALLOW, BLOCK, REVIEW})


class PolicyEngineError(Exception):
    """Raised when policy evaluation itself fails (fail closed)."""


@dataclass
class PolicyDecision:
    """One evaluated decision with explainability fields for the audit log."""

    action: str  # ALLOW | BLOCK | REVIEW
    reason: str  # rule name | NO_MATCHING_POLICY
    matched_rule_id: int | None = None
    # All matching rules (id, name, action) — shows the conflict resolution.
    considered: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "matched_rule_id": self.matched_rule_id,
        }


def path_matches(pattern: str | None, path: str) -> bool:
    """Match a URL path against a policy pattern (glob or exact).

    - null or `/*` matches everything;
    - `X/*` matches X itself and any path under X (single or nested levels);
    - otherwise fnmatch glob / exact comparison.
    """
    if pattern is None or pattern == "/*":
        return True
    if pattern.endswith("/*"):
        prefix = pattern[:-1]  # keep the trailing '/'
        return path.startswith(prefix) or path == pattern[:-2]
    return fnmatch.fnmatchcase(path, pattern)


def _specificity(rule) -> tuple[int, int]:
    """Tie-break score: more non-null constraints win; a longer pattern beats
    a shorter one within the same constraint count."""
    constraints = sum(
        1
        for value in (
            rule.role,
            rule.path_pattern,
            rule.http_method,
            rule.sensitive_required,
            rule.minimum_risk,
        )
        if value is not None
    )
    pattern_len = len(rule.path_pattern) if rule.path_pattern else 0
    return constraints, pattern_len


def rule_matches(rule, *, role: str, method: str, path: str, detected: bool,
                 risk: float, unscanned: bool = False) -> bool:
    """Check whether a policy rule matches the current request context.
    `unscanned` is treated as sensitive (fail closed: truncated bodies must
    not bypass sensitive-data rules)."""
    if not rule.enabled:
        return False
    if rule.role is not None and rule.role != role:
        return False
    if rule.http_method is not None and rule.http_method.upper() != method.upper():
        return False
    if not path_matches(rule.path_pattern, path):
        return False
    sensitive = detected or unscanned
    if rule.sensitive_required is not None and rule.sensitive_required != sensitive:
        return False
    if rule.minimum_risk is not None and risk < rule.minimum_risk:
        return False
    return True


def _stored_action(rule) -> str:
    """Extract and validate rule action. Corrupt/unknown values default to
    BLOCK (fail closed)."""
    action = (rule.action or "").strip().upper()
    return action if action in VALID_ACTIONS else BLOCK


def evaluate_policies(
    rules,
    *,
    role: str,
    method: str,
    path: str,
    detected: bool,
    risk: float,
    unscanned: bool = False,
) -> PolicyDecision:
    """Evaluate all policy rules against one request.

    `rules` is any iterable of `app.models.policy.Policy` rows.
    The engine is stateless. Raises PolicyEngineError only when evaluation
    itself is impossible — the caller must fail closed on it.
    """
    try:
        matching = [
            rule
            for rule in rules
            if rule_matches(
                rule,
                role=role,
                method=method,
                path=path,
                detected=detected,
                risk=risk,
                unscanned=unscanned,
            )
        ]

        considered = [
            {"id": rule.id, "name": rule.name, "action": _stored_action(rule)}
            for rule in matching
        ]
        if not matching:
            # Fail closed: unknown territory + sensitive data → BLOCK.
            if detected or unscanned:
                return PolicyDecision(
                    action=BLOCK, reason="NO_MATCHING_POLICY", considered=considered
                )
            return PolicyDecision(
                action=ALLOW, reason="NO_MATCHING_POLICY", considered=considered
            )

        # Most restrictive wins; ties → specificity then lower id — fully deterministic.
        matching.sort(
            key=lambda rule: (
                _RESTRICTIVENESS[_stored_action(rule)],
                (-_specificity(rule)[0], -_specificity(rule)[1], rule.id),
            )
        )
        winner = matching[0]
        return PolicyDecision(
            action=_stored_action(winner),
            reason=winner.name,
            matched_rule_id=winner.id,
            considered=considered,
        )
    except PolicyEngineError:
        raise
    except Exception as exc:  # noqa: BLE001 - evaluation must fail closed
        raise PolicyEngineError(f"policy evaluation failed: {type(exc).__name__}") from exc
