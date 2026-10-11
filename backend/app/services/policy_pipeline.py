"""Policy enforcement pipeline stage.

Evaluates security policies using inspection results:
  - BLOCK: 403 DLP_POLICY_BLOCK (request halted immediately)
  - REVIEW: 202 REVIEW (held for administrator inspection)
  - ALLOW: Permitted to proceed to upstream backend microservice

Fail-closed guarantee: Any policy engine exception returns 500 INTERNAL_SECURITY_ERROR.
All outcomes produce audit event records.
"""

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.errors import SentinelGateError
from app.services.dlp_service import DLPEngineError
from app.services.policy_service import PolicyDecision, PolicyEngineError, evaluate_policies

_logger = logging.getLogger("sentinelgate")


class PolicyBlock(SentinelGateError):
    """DLP policy BLOCK → 403 DLP_POLICY_BLOCK. Nothing is forwarded."""

    status_code = 403
    error_code = "DLP_POLICY_BLOCK"
    message = "Request blocked by DLP policy"


class PolicyReview(SentinelGateError):
    """DLP policy REVIEW → 202 Accepted (held for review, not processed)."""

    status_code = 202
    error_code = "REVIEW"
    message = "Request held for review"


def evaluate_request(request: Request, db) -> PolicyDecision:
    """Evaluate the policies for an inspected request and return the decision.

    Returns the decision for ALLOW flows; raises PolicyBlock / PolicyReview
    for the enforced outcomes. Any internal failure raises
    PolicyEngineError-shaped failures as 500 INTERNAL_SECURITY_ERROR with
    the audit already written (fail closed).
    """
    dlp = getattr(request.state, "dlp_result", None)
    risk = getattr(request.state, "risk_result", None)
    if dlp is None or risk is None:
        # Pipeline ordering bug — DLP inspection stage did not run. Fail closed.
        _audit_decision(
            request, db,
            decision="BLOCK", reason="POLICY_ENGINE_ERROR",
            response_status=500, detected_categories=[],
            risk_score=1.0,
        )
        raise SentinelGateError("DLP results missing from request pipeline")

    from app.models import Policy

    try:
        rules = db.query(Policy).all()
        decision = evaluate_policies(
            rules,
            role=getattr(request.state, "user_role", None) or "",
            method=getattr(request.state, "method", "") or "",
            path=getattr(request.state, "path", "") or "",
            detected=dlp.detected,
            risk=risk.final,
            unscanned=dlp.unscanned,
        )
    except (PolicyEngineError, DLPEngineError) as exc:
        reason = (
            "DLP_ENGINE_FAILURE"
            if isinstance(exc, DLPEngineError)
            else "POLICY_ENGINE_ERROR"
        )
        _logger.error("policy pipeline fail-closed: %s", reason)
        _audit_decision(
            request, db,
            decision="BLOCK", reason=reason, response_status=500,
            detected_categories=dlp.categories(), risk_score=1.0,
        )
        raise SentinelGateError("Internal security error") from exc

    _audit_decision(
        request, db,
        decision=decision.action,
        reason=decision.reason,
        response_status={
            "BLOCK": 403,
            "REVIEW": 202,
            "ALLOW": 200,
        }.get(decision.action, 500),
        detected_categories=dlp.categories(),
        risk_score=risk.final,
    )

    if decision.action == "BLOCK":
        raise PolicyBlock()
    if decision.action == "REVIEW":
        raise PolicyReview()
    return decision


def _audit_decision(
    request: Request,
    db,
    *,
    decision: str,
    reason: str,
    response_status: int,
    detected_categories: list[str],
    risk_score: float,
) -> None:
    """Write the audit row for a decision (best-effort, never raises)."""
    from app.services.audit_service import record_event

    user = getattr(request.state, "user", None)
    record_event(
        request,
        decision=decision,
        risk_score=risk_score,
        detected_categories=detected_categories,
        reason=reason,
        response_status=response_status,
        db=db,
        user_id=getattr(user, "id", None),
        role=getattr(user, "role", None),
    )
