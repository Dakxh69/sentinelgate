"""Gateway core pipeline service.

Executes the Zero-Trust security pipeline in strict, deterministic sequence:
    1. Authentication (JWT verification)
    2. Authorization (RBAC permission validation)
    3. Rate Limiting (Distributed Redis token-bucket / fixed window)
    4. DLP Inspection (Sensitive pattern & keyword detection)
    5. Risk Scoring (Multi-factor weighted risk assessment)
    6. Policy Evaluation (Least-permissive-wins rule evaluation)
    7. Allow/Block/Review Decision:
       - ALLOW: Forward to internal protected microservice with sanitized identity headers
       - BLOCK: Reject with 403 DLP_POLICY_BLOCK (never forwarded)
       - REVIEW: Hold with 202 status (never forwarded)
    8. Audit Logging: Record complete decision event in PostgreSQL

Security invariant: Fail-closed on all internal errors.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response

_logger = logging.getLogger("sentinelgate")

# Route table: client resource → internal backend resource.
FORWARDED_ROUTES: dict[str, tuple[str, str]] = {
    "GET /protected/data": ("GET", "/internal/data"),
    "POST /protected/upload": ("POST", "/internal/upload"),
}
# /protected/profile stays gateway-owned (no forward entry).

# Downstream availability error (deliberately distinct from security failures).
BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"


class PipelineStage:
    """Named pipeline stages for the order-asserting test (dummy-hook friendly)."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMITING = "rate_limiting"
    DLP = "dlp_inspection"
    RISK = "risk_scoring"
    POLICY = "policy_evaluation"
    FORWARD = "forward_to_backend"
    AUDIT = "audit"


class SentinelFailClosed(Exception):
    """Internal marker: a security stage failed and already audited a rejection."""


class StageRecorder:
    """Sequential stage recorder used by the pipeline-order test."""

    def __init__(self) -> None:
        self.names: list[str] = []

    def record(self, name: str) -> None:
        self.names.append(name)


async def handle_protected(
    request: Request,
    *,
    current_user,
    db,
    stages: StageRecorder | None = None,
) -> Response:
    """Run the security pipeline for /protected/data|upload and return the Response.

    `stages`: injected recorder used by the pipeline-order unit test;
    production callers leave it None (a fresh recorder is created and stored
    on request.state so tests can still observe the sequence).

    Authentication/authorization ran as FastAPI dependencies before this call
    (get_current_user / require_role); recording them here keeps the pipeline
    sequence observable and explicit.
    """
    recorder = stages or StageRecorder()
    request.state.pipeline_stages = recorder
    # Identity stays on request.state for the DLP/policy/audit stages
    # (policy evaluation is role-aware).
    request.state.user = current_user
    request.state.user_role = getattr(current_user, "role", None)

    recorder.record(PipelineStage.AUTHENTICATION)
    recorder.record(PipelineStage.AUTHORIZATION)

    # ---------------------------------------------------------- rate limiting
    recorder.record(PipelineStage.RATE_LIMITING)
    from app.services.rate_limit_service import enforce_user_rate_limit_raw

    from app.core.errors import SentinelGateError

    try:
        enforce_user_rate_limit_raw(request, current_user, db)
    except SentinelGateError as limiter_error:
        # Limiter already audited its rejection: stop the pipeline here —
        # never reach DLP/forwarding. Render the limiter's own error
        # (429 RATE_LIMIT_EXCEEDED / 503 REDIS_UNAVAILABLE).
        return JSONResponse(
            status_code=limiter_error.status_code,
            content={
                "error": limiter_error.error_code,
                "message": limiter_error.message,
            },
        )

    # ---------------------------------------------------------- DLP + risk
    try:
        recorder.record(PipelineStage.DLP)
        body = await _safe_body(request)
        dlp, risk = _inspect(
            request, body, external_upload=_is_upload(request), db=db
        )
        recorder.record(PipelineStage.RISK)
        request.state.risk_result = risk
    except DLPEngineStageFailure as exc:
        # DLP engine failure: already audited — reject fail closed.
        _logger.warning("gateway fail-closed at DLP stage")
        return _fail_closed()

    # ---------------------------------------------------------- policy
    recorder.record(PipelineStage.POLICY)
    try:
        decision = _evaluate(request, db)
    except SentinelFailClosed:
        # Policy engine error: already audited — reject fail closed.
        _logger.warning("gateway fail-closed at policy stage")
        return _fail_closed()

    # ---------------------------------------------------------- decision
    # PolicyBlock / PolicyReview come back as decision exceptions:
    # BLOCK/REVIEW short-circuit before forwarding; audit rows were already
    # written by the policy stage (audit always happens).
    import app.services.policy_pipeline as policy_pipeline

    is_block = isinstance(decision, policy_pipeline.PolicyBlock) or (
        getattr(decision, "action", None) == "BLOCK"
    )
    is_review = isinstance(decision, policy_pipeline.PolicyReview) or (
        getattr(decision, "action", None) == "REVIEW"
    )
    if is_block or is_review:
        # Audit already recorded by evaluate_request; mark the audit stage
        # so the recorded sequence shows it happened.
        recorder.record(PipelineStage.AUDIT)
        return _blocked() if is_block else _review()

    # ---------------------------------------------------------- forward (ALLOW)
    recorder.record(PipelineStage.FORWARD)
    response = await _forward(request, db)

    # ---------------------------------------------------------- audit
    recorder.record(PipelineStage.AUDIT)
    if isinstance(response, SentinelFailClosed):
        # Backend unreachable: 502 availability error, audited inside _forward.
        return _unavailable()
    return response


class DLPEngineStageFailure(Exception):
    """DLP stage failed — audit row already written by the scanner."""


def _is_upload(request: Request) -> bool:
    return request.method == "POST" and request.url.path == "/protected/upload"


async def _safe_body(request: Request) -> str | None:
    """Read the raw request body as text for DLP scanning.

    Never logged. Empty/unreadable bodies scan as nothing; oversized
    payloads are truncated-and-flagged inside scan_request (unscanned: true).
    """
    try:
        raw = await request.body()
    except Exception:  # noqa: BLE001 - unreadable body must not crash staging
        return None
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace")


def _inspect(request: Request, body: str | None, *, external_upload: bool, db) -> Any:
    """DLP inspection + risk scoring pipeline stage."""
    from app.services.dlp_pipeline import inspect_request

    try:
        return inspect_request(
            request, body, external_upload=external_upload, db=db
        )
    except Exception as exc:  # noqa: BLE001 - DLP stage failure is fail closed
        # inspect_request already audited DLP_ENGINE_FAILURE;
        # surface the fail-closed marker to the decision logic.
        raise DLPEngineStageFailure() from exc


def _evaluate(request: Request, db) -> Any:
    """Policy evaluation stage.

    Returns the ALLOW PolicyDecision, or the PolicyBlock/PolicyReview decision
    exception (rendered as 403/202 by the pipeline — never forwarded).
    Raises SentinelFailClosed on a real engine failure (fail closed).
    """
    from app.services.policy_pipeline import evaluate_request

    try:
        return evaluate_request(request, db)
    except Exception as exc:  # noqa: BLE001 - triage below decides the path
        import app.services.policy_pipeline as policy_pipeline

        if isinstance(
            exc, (policy_pipeline.PolicyBlock, policy_pipeline.PolicyReview)
        ):
            # Enforced decisions, not engine failures — return them as the
            # stage result so decision rendering stays in one place.
            return exc
        raise SentinelFailClosed() from exc


def _fail_closed() -> Response:
    """Return 500 INTERNAL_SECURITY_ERROR — generic, no internals leaked."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_SECURITY_ERROR",
            "message": "Internal security error",
        },
    )


def _blocked() -> Response:
    return JSONResponse(
        status_code=403,
        content={
            "error": "DLP_POLICY_BLOCK",
            "message": "Request blocked by DLP policy",
        },
    )


def _review() -> Response:
    return JSONResponse(
        status_code=202,
        content={
            "decision": "REVIEW",
            "reason": "Request held for review by DLP policy",
        },
    )


def _unavailable() -> Response:
    return JSONResponse(
        status_code=502,
        content={
            "error": BACKEND_UNAVAILABLE,
            "message": "Backend did not respond",
        },
    )


async def _forward(request: Request, db) -> Response | SentinelFailClosed:
    """Forward an ALLOWed request to the internal backend over httpx."""
    from app.core.config import get_settings
    from app.services.audit_service import record_event

    from app.services.dlp_pipeline import stage_response_extra

    settings = get_settings()
    user = getattr(request.state, "user", None)
    route_key = f"{request.method} {request.url.path}"
    route = FORWARDED_ROUTES.get(route_key)
    if route is None:
        # Gateway-owned resource: render the pipeline observability payload.
        dlp = getattr(request.state, "dlp_result", None)
        risk = getattr(request.state, "risk_result", None)
        payload = stage_response_extra(dlp, risk) if dlp is not None else {}
        payload["stage"] = "forwarded"
        return JSONResponse(status_code=200, content=payload)

    backend_method, backend_path = route
    url = f"{settings.BACKEND_URL}{backend_path}"
    headers = _sanitized_headers(request)
    body = await _safe_body(request)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client_http:
            backend_response = await client_http.request(
                backend_method,
                url,
                headers=headers,
                content=body,
            )
    except (httpx.TimeoutException, httpx.NetworkError, RuntimeError) as exc:
        _logger.warning(
            "backend unavailable (%s) — 502 BACKEND_UNAVAILABLE",
            type(exc).__name__,
        )
        record_event(
            request,
            decision="BLOCK",
            risk_score=None,
            detected_categories=None,
            reason=BACKEND_UNAVAILABLE,
            forwarded=False,
            response_status=502,
            db=db,
            user_id=getattr(user, "id", None),
            role=getattr(user, "role", None),
        )
        return SentinelFailClosed()

    try:
        payload = backend_response.json() or {}
    except ValueError:
        payload = {}
    # Keep the DLP/risk observability fields in the client response so demo
    # flows still show what the gateway saw; the backend's own payload takes
    # precedence for its business keys.
    dlp = getattr(request.state, "dlp_result", None)
    risk = getattr(request.state, "risk_result", None)
    observability = stage_response_extra(dlp, risk) if dlp is not None else {}
    merged = {**observability, **payload}
    merged["stage"] = "forwarded"

    response = JSONResponse(
        status_code=backend_response.status_code,
        content=merged,
    )

    # Audit the ALLOW after forwarding succeeded (audit always happens).
    record_event(
        request,
        decision="ALLOW",
        risk_score=getattr(risk, "final", None),
        detected_categories=dlp.categories() if dlp is not None else [],
        reason=None,
        response_status=backend_response.status_code,
        db=db,
        user_id=getattr(user, "id", None),
        role=getattr(user, "role", None),
        forwarded=True,
    )
    return response


def _sanitized_headers(request: Request) -> dict[str, str]:
    """Only allowlisted identity headers reach the backend."""
    user = getattr(request.state, "user", None)
    request_id = getattr(request.state, "request_id", None)

    headers: dict[str, str] = {}
    if request_id:
        headers["X-Request-ID"] = str(request_id)
    if user is not None:
        headers["X-User-Id"] = str(getattr(user, "id", ""))
        headers["X-User-Role"] = str(getattr(user, "role", ""))
    return headers
