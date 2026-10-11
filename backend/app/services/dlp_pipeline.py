"""Gateway pipeline stage: Sensitive data inspection and risk evaluation.

Orchestrates inspection across body and query string, feeds results to
risk scoring service, and populates results on request state.
Structured logging records category labels and calculated risk without raw values.
"""

from __future__ import annotations

import logging

from fastapi import Request

from app.services.dlp_service import DLPResult, scan_request
from app.services.risk_service import RiskResult, score_risk

_logger = logging.getLogger("sentinelgate")

UPLOAD_PATH = "/protected/upload"


def inspect_request(
    request: Request,
    body: str | bytes | None,
    *,
    external_upload: bool = False,
    db=None,
) -> tuple[DLPResult, RiskResult]:
    """Scan body + query, score risk, stash results on request.state.

    Returns (dlp_result, risk_result) for the route response. Suspicious
    behavior is read from the `security_events:{source_ip}` Redis counter
    (a failed read counts as 0 — see risk_service).
    """
    # C++ engine integration: when DLP_ENGINE_PATH is configured the
    # Aho-Corasick binary runs per region; any failure raises DLPEngineError
    # which the policy stage maps to a fail-closed 500. Unset → Python-only mode.
    from app.core.errors import SentinelGateError
    from app.services.dlp_service import DLPEngineError, engine_path

    try:
        dlp = scan_request(
            body,
            query_string=request.url.query,
            use_cpp_engine=engine_path() is not None,
        )
    except DLPEngineError as exc:
        # Fail closed at the scan boundary: a broken C++ engine must reject
        # the request. The 500 INTERNAL_SECURITY_ERROR response is emitted by
        # the app-wide handler; the audit row (DLP_ENGINE_FAILURE) is written
        # here because scanning precedes the policy stage.
        from app.services.audit_service import record_event

        record_event(
            request,
            decision="BLOCK",
            risk_score=1.0,
            detected_categories=[],
            reason="DLP_ENGINE_FAILURE",
            response_status=500,
            db=db,
        )
        raise SentinelGateError("Internal security error") from exc

    if external_upload or request.url.path == UPLOAD_PATH:
        upload_modifier = True
    else:
        upload_modifier = False

    from app.services.risk_service import is_suspicious_behavior

    from app.core.redis_client import create_redis_client

    try:
        redis_client = create_redis_client()
    except Exception:  # noqa: BLE001 - risk must never raise into the pipeline
        redis_client = None

    risk = score_risk(
        dlp.categories(),
        external_upload=upload_modifier,
        suspicious_behavior=is_suspicious_behavior(redis_client, getattr(request.state, "source_ip", None)),
    )

    request.state.dlp_result = dlp
    request.state.risk_result = risk

    if dlp.detected or dlp.unscanned:
        from app.core.logging import log_event

        log_event(
            _logger,
            "dlp detection",
            request_id=getattr(request.state, "request_id", None),
            categories=",".join(dlp.categories()) or None,
            unscanned=dlp.unscanned or None,
            risk=risk.final,
        )

    return dlp, risk


def stage_response_extra(dlp: DLPResult, risk: RiskResult) -> dict:
    """Build the public DLP + risk payload section appended to gateway responses."""
    extra = dlp.to_public_dict()
    extra["risk_score"] = round(risk.final, 2)
    return extra
