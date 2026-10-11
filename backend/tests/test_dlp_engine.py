"""Day 5 C++ engine integration tests (day-05 R3/R4, spec sections 23-26, 35.8).

Covers: CLI contract end-to-end, output validation, merge semantics, and the
fail-closed matrix (missing binary, non-zero exit, bad JSON, timeout) — a
failing engine must reject the request, never allow it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.dlp_service import (
    DLPEngineError,
    KNOWN_CATEGORIES,
    run_cpp_engine,
    scan_text_with_engine,
)

ENGINE = Path(__file__).resolve().parents[2] / "dlp-engine" / "build" / "dlp-engine"

ENGINE_REQUIRED = pytest.mark.skipif(
    not ENGINE.exists(), reason="dlp-engine binary not built (run cmake build)"
)


# --------------------------------------------------------------------------- #
# CLI contract (R3, section 26)
# --------------------------------------------------------------------------- #


@ENGINE_REQUIRED
class TestCliContract:
    def test_spec_example_api_key(self):
        result = subprocess.run(
            [str(ENGINE), "--scan"],
            input="api_key=secret123",
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload == {"detected": True, "matches": ["API_KEY"]}

    def test_multi_match_sorted(self):
        result = subprocess.run(
            [str(ENGINE), "--scan"],
            input="password=x api_key=y",
            capture_output=True,
            text=True,
            timeout=5,
        )
        payload = json.loads(result.stdout)
        assert payload["detected"] is True
        assert payload["matches"] == sorted(payload["matches"])
        assert "API_KEY" in payload["matches"]
        assert "PASSWORD" in payload["matches"]

    def test_clean_and_empty_input(self):
        for text in ("nothing to see here", ""):
            result = subprocess.run(
                [str(ENGINE), "--scan"], input=text, capture_output=True, text=True, timeout=5
            )
            assert result.returncode == 0
            assert json.loads(result.stdout) == {"detected": False, "matches": []}

    def test_case_insensitive(self):
        result = subprocess.run(
            [str(ENGINE), "--scan"],
            input="My Secret Value and APIKEY here",
            capture_output=True,
            text=True,
            timeout=5,
        )
        matches = json.loads(result.stdout)["matches"]
        assert matches == ["API_KEY", "SECRET"]

    def test_bad_args_nonzero_exit(self):
        result = subprocess.run([str(ENGINE)], capture_output=True, text=True, timeout=5)
        assert result.returncode != 0


# --------------------------------------------------------------------------- #
# run_cpp_engine validation (R4, section 26)
# --------------------------------------------------------------------------- #


class TestRunCppEngineValidation:
    def test_real_binary_valid_output(self):
        categories = run_cpp_engine(str(ENGINE), "password=hunter2")
        assert categories == ["PASSWORD"]

    def test_missing_binary_raises(self):
        with pytest.raises(DLPEngineError):
            run_cpp_engine("/nonexistent/dlp-engine", "hello")

    def test_nonzero_exit_raises(self):
        # /bin/false exits 1 with empty stdout — every failure mode rejected.
        with pytest.raises(DLPEngineError):
            run_cpp_engine("/bin/false", "hello")

    def test_bad_json_raises(self):
        # /bin/echo prints its args — not the contracted JSON line.
        with pytest.raises(DLPEngineError):
            run_cpp_engine("/bin/echo", "hello")

    def test_wrong_types_raise(self, tmp_path):
        # exit 0 + valid JSON, but wrong shape (detected not bool).
        fake = tmp_path / "fake-engine"
        fake.write_text('#!/bin/sh\nprintf \'{"detected": "yes", "matches": []}\'\n')
        fake.chmod(0o755)
        with pytest.raises(DLPEngineError):
            run_cpp_engine(str(fake), "hello")

    def test_unknown_category_raises(self, tmp_path):
        fake = tmp_path / "fake-engine"
        fake.write_text('#!/bin/sh\nprintf \'{"detected": true, "matches": ["TOP_SECRET_CAT"]}\'\n')
        fake.chmod(0o755)
        with pytest.raises(DLPEngineError):
            run_cpp_engine(str(fake), "hello")

    def test_timeout_raises(self, tmp_path):
        fake = tmp_path / "hanging-engine"
        fake.write_text("#!/bin/sh\nsleep 30\n")
        fake.chmod(0o755)
        with pytest.raises(DLPEngineError):
            run_cpp_engine(str(fake), "hello")

    def test_known_categories_complete(self):
        assert KNOWN_CATEGORIES == {
            "EMAIL", "PHONE", "AADHAAR", "CREDIT_CARD", "API_KEY", "PASSWORD", "SECRET",
        }


# --------------------------------------------------------------------------- #
# scan_text_with_engine merge semantics (R4)
# --------------------------------------------------------------------------- #


class TestMergeSemantics:
    def test_python_only_mode_when_unset(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.get_settings(), "DLP_ENGINE_PATH", None)
        result = scan_text_with_engine("email user@example.com please")
        assert [m.type for m in result.matches] == ["EMAIL"]

    def test_engine_path_missing_fails_closed(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.get_settings(), "DLP_ENGINE_PATH", "/nonexistent/engine")
        with pytest.raises(DLPEngineError):
            scan_text_with_engine("anything at all")

    def test_merge_python_values_and_engine_keywords(self, monkeypatch):
        """Python value detectors + C++ keyword signals merge per category."""
        from app.core import config

        monkeypatch.setattr(config.get_settings(), "DLP_ENGINE_PATH", str(ENGINE))
        text = "contact me at user@example.com with the api_key value"
        result = scan_text_with_engine(text)
        categories = {m.type for m in result.matches}
        # Python regex finds EMAIL (value); the engine flags API_KEY + SECRET
        # (keyword context: "api_key" standalone, "key"... only API_KEY is a
        # whole-word keyword here — "api_key value" has it delimited).
        assert "EMAIL" in categories
        assert "API_KEY" in categories
        # Python value detectors outrank engine keyword signals.
        confidences = {m.type: m.confidence for m in result.matches}
        assert confidences["EMAIL"] == 0.90
        assert confidences["API_KEY"] >= 0.5

    def test_engine_finding_alone_still_counts(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.get_settings(), "DLP_ENGINE_PATH", str(ENGINE))
        result = scan_text_with_engine("the password field is required")
        categories = {m.type for m in result.matches}
        assert "PASSWORD" in categories
        assert result.detected


# --------------------------------------------------------------------------- #
# Fail closed at the HTTP layer (R4, section 35.8)
# --------------------------------------------------------------------------- #


def _register_and_login(client, username="bob"):
    response = client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": "Sup3rSecret!x"},
    )
    assert response.status_code == 201, response.text
    response = client.post(
        "/auth/login", json={"email": f"{username}@example.com", "password": "Sup3rSecret!x"}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class TestHttpFailClosed:
    def test_engine_failure_rejects_request_never_allows(self, client, db_session, monkeypatch):
        """DLP_ENGINE_PATH set but binary broken → 500 + audit DLP_ENGINE_FAILURE."""
        from app.core import config
        from app.services.audit_service import query_events

        headers = _register_and_login(client, "bob")
        monkeypatch.setattr(
            config.get_settings(), "DLP_ENGINE_PATH", "/nonexistent/dlp-engine"
        )
        response = client.get("/protected/data", headers=headers)
        assert response.status_code == 500
        assert response.json()["error"] == "INTERNAL_SECURITY_ERROR"

        events, _ = query_events(db_session, limit=10)
        assert any(
            e.reason == "DLP_ENGINE_FAILURE" and e.decision == "BLOCK"
            for e in events
        )
