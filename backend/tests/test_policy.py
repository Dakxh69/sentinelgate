"""Day 5 policy tests (spec section 34 + day-05 R1/R2/R6).

Covers: CRUD validation + ADMIN gating, most-restrictive-wins with
conflicting rules, no-match fail closed, corrupt action → BLOCK, policy
engine error → INTERNAL_SECURITY_ERROR (never ALLOW), §19 scenarios A/B/C
through the HTTP pipeline, and complete audit rows for every decision.
"""

from __future__ import annotations

import pytest

from app.models import ADMIN, USER, Policy
from app.models import ALLOW, BLOCK, REVIEW
from app.services.policy_service import (
    PolicyEngineError,
    evaluate_policies,
    path_matches,
    rule_matches,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _register(client, username="alice", password="Sup3rSecret!x", role=None):
    response = client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, username="alice", password="Sup3rSecret!x"):
    response = client.post(
        "/auth/login", json={"email": f"{username}@example.com", "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _admin_headers(client, db_session):
    """Log in as the seeded admin (test env password), else create one."""
    from app.core.security import hash_password
    from app.models import User

    admin = db_session.query(User).filter_by(username="admin").one_or_none()
    if admin is None:
        admin = User(
            username="admin",
            email="admin@example.com",
            password_hash=hash_password("AdminPass!42"),
            role=ADMIN,
            is_active=True,
        )
        db_session.add(admin)
        db_session.commit()
    elif admin.email != "admin@example.com":
        # Seeded admin uses a different address — normalize it for login.
        admin.email = "admin@example.com"
        db_session.commit()
    try:
        return _login(client, "admin", "AdminPass!42")
    except AssertionError:
        # Seeded admin with a different password in this DB — reset it for
        # the test run (test DB only).
        admin.password_hash = hash_password("AdminPass!42")
        db_session.commit()
        return _login(client, "admin", "AdminPass!42")


def _seed_default_policies(db_session):
    """Load the Day 1 DEFAULT_POLICIES into the fresh test schema (§19
    scenarios run against the real policy set, not ad-hoc rules)."""
    from app.db.seed import DEFAULT_POLICIES

    if db_session.query(Policy).count() == 0:
        db_session.add_all([Policy(**spec) for spec in DEFAULT_POLICIES])
        db_session.commit()


def _make_rule(**overrides):
    """Policy rule with §18 defaults; most fields null = wildcard."""
    base = {
        "id": 1,
        "name": "rule",
        "role": None,
        "path_pattern": None,
        "http_method": None,
        "sensitive_required": None,
        "minimum_risk": None,
        "action": ALLOW,
        "enabled": True,
    }
    base.update(overrides)
    return Policy(**base)


# --------------------------------------------------------------------------- #
# Evaluation engine (unit)
# --------------------------------------------------------------------------- #


class TestRuleMatching:
    def test_wildcard_rule_matches_everything(self):
        rule = _make_rule()
        assert rule_matches(rule, role="USER", method="GET", path="/x", detected=False, risk=0.0)

    def test_role_method_path_constraints(self):
        rule = _make_rule(role="USER", http_method="POST", path_pattern="/protected/*")
        assert rule_matches(rule, role="USER", method="POST", path="/protected/upload", detected=False, risk=0.0)
        assert not rule_matches(rule, role="ADMIN", method="POST", path="/protected/upload", detected=False, risk=0.0)
        assert not rule_matches(rule, role="USER", method="GET", path="/protected/upload", detected=False, risk=0.0)

    def test_disabled_rule_never_matches(self):
        rule = _make_rule(enabled=False)
        assert not rule_matches(rule, role="USER", method="GET", path="/x", detected=False, risk=0.0)

    def test_minimum_risk_threshold_inclusive(self):
        rule = _make_rule(minimum_risk=0.5)
        assert rule_matches(rule, role="USER", method="GET", path="/x", detected=False, risk=0.5)
        assert not rule_matches(rule, role="USER", method="GET", path="/x", detected=False, risk=0.49)

    def test_sensitive_required_tracks_detection(self):
        rule = _make_rule(sensitive_required=True)
        assert rule_matches(rule, role="USER", method="GET", path="/x", detected=True, risk=0.9)
        assert not rule_matches(rule, role="USER", method="GET", path="/x", detected=False, risk=0.0)

    def test_unscanned_counts_as_sensitive(self):
        rule = _make_rule(sensitive_required=False)
        # Fail closed: truncated-and-flagged input must not match a clean rule.
        assert not rule_matches(rule, role="USER", method="GET", path="/x", detected=False, risk=0.0, unscanned=True)
        clean = _make_rule(sensitive_required=True)
        assert rule_matches(clean, role="USER", method="GET", path="/x", detected=False, risk=0.0, unscanned=True)

    def test_path_pattern_glob_and_prefix(self):
        assert path_matches("/protected/*", "/protected/upload")
        assert path_matches("/protected/*", "/protected")
        assert path_matches("/protected/*", "/protected/other/x")  # prefix covers nested
        assert not path_matches("/protected/*", "/protectedx")
        assert path_matches("/protected/data", "/protected/data")
        assert not path_matches("/protected/data", "/protected/datax")
        assert path_matches(None, "/anything")
        assert path_matches("/*", "/anything")


class TestConflictResolution:
    def test_most_restrictive_wins(self):
        rules = [
            _make_rule(id=1, name="allow-all", action=ALLOW),
            _make_rule(id=2, name="block-sensitive", sensitive_required=True, action=BLOCK),
        ]
        decision = evaluate_policies(
            rules, role="USER", method="POST", path="/p", detected=True, risk=0.9
        )
        assert decision.action == BLOCK
        assert decision.reason == "block-sensitive"

    def test_review_outranks_allow_block_outranks_review(self):
        rules = [
            _make_rule(id=1, name="allow", action=ALLOW),
            _make_rule(id=2, name="review", action=REVIEW),
        ]
        assert evaluate_policies(rules, role="U", method="GET", path="/p", detected=False, risk=0.0).action == REVIEW
        rules.append(_make_rule(id=3, name="block", action=BLOCK))
        assert evaluate_policies(rules, role="U", method="GET", path="/p", detected=False, risk=0.0).action == BLOCK

    def test_tie_break_specificity_then_lower_id(self):
        # Same action: the more constrained rule wins.
        rules = [
            _make_rule(id=1, name="loose", action=BLOCK, sensitive_required=True),
            _make_rule(id=2, name="tight", action=BLOCK, sensitive_required=True, minimum_risk=0.1),
        ]
        decision = evaluate_policies(rules, role="U", method="GET", path="/p", detected=True, risk=0.9)
        assert decision.reason == "tight"

        # Equal specificity: longer pattern wins.
        rules = [
            _make_rule(id=1, name="short", action=BLOCK, path_pattern="/p*"),
            _make_rule(id=2, name="long", action=BLOCK, path_pattern="/protected/*"),
        ]
        decision = evaluate_policies(rules, role="U", method="GET", path="/protected/upload", detected=False, risk=0.0)
        assert decision.reason == "long"

        # Everything equal: lower id wins (deterministic).
        rules = [
            _make_rule(id=7, name="a", action=REVIEW),
            _make_rule(id=3, name="b", action=REVIEW),
        ]
        decision = evaluate_policies(rules, role="U", method="GET", path="/p", detected=False, risk=0.0)
        assert decision.reason == "b"

    def test_corrupt_action_is_block_never_allow(self):
        rules = [_make_rule(id=1, name="corrupt", action="MAYBE")]
        decision = evaluate_policies(rules, role="U", method="GET", path="/p", detected=False, risk=0.0)
        assert decision.action == BLOCK

    def test_no_matching_policy_fail_closed_on_sensitive(self):
        rules = [_make_rule(id=1, name="clean-only", sensitive_required=False, action=ALLOW)]
        decision = evaluate_policies(rules, role="U", method="GET", path="/p", detected=True, risk=0.7)
        assert decision.action == BLOCK
        assert decision.reason == "NO_MATCHING_POLICY"

    def test_no_matching_policy_allows_clean(self):
        decision = evaluate_policies([], role="U", method="GET", path="/p", detected=False, risk=0.0)
        assert decision.action == ALLOW

    def test_evaluation_error_raises(self):
        # A rule whose fields break evaluation (non-comparable minimum_risk)
        # must surface as PolicyEngineError — fail closed, §35.7.
        bad = _make_rule(minimum_risk="not-a-number")
        with pytest.raises(PolicyEngineError):
            evaluate_policies([bad], role="U", method="GET", path="/p", detected=False, risk=0.0)


# --------------------------------------------------------------------------- #
# CRUD API (§11/§17/§21)
# --------------------------------------------------------------------------- #


class TestPolicyCrud:
    def test_admin_can_create(self, client, db_session):
        headers = _admin_headers(client, db_session)
        response = client.post(
            "/admin/policies",
            json={"name": "block-guest-data", "role": "GUEST", "path_pattern": "/protected/data", "action": "BLOCK"},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        assert response.json()["action"] == "BLOCK"
        assert response.json()["id"] is not None

    def test_validation_rejects_invalid(self, client, db_session):
        headers = _admin_headers(client, db_session)
        bad_payloads = [
            {"name": "x", "action": "MAYBE"},                       # bad action
            {"name": "x", "action": "BLOCK", "minimum_risk": 1.5},  # risk out of range
            {"name": "x", "action": "BLOCK", "path_pattern": "protected/*"},  # no leading /
            {"name": "", "action": "BLOCK"},                        # empty name
            {"name": "x", "action": "BLOCK", "enabled": "yes-please"},  # not bool
            {"name": "x", "action": "BLOCK", "role": "SUPERUSER"},  # unknown role
        ]
        for payload in bad_payloads:
            response = client.post("/admin/policies", json=payload, headers=headers)
            assert response.status_code == 422, (payload, response.text)
            assert response.json()["error"] == "INVALID_REQUEST"

    def test_non_admin_is_403(self, client, db_session):
        _register(client)
        headers = _login(client)
        response = client.post("/admin/policies", json={"name": "x", "action": "ALLOW"}, headers=headers)
        assert response.status_code == 403
        response = client.post("/admin/policies", json={"name": "x", "action": "ALLOW"})
        assert response.status_code == 401

    def test_update_and_delete(self, client, db_session):
        headers = _admin_headers(client, db_session)
        created = client.post(
            "/admin/policies", json={"name": "temp", "action": "REVIEW"}, headers=headers
        ).json()
        updated = client.put(
            f"/admin/policies/{created['id']}", json={"name": "temp2", "action": "BLOCK"}, headers=headers
        )
        assert updated.status_code == 200
        assert updated.json()["action"] == "BLOCK"
        deleted = client.delete(f"/admin/policies/{created['id']}", headers=headers)
        assert deleted.status_code == 204
        listing = client.get("/admin/policies", headers=headers).json()
        assert all(p["name"] != "temp" for p in listing["policies"])

    def test_update_delete_unknown_id_404(self, client, db_session):
        headers = _admin_headers(client, db_session)
        assert client.put("/admin/policies/99999", json={"name": "x", "action": "ALLOW"}, headers=headers).status_code == 404
        assert client.delete("/admin/policies/99999", headers=headers).status_code == 404


# --------------------------------------------------------------------------- #
# §19 scenarios through the HTTP pipeline
# --------------------------------------------------------------------------- #


class TestScenarios:
    def test_scenario_a_user_clean_get_allows(self, client, db_session, backend_url):
        """§19 A: USER, GET /protected/data, clean, risk 0 → ALLOW (200)."""
        _seed_default_policies(db_session)
        _register(client)
        headers = _login(client)
        response = client.get("/protected/data", headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["stage"] == "forwarded"
        assert response.json()["detected"] is False

    def test_scenario_b_user_upload_aadhaar_blocks_403(self, client, db_session):
        """§19 B: USER, POST upload, Aadhaar, risk 0.75+ → BLOCK 403 DLP_POLICY_BLOCK."""
        _seed_default_policies(db_session)
        _register(client)
        headers = _login(client)
        response = client.post(
            "/protected/upload",
            json={"note": "aadhaar 234123412345 for verification"},
            headers=headers,
        )
        assert response.status_code == 403, response.text
        assert response.json()["error"] == "DLP_POLICY_BLOCK"

    def test_scenario_c_admin_upload_card_reviews_202(self, client, db_session):
        """§19 C: ADMIN, POST upload, credit card, risk 0.85 → REVIEW 202."""
        _seed_default_policies(db_session)
        _admin_headers(client, db_session)  # ensure admin exists
        headers = _login(client, "admin", "AdminPass!42")
        response = client.post(
            "/protected/upload",
            json={"payment": "credit_card 4532015112830366 charged"},
            headers=headers,
        )
        assert response.status_code == 202, response.text
        assert response.json()["decision"] == "REVIEW"


# --------------------------------------------------------------------------- #
# Fail closed at the HTTP layer + audit completeness
# --------------------------------------------------------------------------- #


class TestFailClosedAndAudit:
    def test_policy_engine_error_is_500_never_allow(self, client, db_session, monkeypatch):
        """§35.7: evaluation crash → 500 INTERNAL_SECURITY_ERROR + audit."""
        _register(client)
        headers = _login(client)
        import app.services.policy_pipeline as pipeline

        def boom(*args, **kwargs):
            raise PolicyEngineError("simulated evaluation crash")

        monkeypatch.setattr(pipeline, "evaluate_policies", boom)
        response = client.get("/protected/data", headers=headers)
        assert response.status_code == 500
        assert response.json()["error"] == "INTERNAL_SECURITY_ERROR"

        from app.services.audit_service import query_events

        events, _ = query_events(db_session, limit=10)
        assert any(
            e.reason == "POLICY_ENGINE_ERROR" and e.decision == "BLOCK" and e.response_status == 500
            for e in events
        )

    def test_every_decision_writes_audit_event(self, client, db_session):
        """ALLOW/BLOCK/REVIEW each write a complete §20 audit row."""
        from app.services.audit_service import query_events

        _seed_default_policies(db_session)
        _register(client)
        user_headers = _login(client)

        client.get("/protected/data", headers=user_headers)  # ALLOW
        client.post(
            "/protected/upload",
            json={"note": "aadhaar 234123412345"},
            headers=user_headers,
        )  # BLOCK
        _admin_headers(client, db_session)
        client.post(
            "/protected/upload",
            json={"payment": "credit_card 4532015112830366"},
            headers={"Authorization": _login(client, "admin", "AdminPass!42")["Authorization"]},
        )  # REVIEW

        events, total = query_events(db_session, limit=50)
        assert total >= 3
        by_decision = {}
        for event in events:
            if event.path and event.path.startswith("/protected/"):
                by_decision.setdefault(event.decision, event)
        assert {"ALLOW", "BLOCK", "REVIEW"} <= set(by_decision)
        for decision, event in by_decision.items():
            assert event.reason
            assert event.request_id
            assert event.response_status == {"ALLOW": 200, "BLOCK": 403, "REVIEW": 202}[decision]
            assert event.path.startswith("/protected/")

    def test_audit_records_no_raw_values(self, client, db_session):
        """§2.5: the Aadhaar number itself never lands in the audit row."""
        from app.services.audit_service import query_events

        _register(client)
        headers = _login(client)
        secret = "234123412345"
        client.post("/protected/upload", json={"note": f"aadhaar {secret}"}, headers=headers)

        events, _ = query_events(db_session, limit=20)
        for event in events:
            serialized = str(event.detected_categories)
            assert secret not in serialized
