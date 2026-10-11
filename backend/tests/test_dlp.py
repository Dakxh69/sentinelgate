"""DLP scanner tests (Day 4 R6, spec sections 34 DLP tests + 13–15).

Covers: each category's §13–14 case, the false-positive guards (context
keywords for phone/Aadhaar, Luhn for cards), the §15 public contract shape
and no-raw-values guarantee, dedupe, and the oversized/truncated flag.
"""

from __future__ import annotations

import pytest

from app.services.dlp_service import (
    MAX_SCAN_BYTES,
    DetectionMatch,
    DLPResult,
    scan,
    scan_request,
)


def categories(result: DLPResult) -> list[str]:
    return [match.type for match in result.matches]


# --------------------------------------------------------------- §14.1 EMAIL


def test_normal_text_has_no_detection():
    result = scan("Hello, please review the quarterly report by Friday.")
    assert result.detected is False
    assert result.matches == []
    assert result.unscanned is False


def test_email_detected():
    result = scan("contact me at person@example.com please")
    assert result.detected is True
    assert categories(result) == ["EMAIL"]


# --------------------------------------------------------------- §14.2 PHONE


def test_indian_phone_with_country_code():
    result = scan("call +91-9876543210 now")
    assert "PHONE" in categories(result)


def test_indian_phone_compact_country_code():
    result = scan("+919876543210")
    assert "PHONE" in categories(result)


def test_bare_ten_digit_without_context_not_reported():
    """§14.2 guard: arbitrary 10-digit numbers without keywords → nothing."""
    result = scan("order reference 9876543210 shipped")
    assert result.detected is False


def test_bare_ten_digit_with_context_reported_at_lower_confidence():
    result = scan("my mobile number is 9876543210")
    assert categories(result) == ["PHONE"]
    match = result.matches[0]
    assert match.confidence == pytest.approx(0.70)


# ------------------------------------------------------------- §14.3 AADHAAR


def test_aadhaar_with_context_keyword_high_confidence():
    result = scan("aadhaar 123456789012 verified")
    assert categories(result) == ["AADHAAR"]
    assert result.matches[0].confidence == pytest.approx(0.95)


def test_aadhaar_without_context_still_reported_as_heuristic():
    """§14.3 heuristic: bare 12-digit token still reported at 0.60."""
    result = scan("reference 123456789012 on file")
    assert categories(result) == ["AADHAAR"]
    assert result.matches[0].confidence == pytest.approx(0.60)


def test_eleven_or_thirteen_digits_not_aadhaar():
    assert categories(scan("12345678901")) == []          # 11 digits
    assert categories(scan("1234567890123")) == []        # 13 digits, no Luhn


# ----------------------------------------------------------- §14.4 CREDIT_CARD


def test_valid_luhn_card_detected():
    # 4111 1111 1111 1111 passes Luhn.
    result = scan("card: 4111 1111 1111 1111")
    assert categories(result) == ["CREDIT_CARD"]
    assert result.matches[0].confidence == pytest.approx(0.90)


def test_luhn_failure_not_reported():
    # Same digit count, fails Luhn → not reported (§14.4).
    result = scan("card: 4111 1111 1111 1112")
    assert "CREDIT_CARD" not in categories(result)


# ------------------------------------------------------------- §14.5 API_KEY


def test_api_key_detected():
    result = scan("api_key=sk-12345678abcdefghij")
    assert categories(result) == ["API_KEY"]
    assert result.matches[0].confidence == pytest.approx(0.95)


def test_token_detected_as_api_key():
    """Day 4 R2 mapping: token= → API_KEY."""
    result = scan("token=abcdef1234567890")
    assert "API_KEY" in categories(result)


def test_pem_private_key_is_secret():
    result = scan("-----BEGIN RSA PRIVATE KEY-----")
    assert categories(result) == ["SECRET"]
    assert result.matches[0].confidence == pytest.approx(0.98)


# ---------------------------------------------------- multi-category (§44.4)


def test_multi_category_body_detects_both():
    """Demo §44 step 4: Aadhaar + API key in one body → both detected."""
    body = "Aadhaar: 123456789012\nAPI_KEY: sk-live-abcdef123456"
    result = scan(body)
    assert set(categories(result)) == {"AADHAAR", "API_KEY"}
    assert result.detected is True


# --------------------------------------------------------------- dedupe R3


def test_overlapping_same_category_matches_deduped():
    """Overlapping hits of the same category keep the highest confidence."""
    result = DLPResult(
        detected=True,
        matches=[
            DetectionMatch(type="EMAIL", confidence=0.90, span=(0, 20)),
            DetectionMatch(type="EMAIL", confidence=0.50, span=(10, 15)),
        ],
    )
    public = result.to_public_dict()
    assert public["detected"] is True
    assert [m["confidence"] for m in public["matches"]] == [0.90]


def test_dedupe_in_scanner():
    """Two competing regexes on the same digits → one match, best confidence."""
    result = scan("+91-9876543210")
    phone_matches = [m for m in result.matches if m.type == "PHONE"]
    assert len(phone_matches) == 1


# ------------------------------------------------------- §15 result contract


def test_public_dict_shape_matches_spec_15():
    result = scan("aadhaar 123456789012 api_key=abcd12345678")
    public = result.to_public_dict()
    assert set(public.keys()) == {"detected", "matches"}
    for match in public["matches"]:
        assert set(match.keys()) == {"type", "confidence"}
        assert 0.0 <= match["confidence"] <= 1.0


def test_public_dict_never_contains_raw_values():
    """§15/§20: no raw secret value ever leaves the scanner."""
    secret = "sk-super-secret-value-99999"
    aadhaar = "123456789012"
    result = scan(f"aadhaar {aadhaar} password=hunter2secret api_key={secret}")
    rendered = str(result.to_public_dict())
    assert secret not in rendered
    assert aadhaar not in rendered
    assert "hunter2secret" not in rendered


# -------------------------------------------- oversized → unscanned (Day 4 R1)


def test_oversized_body_flagged_unscanned():
    oversized = "x" * (MAX_SCAN_BYTES + 1)
    result = scan(oversized)
    assert result.unscanned is True
    assert result.detected is True
    assert result.matches == []


def test_request_scan_combines_body_and_query():
    result = scan_request('{"note": "mail bob@example.com"}', query_string="q=phone+9876543210")
    assert set(categories(result)) == {"EMAIL", "PHONE"}


def test_scan_request_bytes_body():
    result = scan_request(b"pwd=OpenSesame99")
    assert "PASSWORD" in categories(result)
