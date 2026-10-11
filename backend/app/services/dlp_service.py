"""Data Loss Prevention (DLP) inspection engine.

Detects sensitive information across seven core categories:
  - CREDIT_CARD (Luhn checksum verified)
  - AADHAAR (Verhoeff checksum verified)
  - API_KEY & SECRET
  - PASSWORD
  - EMAIL
  - PHONE

Scan Targets: Request body and query string parameters.
Authorization header is excluded by design as it contains standard bearer tokens.
Oversized payloads (> 1 MiB) are flagged as unscanned and fail closed.
Raw values are never exposed or written to logs.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

MAX_SCAN_BYTES = 1024 * 1024  # 1 MiB — payloads larger than this are flagged as unscanned

# Bare 10-digit / Aadhaar numbers count as sensitive only within this window
# (in characters) of a context keyword (avoids treating every arbitrary
# 10-digit number as sensitive without contextual evidence).
CONTEXT_WINDOW_CHARS = 40

PHONE_CONTEXT_KEYWORDS = ("phone", "mobile", "contact", "call", "whatsapp")
AADHAAR_CONTEXT_KEYWORDS = ("aadhaar", "uid", "uidai")

# A "token:" or "secret:"-style key must have at least this many value chars
# before it counts (value must be ≥ 8 chars to reduce false positives).
MIN_SECRET_VALUE_LENGTH = 8

# C++ subprocess integration: hard timeout so a hung engine can never
# wedge a request; the rejection path is fail closed.
DLP_ENGINE_TIMEOUT_SECONDS = 2

# Categories the C++ keyword engine may legitimately report.
# Python-side validation rejects any other value.
KNOWN_CATEGORIES = frozenset(
    {"EMAIL", "PHONE", "AADHAAR", "CREDIT_CARD", "API_KEY", "PASSWORD", "SECRET"}
)


class DLPEngineError(Exception):
    """C++ DLP engine failure: missing binary, non-zero exit, timeout, or
    malformed output. The request is rejected — never allowed."""


@dataclass(frozen=True)
class PatternDef:
    """One detection rule in the pattern registry.

    Exactly one of `regex` / `validator` is set:

    - `regex` — compiled pattern. When `context_keywords` is non-empty the
      hit counts only if a keyword is within CONTEXT_WINDOW_CHARS of the
      match span; otherwise `fallback_confidence` applies (Aadhaar uses
      0.60 heuristic without context; bare phone digits use 0.0 to suppress).
    - `validator` — callable(text) → confidence | None per hit generator.
      Used for rules requiring multi-pass logic (e.g. Luhn-checked cards).
    """

    category: str
    confidence: float
    regex: re.Pattern[str] | None = None
    validator: Callable[[str], tuple[float, list[tuple[int, int]]]] | None = None
    context_keywords: tuple[str, ...] = ()
    fallback_confidence: float | None = None


def _luhn_valid(digits: str) -> bool:
    """Luhn checksum — required for CREDIT_CARD detection, not optional."""
    total, parity = 0, False
    for char in reversed(digits):
        digit = ord(char) - 48
        if parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        parity = not parity
    return total % 10 == 0


def _context_hit(text: str, start: int, end: int, keywords: tuple[str, ...]) -> bool:
    """True when a keyword occurs within ±CONTEXT_WINDOW_CHARS of the span."""
    window = text[max(0, start - CONTEXT_WINDOW_CHARS): min(len(text), end + CONTEXT_WINDOW_CHARS)]
    return any(keyword in window.lower() for keyword in keywords)


# --------------------------------------------------------------------------- #
# Validator-styleatch generators (multi-hit rules)
# --------------------------------------------------------------------------- #


def _credit_card_hits(text: str) -> tuple[float, list[tuple[int, int]]]:
    """Detect 13–19-digit sequences that pass Luhn check (0.90 confidence).
    Luhn failures are not reported.
    """
    spans: list[tuple[int, int]] = []
    for match in re.finditer(r"\b(?:\d[ -]?){12,18}\d\b", text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            spans.append((match.start(), match.end()))
    return (0.90 if spans else 0.0), spans


# --------------------------------------------------------------------------- #
# Pattern registry — extending the scanner = appending a PatternDef entry.
# --------------------------------------------------------------------------- #

PATTERNS: list[PatternDef] = [
    # Pragmatic email regex.
    PatternDef(
        category="EMAIL",
        confidence=0.90,
        regex=re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ),
    # Explicit +91 international prefix: 0.85 confidence regardless of context.
    PatternDef(
        category="PHONE",
        confidence=0.85,
        regex=re.compile(r"\+91-?\d{10}\b"),
    ),
    # Bare 10-digit starting 6–9: only with nearby context keywords (0.70);
    # contextless → suppressed entirely (false-positive guard).
    PatternDef(
        category="PHONE",
        confidence=0.70,
        regex=re.compile(r"\b[6-9]\d{9}\b"),
        context_keywords=PHONE_CONTEXT_KEYWORDS,
        fallback_confidence=0.0,
    ),
    # Aadhaar 12-digit token, heuristic: 0.95 with context keyword
    # (aadhaar/uid/uidai), still reported at 0.60 without (keeps the
    # scanner useful on unstructured text).
    PatternDef(
        category="AADHAAR",
        confidence=0.95,
        regex=re.compile(r"\b\d{12}\b"),
        context_keywords=AADHAAR_CONTEXT_KEYWORDS,
        fallback_confidence=0.60,
    ),
    # Credit card via Luhn-checked validator (Luhn failures not reported).
    # Validator form because candidate regex + checksum need two passes.
    PatternDef(
        category="CREDIT_CARD",
        confidence=0.90,
        validator=_credit_card_hits,
    ),
    # api_key=/apikey=/api-key=/x-api-key:/token= with value ≥ 8 chars,
    # plus the JSON `"api_key": "..."` form.
    PatternDef(
        category="API_KEY",
        confidence=0.95,
        regex=re.compile(
            r"(?i)\b(?:api[_-]?key|token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{"
            + str(MIN_SECRET_VALUE_LENGTH)
            + ",})"
        ),
    ),
    # password=/passwd=/pwd= and the JSON `"password": "..."` form.
    PatternDef(
        category="PASSWORD",
        confidence=0.95,
        regex=re.compile(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"'&,;]+)"
        ),
    ),
    # secret=/client_secret=/private_key=/private-key= and PEM private-key blocks.
    PatternDef(
        category="SECRET",
        confidence=0.98,
        regex=re.compile(
            r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r"|\b(?:client[_-]?secret|private[_-]?key)\s*[:=]\s*[\"']?(\S+)"
            r"|\bsecret\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]+)"
        ),
    ),
]


def registry() -> list[PatternDef]:
    """Snapshot of the pattern registry (for tests / explainability)."""
    return list(PATTERNS)


# --------------------------------------------------------------------------- #
# C++ Aho-Corasick Engine Integration
# --------------------------------------------------------------------------- #


def engine_path() -> str | None:
    """Configured C++ engine binary path, or None for built-in Python scanner mode."""
    from app.core.config import get_settings

    return get_settings().DLP_ENGINE_PATH or None


def run_cpp_engine(engine: str, text: str) -> list[str]:
    """Run the C++ CLI and return validated category names.

    Contract: one JSON line `{"detected": bool, "matches": [category, ...]}`
    on stdout, exit 0. Any deviation — missing binary, non-zero exit,
    timeout, bad JSON, unknown category, wrong types — raises
    DLPEngineError (fail closed). Never silently allows.
    """
    try:
        completed = subprocess.run(
            [engine, "--scan"],
            input=text,
            capture_output=True,
            text=True,
            timeout=DLP_ENGINE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise DLPEngineError(f"DLP engine binary not found: {engine}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DLPEngineError("DLP engine timed out") from exc
    except OSError as exc:
        raise DLPEngineError(f"DLP engine failed to run: {type(exc).__name__}") from exc

    if completed.returncode != 0:
        raise DLPEngineError(f"DLP engine exited {completed.returncode}")

    try:
        payload = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, ValueError) as exc:
        raise DLPEngineError("DLP engine produced malformed JSON") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("detected"), bool):
        raise DLPEngineError("DLP engine output missing boolean 'detected'")
    matches = payload.get("matches")
    if not isinstance(matches, list) or any(
        not isinstance(item, str) for item in matches
    ):
        raise DLPEngineError("DLP engine output has invalid 'matches'")
    unknown = [item for item in matches if item not in KNOWN_CATEGORIES]
    if unknown:
        raise DLPEngineError(f"DLP engine reported unknown categories: {unknown}")
    if payload["detected"] != bool(matches):
        raise DLPEngineError("DLP engine 'detected' contradicts 'matches'")
    return sorted(set(matches))


def scan_text_with_engine(text: str) -> DLPResult:
    """scan() with the C++ engine layered in when configured.

    C++ contributes keyword-category signals; Python contributes value
    detectors (EMAIL, PHONE, CARD). Merge keeps the highest confidence per
    category. Any engine failure raises DLPEngineError → the request is
    rejected with INTERNAL_SECURITY_ERROR (fail closed).
    """
    configured = engine_path()
    if not configured:
        return scan(text)

    # Empty text still exercises the engine contract: a configured-but-broken
    # engine must fail closed even when there is nothing to scan —
    # "nothing to inspect" is not evidence the engine works.
    if text == "":
        run_cpp_engine(configured, text)
        return DLPResult(detected=False)

    base = scan(text)
    # The oversized case never goes to the subprocess — unscanned input
    # stays flagged instead of being partially scanned.
    if base.unscanned:
        return base

    # Truncate defensively for the subprocess too: the engine must never
    # receive more than MAX_SCAN_BYTES (the flagging contract stays intact).
    engine_text = text.encode("utf-8", errors="replace")[:MAX_SCAN_BYTES].decode(
        "utf-8", errors="replace"
    )
    engine_categories = run_cpp_engine(configured, engine_text)

    matches = list(base.matches)
    for category in engine_categories:
        if base.confidence_for(category) <= 0.0:
            # Keyword-only signal: label it with the C++ engine's identity
            # (0.5) so Python value detectors always outrank it on merge.
            matches.append(
                DetectionMatch(type=category, confidence=0.5, span=(0, 0))
            )
    kept = _dedupe(matches)
    return DLPResult(detected=bool(kept), matches=kept)


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


@dataclass
class DetectionMatch:
    type: str
    confidence: float
    # Internal span for dedupe — never serialized publicly.
    span: tuple[int, int] = (0, 0)

    def to_public_dict(self) -> dict:
        return {"type": self.type, "confidence": round(self.confidence, 2)}


@dataclass
class DLPResult:
    detected: bool
    matches: list[DetectionMatch] = field(default_factory=list)
    unscanned: bool = False

    def categories(self) -> list[str]:
        """Unique category names, detection order (only names ever leave)."""
        seen: list[str] = []
        for match in self.matches:
            if match.type not in seen:
                seen.append(match.type)
        return seen

    def confidence_for(self, category: str) -> float:
        """Highest confidence reported for a category (0.0 when absent)."""
        return max(
            (m.confidence for m in self.matches if m.type == category),
            default=0.0,
        )

    def to_public_dict(self) -> dict:
        """Public DLP result shape — no raw values, no spans."""
        return {
            "detected": self.detected,
            "matches": [
                match.to_public_dict() for match in _dedupe(self.matches)
            ],
        }


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


def _dedupe(matches: list[DetectionMatch]) -> list[DetectionMatch]:
    """Drop overlapping same-category matches, keeping highest confidence.

    Different categories overlapping the same span are both kept
    (multi-category text stays fully visible).
    """
    ordered = sorted(matches, key=lambda m: (-m.confidence, m.span[0]))
    kept: list[DetectionMatch] = []
    for match in ordered:
        overlapping = any(
            other.type == match.type
            and match.span[0] < other.span[1]
            and match.span[1] > other.span[0]
            for other in kept
        )
        if not overlapping:
            kept.append(match)
    kept.sort(key=lambda m: (m.span[0], m.type))
    return kept


def scan(text: str | None) -> DLPResult:
    """Scan one region (body text or query string). Deterministic."""
    if text is None:
        return DLPResult(detected=False)
    if len(text.encode("utf-8", errors="replace")) > MAX_SCAN_BYTES:
        # Oversized body: flagged as unscanned so the policy layer can fail closed.
        return DLPResult(detected=True, matches=[], unscanned=True)

    matches: list[DetectionMatch] = []
    for pattern in PATTERNS:
        if pattern.validator is not None:
            confidence, spans = pattern.validator(text)
            if confidence > 0.0:
                matches.extend(
                    DetectionMatch(
                        type=pattern.category,
                        confidence=confidence,
                        span=span,
                    )
                    for span in spans
                )
            continue

        regex = pattern.regex
        assert regex is not None  # registry invariant: regex or validator
        for match in regex.finditer(text):
            confidence = float(pattern.confidence)
            if pattern.context_keywords and not _context_hit(
                text, match.start(), match.end(), pattern.context_keywords
            ):
                confidence = float(
                    pattern.fallback_confidence
                    if pattern.fallback_confidence is not None
                    else pattern.confidence
                )
            if confidence <= 0.0:
                continue  # suppressed (e.g. contextless 10-digit phone)
            matches.append(
                DetectionMatch(
                    type=pattern.category,
                    confidence=confidence,
                    span=(match.start(), match.end()),
                )
            )

    kept = _dedupe(matches)
    return DLPResult(detected=bool(kept), matches=kept)


def scan_request(
    body: str | bytes | None,
    query_string: str | None = None,
    *,
    use_cpp_engine: bool = False,
) -> DLPResult:
    """Scan request body (text/JSON stringified/form) + query string.

    Authorization header is never passed in (module docstring). Any single
    unscannable region flags the whole result `unscanned: true` so the
    policy layer can fail closed. Overlapping hits across regions are deduped
    per region — the scanner never pretends a region was inspected when it
    was not.

    With `use_cpp_engine=True` and DLP_ENGINE_PATH configured, the C++
    Aho-Corasick keyword engine runs on each region; any engine failure
    raises DLPEngineError — the caller must reject, never allow.
    """
    regions: list[str] = []
    empty_request = body is None and not query_string
    if body is not None:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        if body:
            regions.append(body)
    if query_string:
        regions.append(query_string)
    if not regions and use_cpp_engine:
        # A configured engine is verified even on an empty request: run it
        # once on the empty string so a broken binary fails closed here
        # instead of silently skipping inspection.
        scan_text_with_engine("")
        return DLPResult(detected=False)

    matches: list[DetectionMatch] = []
    unscanned = False
    offset = 0  # region-relative spans shifted into a global frame so
    # cross-region overlap checks in _dedupe cannot collide by accident.
    for region in regions:
        result = scan_text_with_engine(region) if use_cpp_engine else scan(region)
        if result.unscanned:
            unscanned = True
        for match in result.matches:
            matches.append(
                DetectionMatch(
                    type=match.type,
                    confidence=match.confidence,
                    span=(match.span[0] + offset, match.span[1] + offset),
                )
            )
        offset += len(region) + 1  # +1: regions never share a boundary char

    kept = _dedupe(matches)
    return DLPResult(
        detected=unscanned or bool(kept),
        matches=kept,
        unscanned=unscanned,
    )
