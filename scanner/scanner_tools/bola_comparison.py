"""Response comparison helpers for cross-user BOLA / IDOR detection.

The dual-user BOLA test fetches the same resource ID as two different users
and decides whether user2 saw user1's data. Two failure modes the naive
``user1_body == user2_body`` check has:

  1. False negatives: real responses embed per-request volatile fields (CSRF
     tokens, server timestamps, request IDs, ETags, nonces). Two requests for
     the *same* resource therefore differ byte-for-byte even under a genuine
     BOLA, so exact equality never fires.

  2. False positives / noise: substring checks like ``"email" in body`` match
     navigation chrome ("Profile", "Account"), HTML ``<meta>`` tags, and JSON
     error envelopes ("invalid email"). They do not indicate the response
     actually carries a user's data.

This module normalizes volatile fields before comparison and detects
user-specific data by looking at concrete PII-shaped *values* rather than
field-name substrings.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

# Max chars compared. Comparison cost is O(n^2) for SequenceMatcher in the
# worst case; cap so a large HTML body can't stall the scan.
_MAX_COMPARE_CHARS = 8000

# Volatile token patterns replaced with a constant before comparison so two
# requests for the same resource normalize to the same text under BOLA.
_VOLATILE_PATTERNS = [
    # ISO-8601 timestamps: 2026-05-29T12:34:56(.789)(Z|+00:00)
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    # Epoch-ish long integers (>= 10 digits): timestamps, request ids
    re.compile(r"\b\d{10,}\b"),
    # UUIDs (request ids, trace ids, nonces)
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    # CSRF / nonce / token / request-id values in JSON or attributes.
    # Matches "key": "value" or key="value" for known volatile key names.
    re.compile(
        r"(?i)(csrf[\w-]*|xsrf[\w-]*|nonce|request[\s_-]?id|trace[\s_-]?id|"
        r"etag|_token|authenticity_token|session[\s_-]?id)"
        r"(\"?\s*[:=]\s*\"?)[^\"',}\s<>]+"
    ),
    # Long hex/base64-ish blobs (>= 24 chars) — opaque tokens
    re.compile(r"\b[A-Za-z0-9_-]{24,}\b"),
]

_VOLATILE_REPLACEMENT = "\x00V\x00"

# Email address — strong "this is a specific user's data" signal.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# JSON-style identity field carrying a non-empty, non-boilerplate value:
#   "email": "a@b.com"  /  "username": "alice"  /  "ssn": "..."  /  "phone": "..."
_IDENTITY_VALUE_RE = re.compile(
    r"(?i)\"(user_?name|user_?id|email|full_?name|first_?name|last_?name|"
    r"phone|ssn|address|account_?(?:id|number)|api_?key|token|balance|"
    r"date_?of_?birth|dob)\"\s*:\s*\"?([^\"\n,}\]]+)",
)

# Values that, despite matching an identity key, are boilerplate / empty and
# should not count as real user data.
_BOILERPLATE_VALUES = {
    "", "null", "none", "n/a", "na", "unknown", "undefined", "true", "false",
    "0", "-", "example", "test", "string", "{}", "[]",
}

# Substrings marking placeholder / non-user addresses and values.
_PLACEHOLDER_VALUE_MARKERS = (
    "example.com", "example.org", "@test", "noreply", "no-reply",
)


def _is_placeholder_value(value: str) -> bool:
    """True for empty/boilerplate values or placeholder addresses."""
    lowered = value.strip().lower()
    if lowered in _BOILERPLATE_VALUES:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_VALUE_MARKERS)


def normalize_response_body(body: str) -> str:
    """Collapse whitespace and mask volatile tokens for stable comparison."""
    if not body:
        return ""
    text = body[: _MAX_COMPARE_CHARS * 2]
    for pattern in _VOLATILE_PATTERNS:
        text = pattern.sub(_VOLATILE_REPLACEMENT, text)
    # Collapse whitespace last so masked tokens don't leave odd spacing.
    text = " ".join(text.split())
    return text[:_MAX_COMPARE_CHARS]


def response_similarity(body_a: str, body_b: str) -> float:
    """Return a 0.0-1.0 similarity ratio of two bodies after normalization.

    1.0 means the responses are identical once volatile fields are masked.
    """
    norm_a = normalize_response_body(body_a)
    norm_b = normalize_response_body(body_b)
    if not norm_a and not norm_b:
        return 1.0
    if not norm_a or not norm_b:
        return 0.0
    if norm_a == norm_b:
        return 1.0
    return SequenceMatcher(None, norm_a, norm_b, autojunk=False).ratio()


def responses_equivalent(body_a: str, body_b: str, threshold: float = 0.95) -> bool:
    """True when two responses are equivalent ignoring volatile per-request fields.

    A genuine BOLA where user2 reads user1's resource produces near-identical
    bodies (same data, different request-time tokens), which exact equality
    would miss but this catches.
    """
    return response_similarity(body_a, body_b) >= threshold


def all_responses_equivalent(bodies: list[str], threshold: float = 0.95) -> bool:
    """True when every body is equivalent to the first (volatile-tolerant).

    Replaces ``len(set(bodies)) == 1`` for multi-user BOLA so per-request
    volatile fields don't make genuinely-equivalent responses look distinct.
    """
    if len(bodies) < 2:
        return True
    first = bodies[0]
    return all(responses_equivalent(first, other, threshold) for other in bodies[1:])


def extract_user_specific_signals(body: str) -> list[str]:
    """Return concrete user-specific data signals found in a response body.

    Looks for PII-shaped *values* (email addresses, populated identity fields)
    rather than field-name substrings, so navigation chrome and error
    envelopes don't register as "user data".
    """
    if not body:
        return []
    signals: list[str] = []

    # Distinct email addresses are a strong identity signal.
    emails = set(_EMAIL_RE.findall(body[: _MAX_COMPARE_CHARS * 2]))
    # Drop obvious placeholder/support addresses.
    emails = {e for e in emails if not _is_placeholder_value(e)}
    for email in list(emails)[:5]:
        signals.append(f"email:{email}")

    # Populated identity fields in JSON.
    for match in _IDENTITY_VALUE_RE.finditer(body[: _MAX_COMPARE_CHARS * 2]):
        key = match.group(1).lower().replace("_", "")
        value = match.group(2).strip().strip('"').strip()
        if _is_placeholder_value(value):
            continue
        if len(value) < 2:
            continue
        signals.append(f"field:{key}")
        if len(signals) >= 12:
            break

    # De-duplicate, preserve order.
    seen: set[str] = set()
    unique: list[str] = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def carries_user_specific_data(body: str) -> bool:
    """Convenience predicate: does the body carry concrete user-specific data?"""
    return bool(extract_user_specific_signals(body))
