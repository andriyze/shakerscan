#!/usr/bin/env python3
"""
Shared retest queue contract and policy helpers.

This module is imported by both API and worker processes to keep retest
payload semantics, type normalization, and retry classification consistent.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

RETEST_QUEUE_SCHEMA_VERSION = 1

SUPPORTED_RETEST_TYPES: tuple[str, ...] = (
    "xss",
    "sqli",
    "ssrf",
    "path_traversal",
    "open_redirect",
    "cors",
)

SUPPORTED_RETEST_VERDICTS: tuple[str, ...] = (
    "exploited",
    "blocked_by_security",
    "out_of_scope_internal",
    "false_positive",
    "likely_fixed",
    "inconclusive",
    "error",
)

RETEST_TYPE_ALIASES: dict[str, str] = {
    "xss": "xss",
    "cross-site-scripting": "xss",
    "cross_site_scripting": "xss",
    "sqli": "sqli",
    "sql-injection": "sqli",
    "sql_injection": "sqli",
    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",
    "server_side_request_forgery": "ssrf",
    "path_traversal": "path_traversal",
    "path-traversal": "path_traversal",
    "lfi": "path_traversal",
    "local-file-inclusion": "path_traversal",
    "open_redirect": "open_redirect",
    "open-redirect": "open_redirect",
    "url_redirect": "open_redirect",
    "url-redirect": "open_redirect",
    "cors": "cors",
    "cors_misconfiguration": "cors",
}

DEFAULT_REPLAY_PAYLOADS: dict[str, str] = {
    "xss": "<script>alert(1)</script>",
    "sqli": "' OR '1'='1",
    "ssrf": "http://127.0.0.1:80/",
    "path_traversal": "../../../etc/passwd",
    "open_redirect": "https://example.org/",
    "cors": "https://evil.example.org",
}

# Ladder names intentionally use stable identifiers so UI/reporting can
# consistently aggregate attempt strategy analytics across versions.
ATTEMPT_LADDERS: dict[str, list[str]] = {
    "xss": ["headless_dom_execution", "reflection_context", "alternate_payloads"],
    "sqli": ["dbms_extraction", "boolean_diff", "timing_fallback"],
    "ssrf": ["oob_callback", "internal_resource_access"],
    "path_traversal": ["direct_traversal", "encoding_bypass"],
    "open_redirect": ["query_redirect_param", "post_redirect_param", "location_header_check"],
    "cors": ["origin_reflection_probe", "wildcard_credentials_probe"],
}

RETRY_CLASS_PATTERNS: dict[str, tuple[str, ...]] = {
    "rate_limited": ("429", "too many requests", "rate limit"),
    "auth": ("401", "403", "unauthorized", "forbidden", "authentication"),
    "validation": ("invalid", "missing", "malformed", "unsupported"),
    "config": ("module unavailable", "no such file", "not installed", "dependency"),
    "transient": ("timeout", "timed out", "connection reset", "connection refused", "service unavailable"),
}

RETRYABLE_CLASSES: set[str] = {"rate_limited", "transient"}


def normalize_retest_type(value: str | None) -> str | None:
    if not value:
        return None
    return RETEST_TYPE_ALIASES.get(str(value).strip().lower())


def get_attempt_ladder(finding_type: str | None) -> list[str]:
    normalized = normalize_retest_type(finding_type)
    if not normalized:
        return []
    return list(ATTEMPT_LADDERS.get(normalized, []))


def classify_retry(message: str | None) -> tuple[str, bool]:
    raw = str(message or "").strip().lower()
    if not raw:
        return "none", False

    for retry_class, patterns in RETRY_CLASS_PATTERNS.items():
        if any(p in raw for p in patterns):
            return retry_class, retry_class in RETRYABLE_CLASSES
    return "internal", False


def build_retest_job_payload(
    *,
    job_id: str,
    verification_id: str,
    finding_id: str,
    submitted_at: str,
    trigger: str | None = None,
    attempt: int = 1,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "finding_retest",
        "queue_schema_version": RETEST_QUEUE_SCHEMA_VERSION,
        "job_id": str(job_id),
        "verification_id": str(verification_id),
        "finding_id": str(finding_id),
        "submitted_at": str(submitted_at),
        "attempt": max(1, int(attempt)),
    }
    if trigger:
        payload["trigger"] = str(trigger)
    return payload


def validate_retest_job_payload(payload: Any) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "payload_not_object"

    if payload.get("type") != "finding_retest":
        return False, "invalid_type"

    schema_version = payload.get("queue_schema_version")
    try:
        schema_version_int = int(schema_version)
    except (TypeError, ValueError):
        return False, "invalid_queue_schema_version"
    if schema_version_int != RETEST_QUEUE_SCHEMA_VERSION:
        return False, "unsupported_queue_schema_version"

    for field in ("job_id", "verification_id", "finding_id", "submitted_at"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"missing_{field}"

    for field in ("verification_id", "finding_id"):
        try:
            uuid.UUID(str(payload[field]))
        except (ValueError, TypeError):
            return False, f"invalid_{field}"

    try:
        datetime.fromisoformat(str(payload["submitted_at"]))
    except (TypeError, ValueError):
        return False, "invalid_submitted_at"

    attempt = payload.get("attempt", 1)
    try:
        attempt_int = int(attempt)
    except (TypeError, ValueError):
        return False, "invalid_attempt"
    if attempt_int < 1:
        return False, "invalid_attempt"

    return True, ""
