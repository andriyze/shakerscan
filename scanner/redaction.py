"""Shared secret-redaction helpers.

Single source of truth for sensitive-key matching and value masking so coverage
cannot drift between the API, scanner reporting, and Model Intake. Before this
module, ``api/api.py`` and ``scanner/scanner_tools/model_intake.py`` each carried
their own ``SENSITIVE_*`` key-set and the two diverged (only Model Intake covered
the AWS/Azure/GCP keys). They now both consume :data:`SENSITIVE_KEYS` here.

This module is intentionally a leaf (stdlib only) so it is cheap to import from
both ``api`` and ``scanner`` without circular-import risk.

Note: ``api/ai_verifier.py`` keeps its own, more aggressive ``[REDACTED]``
provider-bound redactor (different sentinel and purpose: what is safe to send to
an external AI provider). It is not folded in here on purpose, but it sources the
same key-set via :func:`is_sensitive_key` when checking structured payloads.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

MASK = "***"

# Union of the historical api + model_intake key-sets. Keep sorted for diff-ability.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "access_key",
        "access_key_id",
        "access_token",
        "ai_api_key",
        "api_key",
        "api_secret",
        "api_token",
        "auth_cookies",
        "auth_header",
        "auth_headers_json",
        "auth_scenario_json",
        "authorization",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "azure_sas_token",
        "bearer_token",
        "client_secret",
        "credential",
        "credentials",
        "gcp_credentials",
        "hf_token",
        "huggingface_token",
        "login_password",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "secret_access_key",
        "secret_value",
        "session_token",
        "token",
        "user2_cookies",
        "user2_header",
    }
)

SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "_secret",
    "secret_",
    "_token",
    "token_",
    "_credential",
    "credential_",
    "private_key",
    "password",
)

# Query-string parameter names that carry credentials in artifact/reference URLs.
SENSITIVE_QUERY_KEYS: frozenset[str] = frozenset(
    {
        "access_token",
        "access-token",
        "api_key",
        "api-key",
        "awsaccesskeyid",
        "expires",
        "x-amz-credential",
        "x-amz-security-token",
        "x-amz-signature",
        "signature",
        "sig",
        "token",
    }
)

# Free-text token scrubbing (used by scanner reporting + AI transcript bodies).
# The first two patterns are reporting._redact_sensitive's historical ones
# (header / query-string / env-var `key=value` shapes). The third catches
# JSON / dict-literal `"api_key": "SECRET"` shapes, which transcript request and
# response bodies embed as text and which the `=`-only pattern misses.
_SENSITIVE_TEXT_KEY = (
    r"[a-z0-9_-]*(?:api[_-]?key|secret|token|password|passwd|pwd|authorization|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|credential|session[_-]?token|"
    r"refresh[_-]?token|bearer)[a-z0-9_-]*"
)
_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(authorization:\s*bearer)\s+[A-Za-z0-9._-]+"), r"\1 ***"),
    (re.compile(r"(?i)(api[-_ ]?key|token|secret)=([^&\s]+)"), r"\1=***"),
    (
        re.compile(rf'(?i)(["\']{_SENSITIVE_TEXT_KEY}["\']\s*:\s*)(["\'])[^"\']*(["\'])'),
        r"\1\2***\3",
    ),
)

_EMPTY = (None, "", [], {})


def is_sensitive_key(key: Any) -> bool:
    """True if a dict key names a secret (exact match or fragment match)."""
    normalized = str(key or "").strip().lower().replace("-", "_")
    if normalized in SENSITIVE_KEYS:
        return True
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def mask_secret(value: str) -> str:
    """Partial mask for previews: short values fully starred, else first4...last4."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def redact_url_credentials(value: str) -> str:
    """Mask userinfo passwords and sensitive query params in a reference URL.

    Non-URL strings are returned unchanged.
    """
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value

    netloc = parsed.netloc
    if parsed.password:
        hostname = parsed.hostname or ""
        username = urllib.parse.quote(urllib.parse.unquote(parsed.username or ""), safe="")
        host = f"{username}:***@{hostname}" if username else hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        netloc = host

    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if query_pairs:
        redacted_pairs = [
            (key, MASK if key.strip().lower().replace("_", "-") in SENSITIVE_QUERY_KEYS else item)
            for key, item in query_pairs
        ]
        query = urllib.parse.urlencode(redacted_pairs, doseq=True)
    else:
        query = parsed.query
    return urllib.parse.urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, query, parsed.fragment)
    )


def redact_text(text: Any) -> Any:
    """Scrub bearer/api-key/token/secret patterns out of free text."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_sensitive(
    value: Any,
    *,
    redact_strings: bool = False,
    scrub_text: bool = False,
    mask: str = MASK,
) -> Any:
    """Recursively mask values stored under sensitive keys.

    - dict: any key matching :func:`is_sensitive_key` with a non-empty value is
      replaced with ``mask``; other values recurse.
    - list/tuple: each item recurses.
    - str: returned unchanged unless ``redact_strings`` is set, in which case
      reference-URL credentials are masked; with ``scrub_text`` the free-text
      bearer/api-key/token/secret patterns are scrubbed too (used for
      transcript/evidence bodies).
    """
    def _recurse(item: Any) -> Any:
        return redact_sensitive(item, redact_strings=redact_strings, scrub_text=scrub_text, mask=mask)

    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if is_sensitive_key(key) and item not in _EMPTY:
                out[key] = mask
            else:
                out[key] = _recurse(item)
        return out
    if isinstance(value, list):
        return [_recurse(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_recurse(item) for item in value)
    if isinstance(value, str) and redact_strings:
        out_str = redact_url_credentials(value)
        if scrub_text:
            out_str = redact_text(out_str)
        return out_str
    return value
