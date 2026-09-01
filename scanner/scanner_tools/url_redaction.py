"""Deterministic redaction for public URL/path evidence.

Query values are always removed. Path segments that are likely credentials, signatures,
reset/verification tokens, or opaque high-entropy values are replaced while ordinary route
structure remains useful for debugging and coverage reporting.
"""

from __future__ import annotations

import re
import urllib.parse


_SENSITIVE_LABELS = frozenset({
    "access-token", "access_token", "accesstoken", "api-key", "api_key", "apikey",
    "auth", "authorization", "bearer", "code", "confirm", "confirmation",
    "credential", "credentials", "invite", "invitation", "key", "magic", "nonce",
    "otp", "password", "recover", "recovery", "reset", "secret", "session",
    "signature", "signed", "sso", "token", "verify", "verification",
})
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}$")
_HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_OPAQUE_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{28,}$")
_KEY_VALUE_RE = re.compile(r"^([^=:]{1,80})([:=])(.*)$")
_CLIENT_ROUTE_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.~-]*$")
_CLIENT_ROUTE_FIELD_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,200}$")


def _label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _looks_opaque_secret(value: str) -> bool:
    if _JWT_RE.fullmatch(value) or _HEX_SECRET_RE.fullmatch(value):
        return True
    if not _OPAQUE_SECRET_RE.fullmatch(value):
        return False
    # Avoid redacting a long all-alpha documentation slug. Opaque credentials generally mix
    # character classes or contain URL-safe separators.
    return (
        any(ch.isdigit() for ch in value)
        and any(ch.isalpha() for ch in value)
    ) or "_" in value or "-" in value


def redact_path(path: str) -> str:
    """Return a route-useful path with likely secret segments removed."""
    raw = str(path or "") or "/"
    leading = raw.startswith("/")
    trailing = raw.endswith("/") and raw != "/"
    segments = raw.split("/")
    redacted: list[str] = []
    previous_label = ""
    for index, segment in enumerate(segments):
        if segment == "" and (index == 0 or index == len(segments) - 1):
            redacted.append("")
            continue
        decoded = urllib.parse.unquote(segment)
        match = _KEY_VALUE_RE.fullmatch(decoded)
        current_label = _label(decoded)
        if previous_label in _SENSITIVE_LABELS:
            redacted.append("<redacted>")
        elif match and _label(match.group(1)) in _SENSITIVE_LABELS:
            redacted.append(f"{match.group(1)}{match.group(2)}<redacted>")
        elif _looks_opaque_secret(decoded):
            redacted.append("<redacted>")
        else:
            redacted.append(segment)
        previous_label = current_label
    result = "/".join(redacted)
    if leading and not result.startswith("/"):
        result = "/" + result
    if trailing and not result.endswith("/"):
        result += "/"
    return result or "/"


def redact_url(
    value: str,
    *,
    query_placeholder: str = "<redacted>",
    max_length: int = 2_000,
) -> str:
    """Redact one absolute or relative URL without retaining userinfo or query values."""
    text = str(value or "").strip()
    parsed = urllib.parse.urlsplit(text)
    path = redact_path(parsed.path or "/")
    query = urllib.parse.urlencode([
        (str(name)[:200], query_placeholder)
        for name, _item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    ])
    if parsed.scheme or parsed.netloc:
        host = parsed.hostname or ""
        display = f"[{host}]" if ":" in host and not host.startswith("[") else host
        try:
            port = parsed.port
        except ValueError:
            port = None
        default = 443 if parsed.scheme.lower() == "https" else 80
        authority = display if port in {None, default} else f"{display}:{port}"
        result = urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, query, ""))
    else:
        result = urllib.parse.urlunsplit(("", "", path, query, ""))
    return result[:max_length]


def redact_client_route(value: str, *, max_length: int = 1_000) -> str | None:
    """Return a value-free SPA fragment route, or ``None`` when it is unsafe.

    Browser proof URLs commonly use ``#/route?field=<payload>``. Public evidence
    needs the route and field names to remain actionable, but must never retain
    the fragment values because that is where the injected proof payload lives.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return None
    raw = parsed.fragment if parsed.fragment else text.lstrip("#")
    if (
        not raw
        or len(raw.encode("utf-8", "replace")) > max_length
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in raw)
    ):
        return None
    raw_path, separator, raw_query = raw.partition("?")
    bang = raw_path.startswith("!/")
    path_value = raw_path[1:] if bang else raw_path
    try:
        decoded_path = urllib.parse.unquote(path_value)
    except (TypeError, ValueError):
        return None
    if (
        not path_value.startswith("/")
        or path_value.startswith("//")
        or not _CLIENT_ROUTE_PATH_RE.fullmatch(decoded_path)
    ):
        return None
    try:
        pairs = urllib.parse.parse_qsl(
            raw_query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=64,
        ) if separator else []
    except ValueError:
        return None
    names: list[str] = []
    for raw_name, _raw_value in pairs:
        name = str(raw_name or "").strip()
        if (
            not name
            or len(name) > 200
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in name)
            or not _CLIENT_ROUTE_FIELD_RE.fullmatch(name)
        ):
            continue
        if name not in names:
            names.append(name)
    path = redact_path(path_value)
    query = urllib.parse.urlencode([(name, "") for name in sorted(names)])
    route = urllib.parse.urlunsplit(("", "", path, query, ""))
    return ("!" if bang else "") + route
