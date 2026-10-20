"""Shared helpers for the finding detail brief: bounded text, URL parts and shell quoting.

Every value the brief shows comes from the finding's stored, already-redacted evidence. Target
controlled strings (URLs, header values, certificate names) are only ever placed in plain text or,
for copyable commands, passed through ``q`` (the shared ``shell_word``) as a whole argument, so a
pasted command cannot run anything the target chose. A ``#`` line in a command holds fixed text
only: an interactive zsh does not treat it as a comment by default.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Iterable, Mapping

try:
    from scanner_tools.shell_words import shell_word
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.shell_words import shell_word

DETAIL_SCHEMA = "finding-detail/v1"
MAX_TEXT = 600
MAX_LIST = 25


def record(value: Any) -> dict[str, Any]:
    """A JSON object from a stored field (dict or JSON text), else an empty dict."""
    if isinstance(value, str) and len(value) <= 2_000_000:
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def text(value: Any, limit: int = MAX_TEXT) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def strings(value: Any, limit: int = MAX_LIST, chars: int = 300) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, Iterable) or isinstance(value, Mapping):
        return []
    out: list[str] = []
    for item in value:
        entry = text(item, chars)
        if entry and entry not in out:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


def join_limited(values: list[str], limit: int = 5) -> str:
    if not values:
        return ""
    shown = ", ".join(values[:limit])
    return shown + (f" (+{len(values) - limit} more)" if len(values) > limit else "")


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def url_parts(value: Any) -> tuple[str, str, int | None, str]:
    """(scheme, host, port, path) of an absolute http(s) URL; empty parts when unparseable."""
    try:
        parsed = urllib.parse.urlsplit(str(value or ""))
        port = parsed.port
    except ValueError:
        return "", "", None, ""
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        return "", "", None, ""
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, parsed.hostname, port, parsed.path or "/"


def origin_of(value: Any) -> str:
    scheme, host, port, _path = url_parts(value)
    if not scheme:
        return ""
    default = 443 if scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}" + ("" if port == default else f":{port}")


_REDACTED_QUERY_VALUE = re.compile(r"=(?:%3Credacted%3E|<redacted>|\[redacted\]|%5Bredacted%5D)(?=&|$|#)", re.IGNORECASE)


def display_url(value: Any, limit: int = 800) -> str:
    """A stored URL for reading: a value the server redacted reads as ``•••``, not as a marker."""
    return _REDACTED_QUERY_VALUE.sub("=•••", text(value, limit))


def short_date(value: Any) -> str:
    """``2025-01-01T00:00:00+00:00`` -> ``2025-01-01``; other text unchanged."""
    shown = text(value, 40)
    return shown[:10] if re.match(r"^\d{4}-\d{2}-\d{2}T", shown) else shown


def q(value: Any) -> str:
    """One shell word for a target-controlled value in a copyable command."""
    return shell_word(value)


def fact(label: str, value: Any, *, mono: bool = False, limit: int = MAX_TEXT) -> dict[str, Any] | None:
    shown = text(value, limit) if not isinstance(value, list) else join_limited(strings(value), 10)
    if not shown:
        return None
    return {"label": label, "value": shown, **({"mono": True} if mono else {})}


def facts(*entries: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [entry for entry in entries if entry]


def command(cmd: str, expect: str = "", note: str = "") -> dict[str, str]:
    out = {"command": cmd[:2_000]}
    if expect:
        out["expect"] = expect
    if note:
        out["note"] = note
    return out


# Evidence keys never shown as generic facts: receipts, digests and anything credential-shaped.
_HIDDEN_KEY_PARTS = (
    "receipt", "sha256", "hmac", "fingerprint", "secret", "token", "password", "cookie_value",
    "authorization", "api_key", "private", "session_id", "proof_contract", "canonical_capability",
    "severity_basis", "credential",
)


def visible_scalar_facts(evidence: Mapping[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    """Top-level scalar evidence values for a class the brief has no specific renderer for."""
    out: list[dict[str, Any]] = []
    for key, value in evidence.items():
        name = str(key)
        lowered = name.lower()
        if any(part in lowered for part in _HIDDEN_KEY_PARTS):
            continue
        if isinstance(value, (dict, list, tuple)) or value is None or isinstance(value, bool):
            continue
        entry = fact(name.replace("_", " ").capitalize(), value, mono=lowered.endswith(("url", "path", "id")))
        if entry:
            out.append(entry)
        if len(out) >= limit:
            break
    return out


# Server products named by a recorded Server / X-Powered-By header, for stack-specific examples.
_STACKS = (
    ("nginx", ("nginx", "openresty")),
    ("apache", ("apache",)),
    ("iis", ("microsoft-iis", "asp.net")),
    ("caddy", ("caddy",)),
    ("express", ("express",)),
    ("php", ("php",)),
    ("tomcat", ("tomcat", "coyote", "jetty")),
    ("werkzeug", ("werkzeug", "gunicorn", "uvicorn", "python")),
)


def detected_stack(headers: Mapping[str, Any]) -> str | None:
    """The server product the recorded response named, if any (lower-case header names)."""
    for name in ("server", "x-powered-by"):
        value = text(headers.get(name), 200).lower()
        if not value:
            continue
        for stack, markers in _STACKS:
            if any(marker in value for marker in markers):
                return stack
    return None


__all__ = [
    "DETAIL_SCHEMA", "command", "detected_stack", "display_url", "short_date", "fact", "facts", "integer", "join_limited",
    "origin_of", "q", "record", "strings", "text", "url_parts", "visible_scalar_facts",
]
