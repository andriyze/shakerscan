"""Explain a refused redirect: where the instance actually is, and how to point the client there.

Every ShakerScan client refuses to follow a redirect, because following one re-sends the bearer
token to whatever ``Location`` names. A bare "HTTP 308" left people guessing (D17); the usual
cause is an ``http://`` address for an instance served over HTTPS, so name that origin and the
client option that sets it.

A refused certificate is the other connection failure that needs a remedy and not only a reason:
an instance with a certificate from a private CA is unreachable until this machine trusts that CA.
"""

from __future__ import annotations

import urllib.parse


def redirect_origin(location: str | None, request_url: str) -> str | None:
    """The origin a redirect points at (relative locations resolved), or None."""
    if not location:
        return None
    try:
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(request_url, str(location).strip()))
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}"


def redirect_explanation(status: int, location: str | None, request_url: str, *, option: str = "--url") -> str:
    """One sentence for a refused redirect, naming the client ``option`` that sets the origin."""
    target = redirect_origin(location, request_url)
    here = redirect_origin(request_url, request_url)
    text = (
        f"the instance answered HTTP {status} with a redirect to {target or 'another location'}; "
        "an authenticated request is never followed to another location."
    )
    if target and here and target != here:
        upgrade = here.startswith("http://") and target.startswith("https://")
        return text + (
            f" {'The instance is served over HTTPS at' if upgrade else 'It points at'} {target}: "
            f"use that address (shakerscan connect {target}, or {option} {target})."
        )
    return text + f" Use the instance's own origin (shakerscan connect <origin>, or {option} <origin>)."


_CERTIFICATE_FAILURES = ("certificate_verify_failed", "certificate verify failed")
CERTIFICATE_HINT = (
    "this machine does not trust the instance's TLS certificate. If it comes from a private or "
    "corporate CA, set SSL_CERT_FILE to a PEM bundle that includes that CA, exported where you run "
    "shakerscan and where your agent starts `shakerscan mcp`, so the MCP server inherits it"
)


def certificate_hint(reason: object) -> str:
    """The remedy for a TLS verification failure in ``reason``, or "" for any other failure."""
    text = str(reason or "").lower()
    if any(marker in text for marker in _CERTIFICATE_FAILURES):
        return CERTIFICATE_HINT
    return ""


def with_certificate_hint(message: str, reason: object) -> str:
    """``message`` followed by the certificate remedy when ``reason`` is a TLS verification failure."""
    hint = certificate_hint(reason)
    return f"{message}. Hint: {hint}" if hint else message


__all__ = [
    "CERTIFICATE_HINT", "certificate_hint", "redirect_explanation", "redirect_origin",
    "with_certificate_hint",
]
