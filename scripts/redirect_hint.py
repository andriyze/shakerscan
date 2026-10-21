"""Explain a refused redirect: where the instance actually is, and how to point the client there.

Every ShakerScan client refuses to follow a redirect, because following one re-sends the bearer
token to whatever ``Location`` names. A bare "HTTP 308" left people guessing (D17); the usual
cause is an ``http://`` address for an instance served over HTTPS, so name that origin and the
client option that sets it.

A refused certificate is the other connection failure that needs a remedy and not only a reason:
an instance with a certificate from a private CA is unreachable until this machine trusts that CA.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# The same quoting as scanner_tools.shell_words.shell_word (this module is vendored into the
# client on its own, so it carries a copy; a test keeps the two identical).
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_BARE = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")


def shell_word(value: object) -> str:
    """``value`` as one shell word that sh, bash, dash, ksh, zsh and fish read back literally."""
    text = _CONTROL.sub(lambda match: urllib.parse.quote(match.group(), safe=""), str(value))
    if not text:
        return "''"

    def quoted(run: str) -> str:
        if _BARE.fullmatch(run) and not run.startswith("="):
            return run
        return "'" + run.replace("'", "'\"'\"'") + "'"

    return '"\\\\"'.join(quoted(run) if run else "" for run in text.split("\\"))


def _host(netloc: str, hostname: str) -> str | None:
    """``hostname`` written back as a DNS name, IPv4 address or bracketed IPv6 address."""
    if netloc.rsplit("@", 1)[-1].startswith("["):
        try:
            return f"[{ipaddress.IPv6Address(hostname).compressed}]"
        except ValueError:
            return None
    try:
        return str(ipaddress.IPv4Address(hostname))
    except ValueError:
        pass
    name = hostname.lower()
    if len(name) > 253 or not all(_DNS_LABEL.fullmatch(label) for label in name.split(".")):
        return None
    return name


def redirect_origin(location: str | None, request_url: str) -> str | None:
    """The origin a redirect points at (relative locations resolved), or None.

    The origin is rebuilt from the parsed scheme, a strictly validated host and an integer
    port, so it can be named in a command. Anything else in ``Location`` yields None.
    """
    if not location:
        return None
    try:
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(request_url, str(location).strip()))
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        return None
    host = _host(parts.netloc, parts.hostname)
    if host is None:
        return None
    return f"{scheme}://{host}" + (f":{int(port)}" if port is not None else "")


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
        word = shell_word(target)
        return text + (
            f" {'The instance is served over HTTPS at' if upgrade else 'It points at'} {target}: "
            f"use that address (shakerscan connect {word}, or {option} {word})."
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
    "shell_word", "with_certificate_hint",
]
