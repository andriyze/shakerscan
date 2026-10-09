"""The one spelling of a DNS host name: IDNA 2008 with the UTS #46 mapping, strictly.

Every scope decision, permission bound, destination subject, credential host bound and approval
screen spells a host with ``canonical_host``, so the decision names the host the HTTP client
connects to. httpx and browsers encode a non-ASCII host with IDNA 2008 (non-transitional UTS #46);
Python's built-in ``idna`` codec is IDNA 2003, which maps the deviation characters differently:

* ``straße.example`` is ``strasse.example`` under IDNA 2003 but ``xn--strae-oqa.example`` under
  IDNA 2008, a different registrable name;
* a final sigma (``ς``) is folded to ``σ`` under IDNA 2003 only;
* ZERO WIDTH JOINER / NON-JOINER are deleted under IDNA 2003 (``a<ZWJ>b`` became ``ab``) and are
  refused by IDNA 2008 outside the scripts whose joining rules allow them.

A host that fails strict processing raises ``HostNameError``; there is no fallback to the old
codec, so an ambiguous spelling is refused rather than reinterpreted. Encoding is pure: no DNS
lookup and no network traffic.
"""
from __future__ import annotations

import ipaddress

import idna

# Recorded with persisted host bounds, so a bound stored under another rule is recognised.
HOST_CANONICALIZATION = "idna2008-uts46"
_MAX_HOST = 253
_MAX_LABEL = 63


class HostNameError(ValueError):
    """A host that is not a valid DNS name under strict IDNA 2008 / UTS #46."""


def _ip_literal(host: str) -> str | None:
    if ":" in host:
        return host  # an IPv6 literal (with any zone) is not a DNS name; kept as spelled
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return host


def _check_a_label(label: str, host: str) -> None:
    """An ASCII ``xn--`` label must decode, and re-encode to itself, under IDNA 2008."""
    try:
        unicode_label = idna.decode(label)
        again = idna.encode(unicode_label, uts46=True).decode("ascii")
    except (UnicodeError, idna.IDNAError) as exc:
        raise HostNameError(f"host {host!r} has an invalid IDNA 2008 label {label!r}") from exc
    if again != label:
        raise HostNameError(f"host {host!r} has a non-canonical IDNA label {label!r}")


def canonical_host(value: object) -> str:
    """The ASCII host (lower case, no trailing dot, A-labels) the HTTP client connects to.

    IP literals are returned as spelled (lower case, without brackets). Raises ``HostNameError``
    for an empty host or one that strict IDNA 2008 / UTS #46 processing refuses.
    """
    host = str(value or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host.isascii():
        host = host.lower()
        if host.endswith("."):
            host = host[:-1]
        if not host:
            raise HostNameError("host is empty")
        literal = _ip_literal(host)
        if literal is not None:
            return literal
        ascii_host = host
    else:
        try:
            ascii_host = idna.encode(host, uts46=True, transitional=False).decode("ascii").lower()
        except (UnicodeError, idna.IDNAError) as exc:
            raise HostNameError(
                f"host {host!r} is not a valid IDNA 2008 / UTS #46 name: {exc}"
            ) from exc
        if ascii_host.endswith("."):
            ascii_host = ascii_host[:-1]
    if not ascii_host or len(ascii_host) > _MAX_HOST:
        raise HostNameError(f"host {host!r} is empty or longer than {_MAX_HOST} characters")
    for label in ascii_host.split("."):
        if not label or len(label) > _MAX_LABEL:
            raise HostNameError(f"host {host!r} has an empty or over-long label")
        if label.startswith("xn--"):
            _check_a_label(label, host)
    return ascii_host


def unicode_host(ascii_host: object) -> str:
    """The Unicode (U-label) form of a canonical ASCII host, for display beside it."""
    text = str(ascii_host or "")
    if not any(label.startswith("xn--") for label in text.split(".")):
        return text
    try:
        return idna.decode(text)
    except (UnicodeError, idna.IDNAError):
        return text


def host_forms(ascii_host: object) -> dict[str, str]:
    """``{"ascii": ..., "unicode": ...}`` for an approval screen or an API answer."""
    text = str(ascii_host or "")
    return {"ascii": text, "unicode": unicode_host(text)}


def display_host(ascii_host: object) -> str:
    """``xn--strae-oqa.example (straße.example)``; a plain ASCII host is shown once."""
    forms = host_forms(ascii_host)
    if forms["unicode"] == forms["ascii"]:
        return forms["ascii"]
    return f"{forms['ascii']} (Unicode: {forms['unicode']})"


__all__ = [
    "HOST_CANONICALIZATION", "HostNameError", "canonical_host", "display_host", "host_forms",
    "unicode_host",
]
