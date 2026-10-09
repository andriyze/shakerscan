"""Registrable-domain (eTLD+1) and same-site helpers for scanner code, from the one bundled
Public Suffix List (``api/scope/psl.py``, PRIVATE section included).

Use these, never a "last two labels" rule: under one, ``victim.github.io`` and
``attacker.github.io`` (or ``a.co.uk`` and ``b.co.uk``) look like one site, so credentials,
cookies or first-party trust would cross registrants.
"""
from __future__ import annotations

try:
    from scope.psl import registrable_domain as _registrable_domain
    from scope.psl import spans_public_suffix
except ModuleNotFoundError:  # source checkout: the api package beside scanner/
    from api.scope.psl import registrable_domain as _registrable_domain
    from api.scope.psl import spans_public_suffix


def site_of(host: str) -> str:
    """The registrable domain of ``host``; the host itself (lower case, no port or brackets)
    when it has none (an address, ``localhost``, or a public suffix such as ``github.io``)."""
    text = str(host or "").strip().lower()
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.rstrip(".")
    return _registrable_domain(text) or text


def same_site(left: str, right: str) -> bool:
    """True when two hosts share a registrable domain (never across a public suffix)."""
    a, b = site_of(left), site_of(right)
    return bool(a) and a == b


__all__ = ["same_site", "site_of", "spans_public_suffix"]
