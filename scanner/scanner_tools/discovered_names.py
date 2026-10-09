"""Which discovered names belong to an apex, compared on DNS label boundaries.

Passive discovery sources (subfinder, CT logs, crt.sh, Gungnir) return whatever names they hold.
Their filters used to test ``name.endswith(apex)`` without a leading dot, so ``notexample.com``
and ``evil-example.com`` were stored as subdomains of ``example.com`` and became targets with
a Scan button under the operator's root. Every path that turns a discovered name into a target
asks this module instead: a name is accepted only when, after canonicalisation, it equals the
apex or ends with ``"." + apex``.

Canonicalisation matches ``action_scope._canonical_host`` (the host the HTTP client connects to):
lower case, no trailing dot, and IDNA 2008 with the UTS #46 mapping for a non-ASCII name. A leading
``*.`` wildcard label from a certificate is dropped. A name that is not a syntactically valid DNS
name after that is refused rather than guessed at.

Standard library and ``idna`` only, so the scanner package (which does not import the API
package) and the API share it.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

import idna

_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?![0-9]+$)[a-z0-9-]{2,63}$"
)


def canonical_name(value: Any) -> str | None:
    """The canonical ASCII form of one discovered DNS name, or None when it is not one."""
    host = str(value or "").strip().lower()
    while host.startswith("*."):
        host = host[2:]
    if host.endswith("."):
        host = host[:-1]
    if not host or host.startswith(".") or ".." in host:
        return None
    try:
        if host.isascii():
            host = host.encode("idna").decode("ascii")
        else:
            host = idna.encode(host, uts46=True).decode("ascii").rstrip(".")
    except (UnicodeError, idna.IDNAError):
        return None
    host = host.lower()
    return host if _DNS_NAME.fullmatch(host) else None


def name_under_apex(value: Any, apex: Any) -> str | None:
    """The canonical name when it is the apex or a name below it; None otherwise.

    TODO(fix/scope-boundaries): an apex that is itself a public suffix (``co.uk``) would admit
    every registrant below it. The public-suffix check lands with the PSL helper on that branch;
    reuse it here once merged rather than duplicating it.
    """
    root = canonical_name(apex)
    name = canonical_name(value)
    if not root or not name:
        return None
    return name if name == root or name.endswith("." + root) else None


def subdomain_of(value: Any, apex: Any) -> str | None:
    """The canonical name when it is strictly below the apex (never the apex itself)."""
    name = name_under_apex(value, apex)
    root = canonical_name(apex)
    return name if name and name != root else None


def filter_subdomains(names: Iterable[Any], apex: Any) -> tuple[list[str], int]:
    """Distinct canonical subdomains of ``apex`` in input order, and how many inputs were refused.

    The apex itself is neither kept nor counted as refused: it is the root, not a discovery.
    """
    root = canonical_name(apex)
    kept: list[str] = []
    seen: set[str] = set()
    refused = 0
    for value in names or ():
        name = canonical_name(value)
        if root and name == root:
            continue
        if not root or not name or not name.endswith("." + root):
            refused += 1
            continue
        if name not in seen:
            seen.add(name)
            kept.append(name)
    return kept, refused


__all__ = ["canonical_name", "filter_subdomains", "name_under_apex", "subdomain_of"]
