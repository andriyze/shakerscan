"""Explain a refused redirect: where the instance actually is, and how to point the client there.

Every ShakerScan client refuses to follow a redirect, because following one re-sends the bearer
token to whatever ``Location`` names. A bare "HTTP 308" left people guessing (D17); the usual
cause is an ``http://`` address for an instance served over HTTPS, so name that origin and the
client option that sets it.
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


__all__ = ["redirect_explanation", "redirect_origin"]
