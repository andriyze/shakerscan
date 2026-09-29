"""Redirect policy for control-plane HTTP checks that run inside the API process.

The API process sits on the internal network next to PostgreSQL, Redis, MinIO and any
cloud metadata endpoint. Operator-configured endpoints such as an AI Gate target are
fetched from here for quick connectivity and readiness checks, and urllib's default
opener follows a redirect to any host while copying every request header except the
content headers. A target that answers with a redirect could therefore steer the API
process at an internal service and receive operator-configured headers such as
``Authorization`` on the way.

``same_origin_opener`` follows only redirects that stay on the configured origin (or
upgrade ``http`` to ``https`` on the same host's default ports). Any other redirect is
returned to the caller as the redirect response itself, so connectivity reports still
show the 3xx status and ``Location`` instead of an opaque failure.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    try:
        port = parsed.port
    except ValueError:
        return scheme, "", None
    return scheme, (parsed.hostname or "").lower(), port or _DEFAULT_PORTS.get(scheme)


def is_same_origin_redirect(current_url: str, redirect_url: str) -> bool:
    """Return True when following ``redirect_url`` keeps the request on its origin."""
    current = _origin(current_url)
    target = _origin(urllib.parse.urljoin(current_url, redirect_url))
    if not current[1] or not target[1] or current[1] != target[1]:
        return False
    if target == current:
        return True
    # A plain http -> https upgrade on the same host's default ports is not a new service.
    return current == ("http", current[1], 80) and target == ("https", current[1], 443)


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while they stay on the request's origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001 - urllib signature
        if not is_same_origin_redirect(req.full_url, newurl):
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def same_origin_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(SameOriginRedirectHandler())
