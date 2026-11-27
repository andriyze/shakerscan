"""Refuse requests addressed to a DNS name this deployment was never given (DNS rebinding).

The OSS API is tokenless and, by default, reachable only on loopback. A web page the operator
visits can still point a hostname it controls at 127.0.0.1 and then read API responses as its
own same-origin traffic, because the browser keeps sending that hostname in ``Host``. CORS and
the unsafe-origin guard do not see this: the browser considers the request same-origin.

Rebinding needs a publicly delegated name the attacker controls, so the guard admits every
address form such an attacker cannot own:

* IP literals, ``localhost`` and ``*.localhost``;
* single-label names (Docker service names such as ``api``) and private-use suffixes that are
  never delegated in public DNS (``.local``, ``.lan``, ``.home.arpa``, ``.internal`` ...);
* Tailscale MagicDNS names (``*.ts.net``);
* the configured public host, the hosts of configured CORS origins, and the CORS origin regex;
* requests forwarded by the managed fleet gateway with its proxy secret;
* anything listed in ``SHAKERSCAN_ALLOWED_HOSTS`` (exact names, ``.suffix`` entries, or ``*``).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
from typing import Any, Sequence
from urllib.parse import urlsplit


ALLOWED_HOSTS_ENV = "SHAKERSCAN_ALLOWED_HOSTS"

PRIVATE_USE_SUFFIXES = (
    ".localhost",
    ".local",
    ".lan",
    ".home",
    ".home.arpa",
    ".internal",
    ".localdomain",
    ".corp",
    ".test",
    ".ts.net",
)


def _split_host(host_header: str) -> str:
    """Return the lower-cased host of a ``Host`` header value without its port."""
    value = host_header.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else value
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _origin_host(origin: str) -> str:
    try:
        return (urlsplit(origin).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _configured_entries(raw: str) -> tuple[str, ...]:
    return tuple(item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip())


def host_is_allowed(
    host_header: str,
    *,
    allow_origins: Sequence[str] = (),
    allow_origin_regex: str = "",
    public_host: str = "",
    extra_hosts: Sequence[str] = (),
) -> bool:
    host = _split_host(host_header)
    if not host or _is_ip_literal(host) or host == "localhost" or "." not in host:
        return True
    if host.endswith(PRIVATE_USE_SUFFIXES):
        return True
    for entry in extra_hosts:
        if entry == "*" or host == entry or (entry.startswith(".") and host.endswith(entry)):
            return True
    if public_host and host == _split_host(public_host):
        return True
    if any(host == _origin_host(origin) for origin in allow_origins):
        return True
    if allow_origin_regex:
        pattern = re.compile(allow_origin_regex)
        raw = host_header.strip().lower()
        port = f":{raw.split(':', 1)[1]}" if ":" in raw else ""
        for scheme in ("https", "http"):
            if pattern.fullmatch(f"{scheme}://{host}") or pattern.fullmatch(f"{scheme}://{host}{port}"):
                return True
    return False


class TrustedHostGuardMiddleware:
    """Reject HTTP and WebSocket requests whose ``Host`` is an unrecognised public DNS name."""

    def __init__(self, app: Any, *, allow_origins: Sequence[str] = (), allow_origin_regex: str = ""):
        self.app = app
        self.allow_origins = tuple(allow_origins)
        self.allow_origin_regex = allow_origin_regex

    def _gateway_forwarded(self, headers: dict[str, str]) -> bool:
        configured = os.environ.get("FLEET_GATEWAY_PROXY_SECRET", "").strip()
        presented = headers.get("x-shakerscan-gateway-secret", "").strip()
        return bool(
            configured
            and presented
            and secrets.compare_digest(configured.encode("utf-8"), presented.encode("utf-8"))
        )

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers") or []
        }
        if host_is_allowed(
            headers.get("host", ""),
            allow_origins=self.allow_origins,
            allow_origin_regex=self.allow_origin_regex,
            public_host=os.environ.get("SHAKERSCAN_PUBLIC_HOST", ""),
            extra_hosts=_configured_entries(os.environ.get(ALLOWED_HOSTS_ENV, "")),
        ) or self._gateway_forwarded(headers):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({
            "detail": (
                "This API does not answer to that host name. Add it to "
                f"{ALLOWED_HOSTS_ENV} (comma-separated) or SHAKERSCAN_PUBLIC_HOST to allow it."
            ),
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 421,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


def configure_host_guard(app: Any, *, allow_origins: Sequence[str], allow_origin_regex: str = "") -> None:
    """Register the guard as the outermost middleware (Starlette wraps the last one added)."""
    app.add_middleware(
        TrustedHostGuardMiddleware,
        allow_origins=allow_origins,
        allow_origin_regex=allow_origin_regex,
    )


__all__ = [
    "ALLOWED_HOSTS_ENV",
    "TrustedHostGuardMiddleware",
    "configure_host_guard",
    "host_is_allowed",
]
