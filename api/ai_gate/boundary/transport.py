"""Bounded REST transport using AI Gate's credentials and request/token budgets."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from ..budget import RequestBudget, TokenBudget
from .contract import ContractError, relative_path


class BoundaryTransportError(RuntimeError):
    pass


@dataclass(frozen=True)
class Observation:
    status: int
    payload: Any
    digest: str
    byte_count: int
    request_url: str
    remote_ip: str | None


def origin_of(url: str) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ContractError("target_requires_http_origin_without_url_credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ContractError("invalid_target_port") from exc
    host = parsed.hostname.lower()
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ContractError("alpha_requires_https_except_loopback_fixtures")
    host = f"[{host}]" if ":" in host else host
    suffix = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{host}{suffix}"


def budget_limit(raw: Any, default: int, ceiling: int) -> int:
    if raw is None:
        return default
    if type(raw) is not int or not 0 <= raw <= ceiling:
        raise ContractError("invalid_boundary_budget")
    return raw


class BoundaryTransport:
    def __init__(self, session: Any, *, origin: str, headers: dict[str, dict[str, str]],
                 requests: RequestBudget, tokens: TokenBudget, rate_limit_rps: float,
                 max_response_bytes: int = 65536, scope: Any = None,
                 cancelled: Callable[[], bool] | None = None) -> None:
        if not math.isfinite(rate_limit_rps) or not 0 < rate_limit_rps <= 20:
            raise ContractError("boundary_rate_limit_must_be_positive_and_at_most_20")
        self.scope = scope
        self.cancelled = cancelled
        self.session = session
        self.origin = origin
        self.headers = headers
        self.requests = requests
        self.tokens = tokens
        self.delay = 1 / rate_limit_rps
        self.max_response_bytes = max_response_bytes
        self.next_request_at = 0.0
        self.records: list[dict[str, Any]] = []

    async def request(self, *, role: str, method: str, path: str, phase: str,
                      body: dict[str, Any] | None = None) -> Observation:
        if self.cancelled and self.cancelled():
            raise asyncio.CancelledError
        path = relative_path(path)
        if "{" in path or "}" in path or role not in self.headers:
            raise ContractError("unresolved_path_or_principal")
        if method not in {"GET", "POST"} or (method == "GET" and body is not None):
            raise ContractError("boundary_alpha_allows_only_reads_and_chat_posts")
        if self.tokens.exceeded:
            raise BoundaryTransportError("token_budget_exhausted")
        await asyncio.sleep(max(0.0, self.next_request_at - time.monotonic()))
        if self.cancelled and self.cancelled():
            raise asyncio.CancelledError
        if self.scope:
            self.scope.validate(self.origin + path)
        # One shared AI Gate counter, consumed before every outbound attempt.
        self.requests.consume(phase=phase)
        self.next_request_at = time.monotonic() + self.delay
        url = self.origin + path
        record: dict[str, Any] = {"phase": phase, "principal": role,
                                  "request_url": url, "method": method}
        self.records.append(record)
        kwargs: dict[str, Any] = {"headers": self.headers[role], "allow_redirects": False}
        if body is not None:
            kwargs["json"] = body
        try:
            async with self.session.request(method, url, **kwargs) as response:
                self.requests.record_response(status_code=response.status)
                record["status_code"] = response.status
                connection = getattr(response, "connection", None)
                transport = getattr(connection, "transport", None)
                peer = transport.get_extra_info("peername") if transport else None
                remote_ip = str(peer[0]) if peer else None
                if remote_ip:
                    record["remote_ip"] = remote_ip
                if self.scope:
                    record["resolved_host"] = self.scope.host
                    record["resolved_ips"] = list(self.scope.addresses.get(self.scope.host, []))
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.content.iter_chunked(8192):
                    if self.cancelled and self.cancelled():
                        raise asyncio.CancelledError
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise BoundaryTransportError("response_truncated")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                self.tokens.record(input_chars=len(json.dumps(body)) if body else 0,
                                   output_chars=len(raw))
                digest = "sha256:" + hashlib.sha256(raw).hexdigest()
                record.update(response_sha256=digest, response_bytes=size)
                if 300 <= response.status < 400:
                    raise BoundaryTransportError("redirect_blocked")
                if response.status == 429:
                    raise BoundaryTransportError("rate_limited")
                if response.status >= 500:
                    raise BoundaryTransportError("upstream_failure")
                if "json" not in response.headers.get("Content-Type", "").lower():
                    raise BoundaryTransportError("json_response_required")
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise BoundaryTransportError("invalid_json_response") from exc
                return Observation(response.status, payload, digest, size, url, remote_ip)
        except asyncio.CancelledError:
            record["error"] = "cancelled"
            raise
        except BoundaryTransportError as exc:
            record["error"] = str(exc)
            raise
        except Exception as exc:
            # Exceptions may include headers, URL credentials or response bodies.
            record["error"] = type(exc).__name__
            raise BoundaryTransportError(type(exc).__name__) from None
