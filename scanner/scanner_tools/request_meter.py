"""Process-local outbound request accounting for standalone scanner runs."""

from __future__ import annotations

import contextvars
import ipaddress
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Collection
from typing import Any


REQUEST_METER_SCHEMA_V1 = "request_meter_v1"
REQUEST_BUDGET_MODES = frozenset({"off", "compatibility", "enforce"})
SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class RequestBudgetExceeded(RuntimeError):
    pass


class RequestMethodRejected(RequestBudgetExceeded):
    """Raised before a target-bound request violates its passive method policy."""


class RequestDestinationRejected(RequestBudgetExceeded):
    """Raised before a request exceeds its frozen runtime target binding."""


def canonical_http_origin(value: Any) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        scheme = parsed.scheme.lower()
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return None
        port = parsed.port
    except (TypeError, ValueError):
        return None
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{display_host}{f':{port}' if port and port != default_port else ''}"


def _resolve_host_addresses(host: str) -> frozenset[str]:
    return frozenset(
        str(ipaddress.ip_address(item[4][0]))
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    )


class RequestMeter:
    def __init__(
        self,
        *,
        limit: int | None,
        target_host: str | None,
        mode: str,
        planned: int = 0,
        reserved: int = 0,
        state_changing_limit: int | None = None,
        allowed_methods: Collection[str] | None = None,
        allowed_origins: Collection[str] | None = None,
        allowed_addresses: Collection[str] | None = None,
        require_destination_scope: bool = False,
        destination_resolver: Any = None,
        destination_cache_seconds: float = 1.0,
    ) -> None:
        normalized_mode = str(mode or "compatibility").strip().lower()
        self.mode = normalized_mode if normalized_mode in REQUEST_BUDGET_MODES else "compatibility"
        self.limit = max(0, int(limit)) if limit is not None else None
        self.target_host = str(target_host or "").strip().lower()
        self.planned = max(0, int(planned or 0))
        self.reserved = max(0, int(reserved or 0))
        self.state_changing_limit = (
            None
            if state_changing_limit is None
            else max(0, int(state_changing_limit))
        )
        self.allowed_methods = frozenset(
            str(method or "").strip().upper()
            for method in (allowed_methods or ())
            if str(method or "").strip()
        )
        self.allowed_origins = frozenset(
            origin
            for origin in (
                canonical_http_origin(value) for value in (allowed_origins or ())
            )
            if origin
        )
        self.allowed_addresses = frozenset(
            str(ipaddress.ip_address(str(value).strip()))
            for value in (allowed_addresses or ())
            if str(value).strip()
        )
        self.require_destination_scope = bool(require_destination_scope)
        self._destination_resolver = destination_resolver or _resolve_host_addresses
        self._destination_cache_seconds = max(0.0, float(destination_cache_seconds))
        self._destination_cache: dict[str, tuple[float, frozenset[str]]] = {}
        self.attempted = 0
        self.completed = 0
        self.retried = 0
        self.rejected = 0
        self.method_rejected = 0
        self.state_changing_attempted = 0
        self.state_changing_rejected = 0
        self.destination_rejected = 0
        self.successful = 0
        self.unmetered_tool_invocations = 0
        self.adapter_usage: dict[str, dict[str, int]] = {}
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    @property
    def exhausted(self) -> bool:
        return self.limit is not None and self.attempted >= self.limit

    def matches_target(self, url: Any) -> bool:
        try:
            host = (urllib.parse.urlparse(str(url)).hostname or "").lower()
        except Exception:
            return False
        if not host or not self.target_host:
            return False
        return host == self.target_host or host.endswith(f".{self.target_host}")

    def applies_to(self, url: Any) -> bool:
        return self.mode != "off" and self.matches_target(url)

    def before_request(
        self,
        *,
        phase: str,
        url: Any,
        method: Any = None,
        retry: bool = False,
    ) -> bool:
        normalized_method = str(method or "").strip().upper()
        if self.require_destination_scope:
            self._require_destination(phase=phase, url=url, method=normalized_method)
        if (
            normalized_method
            and self.allowed_methods
            and self.matches_target(url)
            and normalized_method not in self.allowed_methods
        ):
            with self._lock:
                self.rejected += 1
                self.method_rejected += 1
                self._increment_adapter(phase, "rejected")
                self._event(
                    "rejected_method",
                    phase=phase,
                    url=url,
                    method=normalized_method,
                    retry=retry,
                )
            raise RequestMethodRejected(
                f"HTTP method {normalized_method} is not allowed by the passive request policy"
            )
        if not self.applies_to(url):
            return False
        with self._lock:
            state_changing = bool(
                normalized_method and normalized_method not in SAFE_HTTP_METHODS
            )
            if (
                self.enforcing
                and state_changing
                and self.state_changing_limit is not None
                and self.state_changing_attempted >= self.state_changing_limit
            ):
                self.rejected += 1
                self.state_changing_rejected += 1
                self._increment_adapter(phase, "rejected")
                self._event(
                    "rejected_state_changing_budget",
                    phase=phase,
                    url=url,
                    method=normalized_method,
                    retry=retry,
                )
                raise RequestBudgetExceeded(
                    "state-changing request budget exhausted before "
                    f"{phase} ({self.state_changing_attempted}/"
                    f"{self.state_changing_limit})"
                )
            if self.enforcing and self.exhausted:
                self.rejected += 1
                self._increment_adapter(phase, "rejected")
                self._event("rejected", phase=phase, url=url, retry=retry)
                raise RequestBudgetExceeded(
                    f"request budget exhausted before {phase} ({self.attempted}/{self.limit})"
                )
            self.attempted += 1
            if state_changing:
                self.state_changing_attempted += 1
            self._increment_adapter(phase, "attempted")
            if retry:
                self.retried += 1
                self._increment_adapter(phase, "retried")
            self._event("attempted", phase=phase, url=url, retry=retry)
        return True

    def _require_destination(self, *, phase: str, url: Any, method: str) -> None:
        parsed = urllib.parse.urlsplit(str(url or "").strip())
        origin = canonical_http_origin(url)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        reason = None
        observed: frozenset[str] = frozenset()
        if not origin or origin not in self.allowed_origins:
            reason = "origin_not_bound"
        elif host != self.target_host:
            reason = "host_not_bound"
        elif not self.allowed_addresses:
            reason = "address_binding_missing"
        else:
            now = time.monotonic()
            cached = self._destination_cache.get(host)
            if cached and now - cached[0] <= self._destination_cache_seconds:
                observed = cached[1]
            else:
                try:
                    observed = frozenset(
                        str(ipaddress.ip_address(str(value).strip()))
                        for value in self._destination_resolver(host)
                        if str(value).strip()
                    )
                except Exception:
                    observed = frozenset()
                self._destination_cache[host] = (now, observed)
            if not observed:
                reason = "runtime_dns_empty"
            elif not observed.issubset(self.allowed_addresses):
                reason = "runtime_dns_out_of_scope"
        if reason is None:
            return
        with self._lock:
            self.rejected += 1
            self.destination_rejected += 1
            self._increment_adapter(phase, "rejected")
            self._event(
                "rejected_destination",
                phase=phase,
                url=url,
                method=method,
                reason=reason,
                resolved_addresses=sorted(observed),
            )
        raise RequestDestinationRejected(
            f"request destination is outside the frozen target binding ({reason})"
        )

    def record_completion(self, *, phase: str, url: Any, status_code: int | None = None) -> None:
        if not self.applies_to(url):
            return
        with self._lock:
            self.completed += 1
            self._increment_adapter(phase, "completed")
            if status_code is not None and 200 <= int(status_code) < 400:
                self.successful += 1
                self._increment_adapter(phase, "successful")
            self._event("completed", phase=phase, url=url, status_code=status_code)

    def record_unmetered_tool(self, *, tool: str, target_url: Any = None) -> None:
        with self._lock:
            self.unmetered_tool_invocations += 1
            if self.enforcing:
                self.rejected += 1
                self._increment_adapter(tool, "rejected")
                self._event("rejected_unmetered_tool", phase=tool, url=target_url)
                raise RequestBudgetExceeded(
                    f"unmetered network tool '{tool}' is disabled in enforcing request-budget mode"
                )
            self._event("observed_unmetered_tool", phase=tool, url=target_url)

    def _increment_adapter(self, phase: Any, field: str) -> None:
        name = str(phase or "unknown").strip()[:100] or "unknown"
        counters = self.adapter_usage.setdefault(name, {
            "attempted": 0,
            "completed": 0,
            "retried": 0,
            "rejected": 0,
            "successful": 0,
        })
        counters[field] = int(counters.get(field) or 0) + 1

    def _event(self, event: str, *, phase: str, url: Any, **extra: Any) -> None:
        parsed = urllib.parse.urlparse(str(url or ""))
        self.events.append({
            "event": event,
            "phase": str(phase)[:100],
            "host": (parsed.hostname or "")[:253] or None,
            "path": (parsed.path or "/")[:500],
            **extra,
        })
        if len(self.events) > 100:
            del self.events[:-100]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            limit_exceeded = self.limit is not None and self.attempted > self.limit
            return {
                "schema_version": REQUEST_METER_SCHEMA_V1,
                "mode": self.mode,
                "target_host": self.target_host,
                "allowed_http_methods": sorted(self.allowed_methods),
                "allowed_origins": sorted(self.allowed_origins),
                "allowed_addresses": sorted(self.allowed_addresses),
                "destination_scope_required": self.require_destination_scope,
                "planned_requests": self.planned,
                "reserved_requests": self.reserved,
                "state_changing_request_limit": self.state_changing_limit,
                "request_limit": self.limit,
                "attempted_requests": self.attempted,
                "state_changing_attempted_requests": self.state_changing_attempted,
                "state_changing_rejected_requests": self.state_changing_rejected,
                "completed_requests": self.completed,
                "retried_requests": self.retried,
                "rejected_requests": self.rejected,
                "method_rejected_requests": self.method_rejected,
                "destination_rejected_requests": self.destination_rejected,
                "successful_requests": self.successful,
                "remaining_requests": (
                    None if self.limit is None else max(0, self.limit - self.attempted)
                ),
                "budget_exhausted": self.exhausted,
                "limit_exceeded": limit_exceeded,
                "unmetered_tool_invocations": self.unmetered_tool_invocations,
                "fully_metered": self.unmetered_tool_invocations == 0,
                "adapter_usage": {
                    name: dict(counters)
                    for name, counters in sorted(self.adapter_usage.items())
                },
                "events": list(self.events),
            }


_default_request_meter = RequestMeter(limit=None, target_host=None, mode="off")
_request_meter_context: contextvars.ContextVar[RequestMeter | None] = contextvars.ContextVar(
    "shakerscan_request_meter",
    default=None,
)


def configure_request_meter(**kwargs: Any) -> RequestMeter:
    meter = RequestMeter(**kwargs)
    _request_meter_context.set(meter)
    return meter


def get_request_meter() -> RequestMeter:
    return _request_meter_context.get() or _default_request_meter


def install_async_client_metering() -> dict[str, bool]:
    """Install process-wide hooks once; wrappers read the current meter per call."""
    installed = {
        "httpx": False,
        "aiohttp": False,
        "requests": False,
        "urllib": False,
        "playwright": False,
    }
    try:
        import httpx

        original = httpx.AsyncClient.request
        if not getattr(original, "_shakerscan_request_meter", False):
            async def metered_httpx_request(self, method, url, *args, **kwargs):
                meter = get_request_meter()
                metered = meter.before_request(
                    phase="httpx",
                    url=url,
                    method=method,
                    retry=bool(kwargs.pop("_shakerscan_retry", False)),
                )
                if metered and meter.enforcing:
                    kwargs["follow_redirects"] = False
                try:
                    response = await original(self, method, url, *args, **kwargs)
                except Exception:
                    if metered:
                        meter.record_completion(phase="httpx", url=url)
                    raise
                if metered:
                    meter.record_completion(
                        phase="httpx", url=url, status_code=getattr(response, "status_code", None)
                    )
                return response

            metered_httpx_request._shakerscan_request_meter = True
            httpx.AsyncClient.request = metered_httpx_request
        installed["httpx"] = True
    except ImportError:
        pass

    try:
        import aiohttp

        original_aiohttp = aiohttp.ClientSession._request
        if not getattr(original_aiohttp, "_shakerscan_request_meter", False):
            async def metered_aiohttp_request(self, method, str_or_url, *args, **kwargs):
                meter = get_request_meter()
                metered = meter.before_request(
                    phase="aiohttp", url=str_or_url, method=method,
                )
                if metered and meter.enforcing:
                    kwargs["allow_redirects"] = False
                try:
                    response = await original_aiohttp(self, method, str_or_url, *args, **kwargs)
                except Exception:
                    if metered:
                        meter.record_completion(phase="aiohttp", url=str_or_url)
                    raise
                if metered:
                    meter.record_completion(
                        phase="aiohttp", url=str_or_url, status_code=getattr(response, "status", None)
                    )
                return response

            metered_aiohttp_request._shakerscan_request_meter = True
            aiohttp.ClientSession._request = metered_aiohttp_request
        installed["aiohttp"] = True
    except ImportError:
        pass

    try:
        import requests

        original_requests = requests.sessions.Session.request
        if not getattr(original_requests, "_shakerscan_request_meter", False):
            def metered_requests_request(self, method, url, *args, **kwargs):
                meter = get_request_meter()
                metered = meter.before_request(
                    phase="requests", url=url, method=method,
                )
                if metered and meter.enforcing:
                    kwargs["allow_redirects"] = False
                response = None
                try:
                    response = original_requests(self, method, url, *args, **kwargs)
                    return response
                finally:
                    if metered:
                        status = getattr(response, "status_code", None) if response is not None else None
                        meter.record_completion(phase="requests", url=url, status_code=status)

            metered_requests_request._shakerscan_request_meter = True
            requests.sessions.Session.request = metered_requests_request
        installed["requests"] = True
    except ImportError:
        pass

    try:
        original_urlopen = urllib.request.OpenerDirector.open
        if not getattr(original_urlopen, "_shakerscan_request_meter", False):
            def metered_urlopen(self, fullurl, *args, **kwargs):
                url = getattr(fullurl, "full_url", fullurl)
                method = fullurl.get_method() if isinstance(fullurl, urllib.request.Request) else "GET"
                meter = get_request_meter()
                metered = meter.before_request(phase="urllib", url=url, method=method)
                response = None
                try:
                    response = original_urlopen(self, fullurl, *args, **kwargs)
                    return response
                finally:
                    if metered:
                        status = getattr(response, "status", None) if response is not None else None
                        meter.record_completion(phase="urllib", url=url, status_code=status)

            metered_urlopen._shakerscan_request_meter = True
            urllib.request.OpenerDirector.open = metered_urlopen
        installed["urllib"] = True
    except ImportError:
        pass

    try:
        from playwright.async_api import BrowserContext

        original_new_page = BrowserContext.new_page
        if not getattr(original_new_page, "_shakerscan_request_meter", False):
            async def metered_new_page(self, *args, **kwargs):
                page = await original_new_page(self, *args, **kwargs)

                async def meter_route(route, request):
                    meter = get_request_meter()
                    try:
                        meter.before_request(
                            phase="browser", url=request.url, method=request.method,
                        )
                    except RequestBudgetExceeded:
                        await route.abort("blockedbyclient")
                        return
                    # A page route runs before BrowserContext routes.  Fall through
                    # after metering so context-level scope and passive-method
                    # guards still get the request; continue_() would bypass them.
                    await route.fallback()

                def meter_response(response):
                    get_request_meter().record_completion(
                        phase="browser", url=response.url, status_code=response.status
                    )

                def meter_failure(request):
                    get_request_meter().record_completion(phase="browser", url=request.url)

                await page.route("**/*", meter_route)
                page.on("response", meter_response)
                page.on("requestfailed", meter_failure)
                return page

            metered_new_page._shakerscan_request_meter = True
            BrowserContext.new_page = metered_new_page
        installed["playwright"] = True
    except ImportError:
        pass
    return installed
