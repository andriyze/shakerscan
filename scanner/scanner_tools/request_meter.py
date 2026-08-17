"""Process-local outbound request accounting for standalone scanner runs."""

from __future__ import annotations

import contextvars
import threading
import urllib.parse
from typing import Any


REQUEST_METER_SCHEMA_V1 = "request_meter_v1"
REQUEST_BUDGET_MODES = frozenset({"off", "compatibility", "enforce"})


class RequestBudgetExceeded(RuntimeError):
    pass


class RequestMeter:
    def __init__(
        self,
        *,
        limit: int | None,
        target_host: str | None,
        mode: str,
        planned: int = 0,
        reserved: int = 0,
    ) -> None:
        normalized_mode = str(mode or "compatibility").strip().lower()
        self.mode = normalized_mode if normalized_mode in REQUEST_BUDGET_MODES else "compatibility"
        self.limit = max(0, int(limit)) if limit is not None else None
        self.target_host = str(target_host or "").strip().lower()
        self.planned = max(0, int(planned or 0))
        self.reserved = max(0, int(reserved or 0))
        self.attempted = 0
        self.completed = 0
        self.retried = 0
        self.rejected = 0
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

    def applies_to(self, url: Any) -> bool:
        if self.mode == "off":
            return False
        try:
            host = (urllib.parse.urlparse(str(url)).hostname or "").lower()
        except Exception:
            return False
        if not host or not self.target_host:
            return False
        return host == self.target_host or host.endswith(f".{self.target_host}")

    def before_request(self, *, phase: str, url: Any, retry: bool = False) -> bool:
        if not self.applies_to(url):
            return False
        with self._lock:
            if self.enforcing and self.exhausted:
                self.rejected += 1
                self._increment_adapter(phase, "rejected")
                self._event("rejected", phase=phase, url=url, retry=retry)
                raise RequestBudgetExceeded(
                    f"request budget exhausted before {phase} ({self.attempted}/{self.limit})"
                )
            self.attempted += 1
            self._increment_adapter(phase, "attempted")
            if retry:
                self.retried += 1
                self._increment_adapter(phase, "retried")
            self._event("attempted", phase=phase, url=url, retry=retry)
        return True

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
                "planned_requests": self.planned,
                "reserved_requests": self.reserved,
                "request_limit": self.limit,
                "attempted_requests": self.attempted,
                "completed_requests": self.completed,
                "retried_requests": self.retried,
                "rejected_requests": self.rejected,
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
    installed = {"httpx": False, "aiohttp": False, "urllib": False, "playwright": False}
    try:
        import httpx

        original = httpx.AsyncClient.request
        if not getattr(original, "_shakerscan_request_meter", False):
            async def metered_httpx_request(self, method, url, *args, **kwargs):
                meter = get_request_meter()
                metered = meter.before_request(
                    phase="httpx",
                    url=url,
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
                metered = meter.before_request(phase="aiohttp", url=str_or_url)
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
        import urllib.request

        original_urlopen = urllib.request.OpenerDirector.open
        if not getattr(original_urlopen, "_shakerscan_request_meter", False):
            def metered_urlopen(self, fullurl, *args, **kwargs):
                url = getattr(fullurl, "full_url", fullurl)
                meter = get_request_meter()
                metered = meter.before_request(phase="urllib", url=url)
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
                        meter.before_request(phase="browser", url=request.url)
                    except RequestBudgetExceeded:
                        await route.abort("blockedbyclient")
                        return
                    await route.continue_()

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
