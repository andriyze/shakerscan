"""Target-bound, read-only browser navigation for canonical Hunt execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import math
import re
import time
from typing import Any, Mapping
import urllib.parse

try:
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from runtime.models import PreparedExecution, TargetBinding
except ModuleNotFoundError:  # package imports in host-side tests
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..runtime.models import PreparedExecution, TargetBinding


SAFE_BROWSER_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BROWSER_RESPONSE_OBSERVATIONS = 200
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")


class BrowserCapabilityInputError(ValueError):
    pass


def _origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise BrowserCapabilityInputError("browser target origin is invalid")
    if parsed.username or parsed.password:
        raise BrowserCapabilityInputError("browser target origin must not contain userinfo")
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), "", "", "")
    )


def _origin_key(value: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise BrowserCapabilityInputError("browser URL is invalid")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise BrowserCapabilityInputError("browser URL port is invalid") from exc
    return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port


def _redacted_path(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    names = [
        str(name)[:100]
        for name, _item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)[:50]
    ]
    query = urllib.parse.urlencode([(name, "<redacted>") for name in names])
    return urllib.parse.urlunsplit(("", "", parsed.path or "/", query, ""))


@dataclass(frozen=True)
class PreparedBrowserNavigation:
    capability_name: str
    adapter_name: str
    adapter_version: str
    parser_version: str
    target: TargetBinding
    url: str
    origin: str
    pinned_address: str
    wait_until: str
    timeout_ms: int
    max_requests: int
    input_digest: str
    estimated_budget: Mapping[str, int]
    redacted_execution: Mapping[str, Any]


class BrowserNavigateAdapter:
    capability_name = "browser.navigate"
    adapter_name = "playwright"
    adapter_version = "1"
    parser_version = "browser-navigation/v1"

    def __init__(self, prepared: PreparedBrowserNavigation):
        self.prepared = prepared

    @classmethod
    def prepare(
        cls,
        *,
        target: TargetBinding,
        base_url: str,
        args: Mapping[str, Any],
    ) -> PreparedBrowserNavigation:
        allowed_fields = {"path", "wait_until", "timeout_ms", "max_requests"}
        unknown_fields = sorted(str(key) for key in set(args) - allowed_fields)
        if unknown_fields:
            raise BrowserCapabilityInputError(
                f"unsupported browser input fields: {', '.join(unknown_fields)}"
            )
        if target.target_kind not in {"web", "api"}:
            raise BrowserCapabilityInputError(
                "browser navigation supports only web and API targets"
            )
        base_origin = _origin(base_url)
        if base_origin not in target.allowed_origins:
            raise BrowserCapabilityInputError(
                "browser origin is not present in the target binding"
            )
        if _origin_key(base_origin)[1] != target.canonical_host:
            raise BrowserCapabilityInputError(
                "browser origin host does not match the target binding"
            )
        raw_path = args.get("path", "/")
        if not isinstance(raw_path, str):
            raise BrowserCapabilityInputError("browser path must be a string")
        path = raw_path.strip() or "/"
        if (
            not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or len(path) > 2_000
            or _CONTROL_CHARACTER.search(path)
        ):
            raise BrowserCapabilityInputError(
                "browser path must be a bounded same-origin absolute path"
            )
        parsed_path = urllib.parse.urlsplit(path)
        if parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
            raise BrowserCapabilityInputError(
                "browser path must not contain an origin or fragment"
            )
        raw_wait_until = args.get("wait_until", "domcontentloaded")
        if not isinstance(raw_wait_until, str):
            raise BrowserCapabilityInputError("wait_until must be a string")
        wait_until = raw_wait_until.strip().lower() or "domcontentloaded"
        if wait_until not in {"domcontentloaded", "load"}:
            raise BrowserCapabilityInputError(
                "wait_until must be domcontentloaded or load"
            )
        raw_timeout_ms = args.get("timeout_ms", 20_000)
        raw_max_requests = args.get("max_requests", 25)
        if (
            isinstance(raw_timeout_ms, bool)
            or not isinstance(raw_timeout_ms, int)
            or isinstance(raw_max_requests, bool)
            or not isinstance(raw_max_requests, int)
        ):
            raise BrowserCapabilityInputError(
                "browser timeout and request limit must be integers"
            )
        timeout_ms = raw_timeout_ms
        max_requests = raw_max_requests
        if not 1_000 <= timeout_ms <= 30_000:
            raise BrowserCapabilityInputError(
                "browser timeout_ms must be between 1000 and 30000"
            )
        if not 1 <= max_requests <= 50:
            raise BrowserCapabilityInputError(
                "browser max_requests must be between 1 and 50"
            )
        if not target.allowed_addresses:
            raise BrowserCapabilityInputError(
                "browser target binding has no frozen runtime address"
            )
        pinned_address = str(ipaddress.ip_address(target.allowed_addresses[0]))
        if _is_ip_literal(target.canonical_host) and str(
            ipaddress.ip_address(str(target.canonical_host))
        ) != pinned_address:
            raise BrowserCapabilityInputError(
                "browser IP target does not match its frozen runtime address"
            )
        url = urllib.parse.urljoin(f"{base_origin}/", path.lstrip("/"))
        if _origin_key(url) != _origin_key(base_origin):
            raise BrowserCapabilityInputError("browser URL escaped the target origin")
        normalized = {
            "target_id": target.target_id,
            "target_kind": target.target_kind,
            "origin": base_origin,
            "path": path,
            "pinned_address": pinned_address,
            "wait_until": wait_until,
            "timeout_ms": timeout_ms,
            "max_requests": max_requests,
        }
        return PreparedBrowserNavigation(
            capability_name=cls.capability_name,
            adapter_name=cls.adapter_name,
            adapter_version=cls.adapter_version,
            parser_version=cls.parser_version,
            target=target,
            url=url,
            origin=base_origin,
            pinned_address=pinned_address,
            wait_until=wait_until,
            timeout_ms=timeout_ms,
            max_requests=max_requests,
            input_digest=PreparedExecution.digest_input(normalized),
            estimated_budget={
                "browser_actions": 1,
                "http_requests": max_requests,
                "tool_wall_seconds": max(1, math.ceil(timeout_ms / 1_000)),
            },
            redacted_execution={
                "origin": base_origin,
                "path": _redacted_path(path),
                "pinned_address": pinned_address,
                "wait_until": wait_until,
                "max_requests": max_requests,
                "read_only_requests_only": True,
            },
        )

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        prepared = self.prepared
        started = time.monotonic()
        request_count = 0
        blocked: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        browser_started = False
        playwright = None
        browser = None
        context = None
        try:
            from playwright.async_api import TimeoutError as PlaywrightTimeoutError
            from playwright.async_api import async_playwright
        except ImportError:
            return CapabilityAdapterResult(
                status="failed",
                errors=("playwright_unavailable",),
                actual_budget={},
                parser_version=self.parser_version,
                redacted_execution=prepared.redacted_execution,
            )
        try:
            if cancelled():
                return CapabilityAdapterResult(
                    status="cancelled",
                    errors=("cancelled_before_browser_start",),
                    actual_budget={},
                    parser_version=self.parser_version,
                    redacted_execution=prepared.redacted_execution,
                )
            playwright = await async_playwright().start()
            mapped = (
                f"[{prepared.pinned_address}]"
                if ":" in prepared.pinned_address
                else prepared.pinned_address
            )
            resolver_args = []
            if not _is_ip_literal(prepared.target.canonical_host):
                resolver_args.append(
                    f"--host-resolver-rules=MAP {prepared.target.canonical_host} {mapped}"
                )
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    *resolver_args,
                ],
            )
            browser_started = True
            context = await browser.new_context(
                accept_downloads=False,
                ignore_https_errors=True,
                service_workers="block",
            )
            await context.add_init_script(
                "window.WebSocket = class { constructor() { throw new Error('blocked'); } };"
                "window.EventSource = class { constructor() { throw new Error('blocked'); } };"
            )
            page = await context.new_page()

            async def route_request(route) -> None:
                nonlocal request_count
                request = route.request
                reason = None
                if cancelled():
                    reason = "cancelled"
                else:
                    try:
                        same_origin = _origin_key(request.url) == _origin_key(prepared.origin)
                    except BrowserCapabilityInputError:
                        same_origin = False
                    if not same_origin:
                        reason = "cross_origin"
                    elif request.method.upper() not in SAFE_BROWSER_METHODS:
                        reason = "state_changing_method"
                    elif request_count >= prepared.max_requests:
                        reason = "request_budget_exhausted"
                if reason:
                    if len(blocked) < MAX_BROWSER_RESPONSE_OBSERVATIONS:
                        blocked.append({
                            "kind": "browser_request_blocked",
                            "reason": reason,
                            "method": request.method.upper(),
                            "url": _observation_url(request.url),
                        })
                    await route.abort("blockedbyclient")
                    return
                request_count += 1
                await route.continue_()

            async def record_response(response) -> None:
                if len(responses) >= MAX_BROWSER_RESPONSE_OBSERVATIONS:
                    return
                try:
                    if _origin_key(response.url) != _origin_key(prepared.origin):
                        return
                    responses.append({
                        "kind": "browser_http_response",
                        "method": response.request.method.upper(),
                        "url": _observation_url(response.url),
                        "status_code": int(response.status),
                        "content_type": str(response.headers.get("content-type") or "")[:200],
                    })
                except Exception:
                    return

            await page.route("**/*", route_request)
            page.on("response", record_response)
            navigation = asyncio.create_task(page.goto(
                prepared.url,
                wait_until=prepared.wait_until,
                timeout=prepared.timeout_ms,
            ))
            loop = asyncio.get_running_loop()
            next_heartbeat = loop.time() + 5.0
            while not navigation.done():
                if cancelled():
                    navigation.cancel()
                    await asyncio.gather(navigation, return_exceptions=True)
                    return _browser_result(
                        prepared,
                        status="cancelled",
                        request_count=request_count,
                        started=started,
                        browser_started=browser_started,
                        observations=responses,
                        blocked=blocked,
                        errors=("cancelled",),
                    )
                if loop.time() >= next_heartbeat:
                    await heartbeat()
                    next_heartbeat = loop.time() + 5.0
                await asyncio.wait({navigation}, timeout=0.1)
            response = await navigation
            await heartbeat()
            if _origin_key(page.url) != _origin_key(prepared.origin):
                return _browser_result(
                    prepared,
                    status="blocked",
                    request_count=request_count,
                    started=started,
                    browser_started=browser_started,
                    observations=responses,
                    blocked=blocked,
                    errors=("final_url_outside_target_origin",),
                )
            main = {
                "kind": "browser_navigation",
                "url": _observation_url(page.url),
                "status_code": int(response.status) if response is not None else None,
                "same_origin": True,
                "read_only_requests_only": True,
                "request_count": request_count,
                "blocked_request_count": len(blocked),
            }
            return _browser_result(
                prepared,
                status="partial" if blocked else "success",
                request_count=request_count,
                started=started,
                browser_started=browser_started,
                observations=[main, *responses],
                blocked=blocked,
                errors=("browser_requests_blocked",) if blocked else (),
            )
        except PlaywrightTimeoutError:
            return _browser_result(
                prepared,
                status="partial",
                request_count=request_count,
                started=started,
                browser_started=browser_started,
                observations=responses,
                blocked=blocked,
                errors=("browser_navigation_timeout",),
                timed_out=True,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return _browser_result(
                prepared,
                status="failed",
                request_count=request_count,
                started=started,
                browser_started=browser_started,
                observations=responses,
                blocked=blocked,
                errors=(f"browser_navigation:{type(exc).__name__}",),
            )
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    await browser.close()
                except Exception:
                    pass
            if playwright is not None:
                try:
                    await playwright.stop()
                except Exception:
                    pass


def _is_ip_literal(value: str | None) -> bool:
    try:
        ipaddress.ip_address(str(value or ""))
        return True
    except ValueError:
        return False


def _observation_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or ""))
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", "")
    )[:2_000]


def _browser_result(
    prepared: PreparedBrowserNavigation,
    *,
    status: str,
    request_count: int,
    started: float,
    browser_started: bool,
    observations: list[Mapping[str, Any]],
    blocked: list[Mapping[str, Any]],
    errors: tuple[str, ...],
    timed_out: bool = False,
) -> CapabilityAdapterResult:
    partial = status == "partial"
    elapsed = max(0, math.ceil(time.monotonic() - started))
    return CapabilityAdapterResult(
        status=status,
        observations=tuple([*observations, *blocked][
            :MAX_BROWSER_RESPONSE_OBSERVATIONS
        ]),
        errors=errors,
        actual_budget={
            "browser_actions": 1 if browser_started else 0,
            "http_requests": request_count,
            "tool_wall_seconds": elapsed,
        },
        partial=partial,
        timed_out=timed_out,
        execution_started=browser_started,
        parser_version=prepared.parser_version,
        redacted_execution=prepared.redacted_execution,
    )
