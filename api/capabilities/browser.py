"""Target-bound, read-only browser actions for canonical Hunt execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import ipaddress
import math
import re
import time
from typing import Any, Mapping
import urllib.parse

try:
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from pinned_socks_proxy import PinnedSocksProxy
    from runtime.models import PreparedExecution, TargetBinding
    from runtime.secret_material import contains_secret_material
    from runtime.target_bound_socket import FrozenTargetSocketFactory
except ModuleNotFoundError:  # package imports in host-side tests
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..pinned_socks_proxy import PinnedSocksProxy
    from ..runtime.models import PreparedExecution, TargetBinding
    from ..runtime.secret_material import contains_secret_material
    from ..runtime.target_bound_socket import FrozenTargetSocketFactory

try:
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:  # package imports in host-side tests
    from scanner.scanner_tools.url_redaction import redact_url


SAFE_BROWSER_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BROWSER_RESPONSE_OBSERVATIONS = 200
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_CSS_SELECTOR = re.compile(r"^[A-Za-z0-9_.#\-\[\]=:'\" ()>+~,*^$|]+$")
_DANGEROUS_INTERACTION = re.compile(
    r"(?:^|[^a-z0-9])(?:"
    r"approve|buy|checkout|confirm|create|delete|destroy|disable|enable|execute|"
    r"invite|log[ -]?out|pay|purchase|remove|reset|revoke|save|send|sign[ -]?out|"
    r"start|stop|submit|terminate|transfer|upload"
    r")(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)


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
    return redact_url(value, max_length=2_000)


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


@dataclass(frozen=True)
class PreparedBrowserInteraction:
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
    selector: str
    selector_digest: str
    settle_ms: int
    input_digest: str
    estimated_budget: Mapping[str, int]
    redacted_execution: Mapping[str, Any]


PreparedBrowserAction = PreparedBrowserNavigation | PreparedBrowserInteraction


def _prepare_browser_base(
    *,
    target: TargetBinding,
    base_url: str,
    args: Mapping[str, Any],
    allowed_fields: set[str],
) -> dict[str, Any]:
    unknown_fields = sorted(str(key) for key in set(args) - allowed_fields)
    if unknown_fields:
        raise BrowserCapabilityInputError(
            f"unsupported browser input fields: {', '.join(unknown_fields)}"
        )
    if target.target_kind not in {"web", "api"}:
        raise BrowserCapabilityInputError(
            "browser actions support only web and API targets"
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
    query_pairs = urllib.parse.parse_qsl(
        parsed_path.query, keep_blank_values=True, max_num_fields=50,
    )
    if contains_secret_material(dict(query_pairs)) or contains_secret_material(path):
        raise BrowserCapabilityInputError(
            "browser input contains raw secret material; use a managed credential reference"
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
    parsed_origin = urllib.parse.urlsplit(base_origin)
    socket_factory = FrozenTargetSocketFactory(
        hostname=target.canonical_host,
        port=parsed_origin.port or (
            443 if parsed_origin.scheme.lower() == "https" else 80
        ),
        frozen_addresses=target.allowed_addresses,
    )
    pinned_address = socket_factory.primary_address
    if _is_ip_literal(target.canonical_host) and str(
        ipaddress.ip_address(str(target.canonical_host))
    ) != pinned_address:
        raise BrowserCapabilityInputError(
            "browser IP target does not match its frozen runtime address"
        )
    url = urllib.parse.urljoin(f"{base_origin}/", path.lstrip("/"))
    if _origin_key(url) != _origin_key(base_origin):
        raise BrowserCapabilityInputError("browser URL escaped the target origin")
    return {
        "target": target,
        "url": url,
        "origin": base_origin,
        "path": path,
        "pinned_address": pinned_address,
        "wait_until": wait_until,
        "timeout_ms": timeout_ms,
        "max_requests": max_requests,
        "address_policy": socket_factory.policy_receipt,
    }


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
        common = _prepare_browser_base(
            target=target,
            base_url=base_url,
            args=args,
            allowed_fields={"path", "wait_until", "timeout_ms", "max_requests"},
        )
        normalized = {
            "target_id": target.target_id,
            "target_kind": target.target_kind,
            "origin": common["origin"],
            "path": common["path"],
            "pinned_address": common["pinned_address"],
            "wait_until": common["wait_until"],
            "timeout_ms": common["timeout_ms"],
            "max_requests": common["max_requests"],
        }
        return PreparedBrowserNavigation(
            capability_name=cls.capability_name,
            adapter_name=cls.adapter_name,
            adapter_version=cls.adapter_version,
            parser_version=cls.parser_version,
            target=target,
            url=common["url"],
            origin=common["origin"],
            pinned_address=common["pinned_address"],
            wait_until=common["wait_until"],
            timeout_ms=common["timeout_ms"],
            max_requests=common["max_requests"],
            input_digest=PreparedExecution.digest_input(normalized),
            estimated_budget={
                "browser_actions": 1,
                "http_requests": common["max_requests"],
                "tool_wall_seconds": max(
                    1, math.ceil(common["timeout_ms"] / 1_000)
                ),
            },
            redacted_execution={
                "origin": common["origin"],
                "path": _redacted_path(common["path"]),
                "pinned_address": common["pinned_address"],
                "address_policy": common["address_policy"],
                "wait_until": common["wait_until"],
                "max_requests": common["max_requests"],
                "read_only_requests_only": True,
            },
        )

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        return await _execute_browser_action(
            self.prepared,
            heartbeat=heartbeat,
            cancelled=cancelled,
        )


class BrowserInteractAdapter:
    capability_name = "browser.interact"
    adapter_name = "playwright"
    adapter_version = "1"
    parser_version = "browser-interaction/v1"

    def __init__(self, prepared: PreparedBrowserInteraction):
        self.prepared = prepared

    @classmethod
    def prepare(
        cls,
        *,
        target: TargetBinding,
        base_url: str,
        args: Mapping[str, Any],
    ) -> PreparedBrowserInteraction:
        common = _prepare_browser_base(
            target=target,
            base_url=base_url,
            args=args,
            allowed_fields={
                "path", "selector", "wait_until", "timeout_ms",
                "max_requests", "settle_ms",
            },
        )
        raw_selector = args.get("selector")
        if not isinstance(raw_selector, str):
            raise BrowserCapabilityInputError("browser selector must be a string")
        selector = raw_selector.strip()
        lowered_selector = selector.lower()
        if (
            not selector
            or len(selector) > 500
            or _CONTROL_CHARACTER.search(selector)
            or not _SAFE_CSS_SELECTOR.fullmatch(selector)
            or ">>" in selector
            or lowered_selector.startswith(("xpath=", "text="))
            or ":has-text" in lowered_selector
            or ":text" in lowered_selector
            or contains_secret_material(selector)
        ):
            raise BrowserCapabilityInputError(
                "browser selector must be a bounded CSS selector without secret material"
            )
        raw_settle_ms = args.get("settle_ms", 500)
        if isinstance(raw_settle_ms, bool) or not isinstance(raw_settle_ms, int):
            raise BrowserCapabilityInputError("browser settle_ms must be an integer")
        settle_ms = raw_settle_ms
        if not 0 <= settle_ms <= 2_000:
            raise BrowserCapabilityInputError(
                "browser settle_ms must be between 0 and 2000"
            )
        selector_digest = hashlib.sha256(selector.encode("utf-8")).hexdigest()
        normalized = {
            "target_id": target.target_id,
            "target_kind": target.target_kind,
            "origin": common["origin"],
            "path": common["path"],
            "pinned_address": common["pinned_address"],
            "wait_until": common["wait_until"],
            "timeout_ms": common["timeout_ms"],
            "max_requests": common["max_requests"],
            "selector": selector,
            "settle_ms": settle_ms,
        }
        return PreparedBrowserInteraction(
            capability_name=cls.capability_name,
            adapter_name=cls.adapter_name,
            adapter_version=cls.adapter_version,
            parser_version=cls.parser_version,
            target=target,
            url=common["url"],
            origin=common["origin"],
            pinned_address=common["pinned_address"],
            wait_until=common["wait_until"],
            timeout_ms=common["timeout_ms"],
            max_requests=common["max_requests"],
            selector=selector,
            selector_digest=selector_digest,
            settle_ms=settle_ms,
            input_digest=PreparedExecution.digest_input(normalized),
            estimated_budget={
                "browser_actions": 2,
                "http_requests": common["max_requests"],
                "tool_wall_seconds": max(
                    1, math.ceil(common["timeout_ms"] / 1_000)
                ),
            },
            redacted_execution={
                "origin": common["origin"],
                "path": _redacted_path(common["path"]),
                "pinned_address": common["pinned_address"],
                "address_policy": common["address_policy"],
                "wait_until": common["wait_until"],
                "max_requests": common["max_requests"],
                "selector_sha256": selector_digest,
                "settle_ms": settle_ms,
                "interaction": "click",
                "read_only_requests_only": True,
            },
        )

    async def execute(
        self,
        *,
        heartbeat: Heartbeat,
        cancelled: Cancelled,
    ) -> CapabilityAdapterResult:
        return await _execute_browser_action(
            self.prepared,
            heartbeat=heartbeat,
            cancelled=cancelled,
        )


def browser_capability_adapter(name: str):
    adapters = {
        BrowserNavigateAdapter.capability_name: BrowserNavigateAdapter,
        BrowserInteractAdapter.capability_name: BrowserInteractAdapter,
    }
    normalized = str(name or "").strip().lower()
    if normalized not in adapters:
        raise BrowserCapabilityInputError(
            f"unsupported browser capability: {normalized or '<empty>'}"
        )
    return adapters[normalized]


async def _execute_browser_action(
    prepared: PreparedBrowserAction,
    *,
    heartbeat: Heartbeat,
    cancelled: Cancelled,
) -> CapabilityAdapterResult:
    started = time.monotonic()
    request_count = 0
    browser_actions = 0
    blocked: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    playwright = None
    browser = None
    context = None
    pinned_proxy = None
    try:
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
        from playwright.async_api import async_playwright
    except ImportError:
        return CapabilityAdapterResult(
            status="failed",
            errors=("playwright_unavailable",),
            actual_budget={},
            parser_version=prepared.parser_version,
            redacted_execution=prepared.redacted_execution,
        )

    async def await_task(task: asyncio.Task[Any]) -> tuple[bool, Any]:
        loop = asyncio.get_running_loop()
        next_heartbeat = loop.time() + 5.0
        while not task.done():
            if cancelled():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return False, None
            if loop.time() >= next_heartbeat:
                await heartbeat()
                next_heartbeat = loop.time() + 5.0
            await asyncio.wait({task}, timeout=0.1)
        return True, await task

    try:
        if cancelled():
            return CapabilityAdapterResult(
                status="cancelled",
                errors=("cancelled_before_browser_start",),
                actual_budget={},
                parser_version=prepared.parser_version,
                redacted_execution=prepared.redacted_execution,
            )
        parsed_origin = urllib.parse.urlsplit(prepared.origin)
        pinned_proxy = await PinnedSocksProxy(
            hostname=prepared.target.canonical_host,
            pinned_addresses=prepared.target.allowed_addresses,
            port=parsed_origin.port or (
                443 if parsed_origin.scheme.lower() == "https" else 80
            ),
            max_connections=prepared.max_requests,
        ).start()
        responses.append({
            "kind": "browser_target_transport",
            "address_policy": pinned_proxy.socket_factory.policy_receipt,
            "address_attempts": pinned_proxy.address_attempts,
            "address_connections": pinned_proxy.address_connections,
            "hostname_preserved": True,
            "runtime_dns_resolution": False,
        })
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(
            headless=True,
            proxy={"server": pinned_proxy.proxy_url},
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-background-networking",
                "--dns-prefetch-disable",
                "--disable-features=Prerender2,SpeculationRulesPrefetch,UseDnsHttpsSvcbAlpn",
                "--proxy-bypass-list=<-loopback>",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1",
            ],
        )
        context = await browser.new_context(
            accept_downloads=False,
            ignore_https_errors=True,
            service_workers="block",
        )
        await context.add_init_script(
            "window.WebSocket = class { constructor() { throw new Error('blocked'); } };"
            "window.EventSource = class { constructor() { throw new Error('blocked'); } };"
            "window.open = () => { throw new Error('blocked'); };"
            "navigator.sendBeacon = () => false;"
        )

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
                    "content_type": _safe_content_type(
                        response.headers.get("content-type")
                    ),
                })
            except Exception:
                return

        await context.route("**/*", route_request)
        context.on("response", record_response)
        page = await context.new_page()
        browser_actions = 1
        navigation = asyncio.create_task(page.goto(
            prepared.url,
            wait_until=prepared.wait_until,
            timeout=prepared.timeout_ms,
        ))
        completed, response = await await_task(navigation)
        if not completed:
            return _browser_result(
                prepared,
                status="cancelled",
                request_count=request_count,
                browser_actions=browser_actions,
                started=started,
                observations=responses,
                blocked=blocked,
                errors=("cancelled",),
            )
        await heartbeat()
        if _origin_key(page.url) != _origin_key(prepared.origin):
            return _browser_result(
                prepared,
                status="blocked",
                request_count=request_count,
                browser_actions=browser_actions,
                started=started,
                observations=responses,
                blocked=blocked,
                errors=("final_url_outside_target_origin",),
            )
        navigation_observation = {
            "kind": "browser_navigation",
            "url": _observation_url(page.url),
            "status_code": int(response.status) if response is not None else None,
            "same_origin": True,
            "read_only_requests_only": True,
            "request_count": request_count,
            "blocked_request_count": len(blocked),
        }
        if isinstance(prepared, PreparedBrowserInteraction):
            locator = page.locator(prepared.selector)
            match_count = await locator.count()
            if match_count != 1:
                return _browser_result(
                    prepared,
                    status="blocked",
                    request_count=request_count,
                    browser_actions=browser_actions,
                    started=started,
                    observations=[navigation_observation, *responses],
                    blocked=blocked,
                    errors=(
                        "browser_selector_not_found"
                        if match_count == 0
                        else "browser_selector_ambiguous",
                    ),
                )
            element = await locator.evaluate(
                """element => ({
                    tag: String(element.tagName || '').toLowerCase(),
                    role: String(element.getAttribute('role') || '').toLowerCase(),
                    type: String(element.getAttribute('type') || '').toLowerCase(),
                    href: String(element.href || ''),
                    target: String(element.getAttribute('target') || '').toLowerCase(),
                    download: element.hasAttribute('download'),
                    semantics: String(
                        element.getAttribute('aria-label') ||
                        element.getAttribute('title') ||
                        element.getAttribute('name') ||
                        element.getAttribute('value') ||
                        element.textContent || ''
                    ).slice(0, 500)
                })"""
            )
            element_kind = _validate_read_only_interaction(prepared, element)
            remaining_ms = prepared.timeout_ms - int(
                (time.monotonic() - started) * 1_000
            )
            if remaining_ms <= 0:
                raise PlaywrightTimeoutError("browser interaction deadline expired")
            browser_actions = 2
            click = asyncio.create_task(locator.click(timeout=remaining_ms))
            completed, _value = await await_task(click)
            if not completed:
                return _browser_result(
                    prepared,
                    status="cancelled",
                    request_count=request_count,
                    browser_actions=browser_actions,
                    started=started,
                    observations=[navigation_observation, *responses],
                    blocked=blocked,
                    errors=("cancelled",),
                )
            remaining_ms = prepared.timeout_ms - int(
                (time.monotonic() - started) * 1_000
            )
            if prepared.settle_ms and remaining_ms > 0:
                await asyncio.sleep(min(prepared.settle_ms, remaining_ms) / 1_000)
            if _origin_key(page.url) != _origin_key(prepared.origin):
                return _browser_result(
                    prepared,
                    status="blocked",
                    request_count=request_count,
                    browser_actions=browser_actions,
                    started=started,
                    observations=[navigation_observation, *responses],
                    blocked=blocked,
                    errors=("interaction_final_url_outside_target_origin",),
                )
            interaction_observation = {
                "kind": "browser_interaction",
                "interaction": "click",
                "selector_sha256": prepared.selector_digest,
                "element_kind": element_kind,
                "url": _observation_url(page.url),
                "same_origin": True,
                "read_only_requests_only": True,
                "request_count": request_count,
                "blocked_request_count": len(blocked),
            }
            return _browser_result(
                prepared,
                status="partial" if blocked else "success",
                request_count=request_count,
                browser_actions=browser_actions,
                started=started,
                observations=[
                    navigation_observation, interaction_observation, *responses,
                ],
                blocked=blocked,
                errors=("browser_requests_blocked",) if blocked else (),
            )
        return _browser_result(
            prepared,
            status="partial" if blocked else "success",
            request_count=request_count,
            browser_actions=browser_actions,
            started=started,
            observations=[navigation_observation, *responses],
            blocked=blocked,
            errors=("browser_requests_blocked",) if blocked else (),
        )
    except PlaywrightTimeoutError:
        return _browser_result(
            prepared,
            status="partial",
            request_count=request_count,
            browser_actions=browser_actions,
            started=started,
            observations=responses,
            blocked=blocked,
            errors=("browser_action_timeout",),
            timed_out=True,
        )
    except BrowserCapabilityInputError as exc:
        return _browser_result(
            prepared,
            status="blocked",
            request_count=request_count,
            browser_actions=browser_actions,
            started=started,
            observations=responses,
            blocked=blocked,
            errors=(str(exc),),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return _browser_result(
            prepared,
            status="failed",
            request_count=request_count,
            browser_actions=browser_actions,
            started=started,
            observations=responses,
            blocked=blocked,
            errors=(f"browser_action:{type(exc).__name__}",),
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
        if pinned_proxy is not None:
            try:
                await pinned_proxy.close()
            except Exception:
                pass


def _validate_read_only_interaction(
    prepared: PreparedBrowserInteraction,
    element: Any,
) -> str:
    if not isinstance(element, Mapping):
        raise BrowserCapabilityInputError("browser interaction element is invalid")
    tag = str(element.get("tag") or "").strip().lower()
    role = str(element.get("role") or "").strip().lower()
    element_type = str(element.get("type") or "").strip().lower()
    href = str(element.get("href") or "").strip()
    target = str(element.get("target") or "").strip().lower()
    semantics = str(element.get("semantics") or "")[:500]
    if bool(element.get("download")) or target not in {"", "_self"}:
        raise BrowserCapabilityInputError("browser interaction is not read-only")
    if _DANGEROUS_INTERACTION.search(" ".join((semantics, href))):
        raise BrowserCapabilityInputError("browser interaction has unsafe semantics")
    if tag in {"a", "area"}:
        if not href:
            raise BrowserCapabilityInputError("browser link has no destination")
        if _origin_key(href) != _origin_key(prepared.origin):
            raise BrowserCapabilityInputError("browser link leaves the target origin")
        parsed = urllib.parse.urlsplit(href)
        try:
            query = dict(urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True, max_num_fields=50,
            ))
        except ValueError as exc:
            raise BrowserCapabilityInputError(
                "browser link query is too large"
            ) from exc
        if parsed.fragment or contains_secret_material(query) or contains_secret_material(href):
            raise BrowserCapabilityInputError("browser link contains unsafe material")
        return "same_origin_link"
    if tag == "summary":
        return "disclosure"
    if role == "tab" and tag in {"button", "div", "li", "span"}:
        if tag == "button" and element_type not in {"", "button"}:
            raise BrowserCapabilityInputError("browser tab button can submit a form")
        return "tab"
    raise BrowserCapabilityInputError(
        "browser interaction must select one same-origin link, disclosure, or tab"
    )


def _is_ip_literal(value: str | None) -> bool:
    try:
        ipaddress.ip_address(str(value or ""))
        return True
    except ValueError:
        return False


def _observation_url(value: str) -> str:
    return redact_url(str(value or ""), max_length=2_000)


def _safe_content_type(value: Any) -> str:
    media_type = str(value or "").split(";", 1)[0].strip().lower()
    if not re.fullmatch(r"[a-z0-9!#$&^_.+\-]+/[a-z0-9!#$&^_.+\-]+", media_type):
        return ""
    return media_type[:127]


def _browser_result(
    prepared: PreparedBrowserAction,
    *,
    status: str,
    request_count: int,
    browser_actions: int,
    started: float,
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
            "browser_actions": browser_actions,
            "http_requests": request_count,
            "tool_wall_seconds": elapsed,
        },
        partial=partial,
        timed_out=timed_out,
        execution_started=browser_actions > 0,
        parser_version=prepared.parser_version,
        redacted_execution=prepared.redacted_execution,
    )
