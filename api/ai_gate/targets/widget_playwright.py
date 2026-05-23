from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ai_gate.budget import CHARS_PER_TOKEN_ESTIMATE
from ai_gate.targets.rest_json import as_dict, build_headers, build_url

try:
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH") and os.path.exists("/ms-playwright"):
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/ms-playwright"
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright
except ModuleNotFoundError:  # pragma: no cover - worker runtime supplies playwright
    async_playwright = None

    class PlaywrightTimeoutError(Exception):
        pass


logger = logging.getLogger(__name__)
MIN_WIDGET_RESPONSE_TIMEOUT_MS = 1_000
MAX_WIDGET_RESPONSE_TIMEOUT_MS = 60_000
MAX_WIDGET_SETTLE_DELAY_MS = 5_000
MAX_WIDGET_NETWORK_EVENTS = 512
DEFAULT_WIDGET_WAIT_FOR_RESPONSE = "new_message"
DEFAULT_BROWSER_SAFETY_POLICY = {
    "safe_mode": "observe_only",
    "deny_destructive_actions": True,
    "require_step_up_for_sensitive_actions": True,
    "max_action_depth": 3,
    "destructive_action_keywords": [
        "approve",
        "delete",
        "disable",
        "publish",
        "refund",
        "remove",
        "revoke",
        "send",
        "transfer",
    ],
}
BROWSER_SAFE_MODES = {"observe_only", "mock_actions", "confirm_actions", "allow_actions"}
WIDGET_WAIT_FOR_RESPONSE_OPTIONS = {
    "new_message",
    "selector_change",
    "network_idle",
}
INPUT_SELECTOR_CANDIDATES = (
    "textarea:not([disabled])",
    "[role='textbox']:not([disabled])",
    "[contenteditable='true']",
    "input[type='text']:not([disabled])",
    "input:not([type]):not([disabled])",
    "textarea",
    "input",
)
RESPONSE_SELECTOR_CANDIDATES = (
    "#messages .msg.bot",
    "[data-chat-message='assistant']",
    "[data-message-role='assistant']",
    "[data-role='assistant']",
    ".msg.bot",
    ".message.assistant",
    ".assistant-message",
    ".bot-message",
    "[aria-live] .msg",
    "[role='log'] > *",
    "[role='log'] *",
)
SEND_SELECTOR_CANDIDATES = (
    "[data-chat-send]:not([disabled])",
    "[data-testid*='send' i]:not([disabled])",
    "button[aria-label*='send' i]:not([disabled])",
    "button[title*='send' i]:not([disabled])",
    "button.send-button:not([disabled])",
    "button[type='submit']:not([disabled])",
)


def _sha256_hex(value: bytes | str) -> str:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


def _sha256_prefixed(value: bytes | str) -> str:
    return f"sha256:{_sha256_hex(value)}"


def _stable_json_hash(value: Any) -> str:
    return _sha256_hex(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _normalize_hash(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("sha256:") and len(value) == 71:
        return value
    if len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower()):
        return f"sha256:{value.lower()}"
    return None


def _parse_widget_manifest(target: dict[str, Any]) -> dict[str, Any]:
    metadata = as_dict(target.get("metadata_json"))
    manifest = as_dict(metadata.get("widget_manifest"))
    if not manifest:
        raise ValueError("metadata_json.widget_manifest is required for widget AI targets")

    input_selector = manifest.get("input_selector")
    response_selector = manifest.get("response_selector")

    raw_response_timeout = manifest.get("response_timeout_ms")
    response_timeout_ms = (
        15_000
        if raw_response_timeout in (None, "")
        else max(
            MIN_WIDGET_RESPONSE_TIMEOUT_MS,
            min(int(raw_response_timeout), MAX_WIDGET_RESPONSE_TIMEOUT_MS),
        )
    )
    raw_settle_delay = manifest.get("settle_delay_ms")
    settle_delay_ms = (
        500
        if raw_settle_delay in (None, "")
        else max(0, min(int(raw_settle_delay), MAX_WIDGET_SETTLE_DELAY_MS))
    )
    raw_wait_for_response = manifest.get("wait_for_response")
    wait_for_response = (
        raw_wait_for_response
        if isinstance(raw_wait_for_response, str)
        and raw_wait_for_response in WIDGET_WAIT_FOR_RESPONSE_OPTIONS
        else DEFAULT_WIDGET_WAIT_FOR_RESPONSE
    )

    return {
        "entry_url": manifest.get("entry_url")
        if isinstance(manifest.get("entry_url"), str)
        else None,
        "open_widget_selector": manifest.get("open_widget_selector")
        if isinstance(manifest.get("open_widget_selector"), str)
        else None,
        "ready_selector": manifest.get("ready_selector")
        if isinstance(manifest.get("ready_selector"), str)
        else None,
        "input_selector": input_selector.strip()
        if isinstance(input_selector, str) and input_selector.strip()
        else None,
        "send_selector": manifest.get("send_selector")
        if isinstance(manifest.get("send_selector"), str)
        else None,
        "response_selector": response_selector.strip()
        if isinstance(response_selector, str) and response_selector.strip()
        else None,
        "wait_for_response": wait_for_response,
        "response_timeout_ms": response_timeout_ms,
        "settle_delay_ms": settle_delay_ms,
    }


def _split_cookie_pairs(cookie_header: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for raw_pair in cookie_header.split(";"):
        name, sep, value = raw_pair.strip().partition("=")
        if not sep or not name.strip():
            malformed = raw_pair.strip()
            if malformed:
                logger.warning("Skipping malformed widget cookie pair: %s", malformed)
            continue
        pairs.append((name.strip(), value.strip()))
    return pairs


def _request_value(value: Any) -> Any:
    if callable(value):
        try:
            return value()
        except TypeError:
            return value
    return value


def _normalize_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _normalize_browser_safety_policy(metadata: dict[str, Any]) -> dict[str, Any]:
    configured = as_dict(metadata.get("browser_safety_policy")) or as_dict(
        metadata.get("widget_safety_policy")
    )
    safe_mode = configured.get("safe_mode")
    if not isinstance(safe_mode, str) or safe_mode not in BROWSER_SAFE_MODES:
        safe_mode = DEFAULT_BROWSER_SAFETY_POLICY["safe_mode"]

    raw_depth = configured.get("max_action_depth")
    try:
        max_action_depth = int(raw_depth)
    except (TypeError, ValueError):
        max_action_depth = int(DEFAULT_BROWSER_SAFETY_POLICY["max_action_depth"])
    max_action_depth = max(0, min(max_action_depth, 20))

    raw_keywords = configured.get("destructive_action_keywords")
    if isinstance(raw_keywords, list):
        destructive_action_keywords = sorted(
            {
                str(keyword).strip().lower()
                for keyword in raw_keywords
                if isinstance(keyword, (str, int, float)) and str(keyword).strip()
            }
        )[:30]
    else:
        destructive_action_keywords = list(
            DEFAULT_BROWSER_SAFETY_POLICY["destructive_action_keywords"]
        )

    raw_deny_selectors = configured.get("deny_selectors")
    deny_selectors = (
        [
            str(selector).strip()
            for selector in raw_deny_selectors[:30]
            if isinstance(selector, (str, int, float)) and str(selector).strip()
        ]
        if isinstance(raw_deny_selectors, list)
        else []
    )

    raw_deny_url_patterns = configured.get("deny_url_patterns")
    deny_url_patterns = (
        [
            str(pattern).strip()
            for pattern in raw_deny_url_patterns[:30]
            if isinstance(pattern, (str, int, float)) and str(pattern).strip()
        ]
        if isinstance(raw_deny_url_patterns, list)
        else []
    )

    return {
        "safe_mode": safe_mode,
        "deny_destructive_actions": _normalize_bool(
            configured.get("deny_destructive_actions"),
            bool(DEFAULT_BROWSER_SAFETY_POLICY["deny_destructive_actions"]),
        ),
        "require_step_up_for_sensitive_actions": _normalize_bool(
            configured.get("require_step_up_for_sensitive_actions"),
            bool(DEFAULT_BROWSER_SAFETY_POLICY["require_step_up_for_sensitive_actions"]),
        ),
        "max_action_depth": max_action_depth,
        "destructive_action_keywords": destructive_action_keywords,
        "deny_selectors": deny_selectors,
        "deny_url_patterns": deny_url_patterns,
    }


@dataclass
class WidgetConversationExchange:
    request_method: str
    status_code: int | None
    latency_ms: float
    prompt: str
    response_excerpt: str = ""
    error: str | None = None
    input_chars: int = 0
    output_chars: int = 0
    evidence: dict[str, Any] | None = None

    def to_transcript(self, probe: dict[str, str]) -> dict[str, Any]:
        transcript = {
            "probe_id": probe["id"],
            "probe_family": probe["family"],
            "request_method": self.request_method,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "prompt": self.prompt,
        }
        if self.error is not None:
            transcript["error"] = self.error
            if self.evidence:
                transcript["widget_evidence"] = self.evidence
            return transcript

        transcript["response_excerpt"] = self.response_excerpt[:2000]
        transcript["tokens_estimated"] = {
            "input": max(self.input_chars // CHARS_PER_TOKEN_ESTIMATE, 1),
            "output": max(self.output_chars // CHARS_PER_TOKEN_ESTIMATE, 1),
        }
        if self.evidence:
            transcript["widget_evidence"] = self.evidence
        return transcript


class WidgetPlaywrightConversationTarget:
    def __init__(self, target_url: str, target: dict[str, Any]) -> None:
        self.target = target
        raw_url = str(target.get("endpoint_url") or target_url).strip()
        if not raw_url:
            raise ValueError("AI widget target endpoint_url is required")

        self.endpoint_url = build_url(raw_url, target)
        self.manifest = _parse_widget_manifest(target)
        self.method = "BROWSER"
        self.headers = build_headers(target)
        self.credential = as_dict(target.get("credential"))
        self.metadata = as_dict(target.get("metadata_json"))
        self.browser_safety_policy = _normalize_browser_safety_policy(self.metadata)
        self.browser_safety_policy_hash = _sha256_prefixed(
            json.dumps(self.browser_safety_policy, sort_keys=True, ensure_ascii=False)
        )
        self._configured_input_selector = self.manifest.get("input_selector")
        self._configured_send_selector = self.manifest.get("send_selector")
        self._configured_response_selector = self.manifest.get("response_selector")
        self._selector_manifest_hash = _sha256_hex(
            json.dumps(self.manifest, sort_keys=True, ensure_ascii=False)
        )
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._network_events: deque[dict[str, Any]] = deque(maxlen=MAX_WIDGET_NETWORK_EVENTS)

    def _auth_mode(self) -> str:
        auth_state = as_dict(self.metadata.get("playwright_auth_state")) or as_dict(
            self.metadata.get("widget_auth_state")
        )
        if auth_state:
            return "playwright_auth_state"
        return str(self.credential.get("auth_kind") or "none")

    def _auth_state_hash(self) -> str | None:
        auth_state = as_dict(self.metadata.get("playwright_auth_state")) or as_dict(
            self.metadata.get("widget_auth_state")
        )
        return f"sha256:{_stable_json_hash(auth_state)}" if auth_state else None

    async def _autodetect_selector(self, candidates: tuple[str, ...]) -> str | None:
        assert self._page is not None
        for selector in candidates:
            try:
                locator = self._page.locator(selector)
                count = await locator.count()
                if count <= 0:
                    continue
                if await locator.first.is_visible():
                    return selector
            except Exception:
                continue
        return None

    async def _resolve_input_selector(self) -> str:
        selector = self.manifest.get("input_selector")
        if isinstance(selector, str) and selector:
            return selector
        detected = await self._autodetect_selector(INPUT_SELECTOR_CANDIDATES)
        if detected:
            self.manifest["input_selector"] = detected
            return detected
        raise PlaywrightTimeoutError(
            "No widget input selector was configured and ShakerScan could not auto-detect a chat input. "
            "Set metadata_json.widget_manifest.input_selector."
        )

    async def _resolve_response_selector(self) -> str:
        selector = self.manifest.get("response_selector")
        if isinstance(selector, str) and selector:
            return selector
        detected = await self._autodetect_selector(RESPONSE_SELECTOR_CANDIDATES)
        if detected:
            self.manifest["response_selector"] = detected
            return detected
        raise PlaywrightTimeoutError(
            "No widget response selector was configured and ShakerScan could not auto-detect assistant messages. "
            "Set metadata_json.widget_manifest.response_selector."
        )

    async def _resolve_send_selector(self) -> str | None:
        selector = self.manifest.get("send_selector")
        if isinstance(selector, str) and selector:
            return selector
        detected = await self._autodetect_selector(SEND_SELECTOR_CANDIDATES)
        if detected:
            self.manifest["send_selector"] = detected
            return detected
        return None

    def describe_widget_summary(self, transcripts: list[dict[str, Any]]) -> dict[str, Any]:
        selector_manifest_hash = f"sha256:{self._selector_manifest_hash}"

        screenshot_hashes: list[str] = []
        dom_snapshot_hashes: list[str] = []
        network_summary_hashes: list[str] = []
        for transcript in transcripts:
            widget_evidence = as_dict(transcript.get("widget_evidence"))
            if widget_evidence:
                screenshot_hash = _normalize_hash(widget_evidence.get("screenshot_hash"))
                dom_snapshot_hash = _normalize_hash(widget_evidence.get("dom_snapshot_hash"))
                network_summary_hash = _normalize_hash(widget_evidence.get("network_summary_hash"))
                if screenshot_hash:
                    screenshot_hashes.append(screenshot_hash)
                if dom_snapshot_hash:
                    dom_snapshot_hashes.append(dom_snapshot_hash)
                if network_summary_hash:
                    network_summary_hashes.append(network_summary_hash)
            for turn in transcript.get("turns") or []:
                turn_record = as_dict(turn)
                widget_evidence = as_dict(turn_record.get("widget_evidence")) if turn_record else None
                if widget_evidence:
                    screenshot_hash = _normalize_hash(widget_evidence.get("screenshot_hash"))
                    dom_snapshot_hash = _normalize_hash(widget_evidence.get("dom_snapshot_hash"))
                    network_summary_hash = _normalize_hash(widget_evidence.get("network_summary_hash"))
                    if screenshot_hash:
                        screenshot_hashes.append(screenshot_hash)
                    if dom_snapshot_hash:
                        dom_snapshot_hashes.append(dom_snapshot_hash)
                    if network_summary_hash:
                        network_summary_hashes.append(network_summary_hash)

        return {
            "selector_manifest_hash": selector_manifest_hash,
            "auth_mode": self._auth_mode(),
            "auth_state_hash": self._auth_state_hash(),
            "auth_state_label": self.metadata.get("playwright_auth_state_label")
            if isinstance(self.metadata.get("playwright_auth_state_label"), str)
            else None,
            "browser_safety_policy": self.browser_safety_policy,
            "browser_safety_policy_hash": self.browser_safety_policy_hash,
            "screenshot_hashes": sorted(set(screenshot_hashes)),
            "dom_snapshot_hashes": sorted(set(dom_snapshot_hashes)),
            "network_summary_hashes": sorted(set(network_summary_hashes)),
            "trace_artifact_hash": None,
        }

    async def _capture_browser_state_evidence(self) -> dict[str, Any]:
        if self._page is None:
            return {}

        summary: dict[str, Any] = {
            "page_url": str(getattr(self._page, "url", "") or "")[:500],
        }

        title_method = getattr(self._page, "title", None)
        if callable(title_method):
            try:
                title = await title_method()
                if isinstance(title, str) and title.strip():
                    summary["page_title"] = title.strip()[:160]
            except Exception:
                pass

        if self._context is not None and callable(getattr(self._context, "cookies", None)):
            try:
                cookies = await self._context.cookies()
                if isinstance(cookies, list):
                    cookie_names = sorted(
                        {
                            str(cookie.get("name"))
                            for cookie in cookies
                            if isinstance(cookie, dict) and cookie.get("name")
                        }
                    )
                    cookie_domains = sorted(
                        {
                            str(cookie.get("domain"))
                            for cookie in cookies
                            if isinstance(cookie, dict) and cookie.get("domain")
                        }
                    )
                    summary["cookie_count"] = len(cookies)
                    summary["cookie_names"] = cookie_names[:20]
                    summary["cookie_domains"] = cookie_domains[:10]
            except Exception:
                pass

        evaluate_method = getattr(self._page, "evaluate", None)
        if callable(evaluate_method):
            try:
                storage_keys = await evaluate_method(
                    """() => ({
                        local_storage_keys: Object.keys(window.localStorage || {}).sort(),
                        session_storage_keys: Object.keys(window.sessionStorage || {}).sort(),
                    })"""
                )
                if isinstance(storage_keys, dict):
                    local_keys = storage_keys.get("local_storage_keys")
                    session_keys = storage_keys.get("session_storage_keys")
                    if isinstance(local_keys, list):
                        summary["local_storage_keys"] = [
                            str(key) for key in local_keys[:20] if isinstance(key, (str, int, float))
                        ]
                    if isinstance(session_keys, list):
                        summary["session_storage_keys"] = [
                            str(key) for key in session_keys[:20] if isinstance(key, (str, int, float))
                        ]
            except Exception:
                pass

        summary_hash = _sha256_prefixed(
            json.dumps(summary, sort_keys=True, ensure_ascii=False)
        )
        return {
            "browser_state_summary": summary,
            "browser_state_summary_hash": summary_hash,
        }

    async def preview_widget(self) -> dict[str, Any]:
        await self._ensure_browser()
        await self._ensure_widget_ready()
        assert self._page is not None

        notes: list[str] = []
        input_selector = await self._resolve_input_selector()
        input_source = "configured" if self._configured_input_selector else "autodetected"

        send_selector = await self._resolve_send_selector()
        send_source = (
            "configured"
            if self._configured_send_selector
            else ("autodetected" if send_selector else "enter_key")
        )
        if send_selector is None:
            notes.append("No send button was detected. Widget scans will use the Enter key.")

        response_selector: str | None = None
        response_source: str | None = None
        try:
            response_selector = await self._resolve_response_selector()
            response_source = (
                "configured" if self._configured_response_selector else "autodetected"
            )
        except Exception:
            notes.append(
                "A response selector could not be detected during preview. Set it manually if assistant replies only appear after the first message."
            )

        ready_selector = self.manifest["ready_selector"] or input_selector
        ready_source = "configured" if self.manifest.get("ready_selector") else "input_selector"
        page_html = await self._page.content()
        screenshot_bytes = await self._page.screenshot(full_page=False)
        network_slice = list(self._network_events)
        browser_state_evidence = await self._capture_browser_state_evidence()

        return {
            "ready": True,
            "target_type": "widget",
            "inspected_url": self._page.url,
            "selector_manifest_hash": _sha256_prefixed(
                json.dumps(self.manifest, sort_keys=True, ensure_ascii=False)
            ),
            "auth_mode": self._auth_mode(),
            "auth_state_hash": self._auth_state_hash(),
            "auth_state_label": self.metadata.get("playwright_auth_state_label")
            if isinstance(self.metadata.get("playwright_auth_state_label"), str)
            else None,
            "browser_safety_policy": self.browser_safety_policy,
            "browser_safety_policy_hash": self.browser_safety_policy_hash,
            "wait_for_response": self.manifest.get("wait_for_response"),
            "detected_selectors": {
                "open_widget_selector": self.manifest.get("open_widget_selector"),
                "ready_selector": ready_selector,
                "input_selector": input_selector,
                "send_selector": send_selector,
                "response_selector": response_selector,
            },
            "selector_sources": {
                "open_widget_selector": "configured"
                if self.manifest.get("open_widget_selector")
                else None,
                "ready_selector": ready_source,
                "input_selector": input_source,
                "send_selector": send_source,
                "response_selector": response_source,
            },
            "screenshot_hash": _sha256_prefixed(screenshot_bytes),
            "dom_snapshot_hash": _sha256_prefixed(page_html),
            "network_summary_hash": _sha256_prefixed(
                json.dumps(network_slice, sort_keys=True, ensure_ascii=False)
            ),
            **browser_state_evidence,
            "notes": notes,
        }

    async def _ensure_browser(self) -> None:
        if self._page is not None:
            return
        if async_playwright is None:
            raise ModuleNotFoundError(
                "playwright is required to execute AI widget scans in the worker runtime"
            )

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )

        credential = self.credential
        auth_kind = credential.get("auth_kind") or "none"
        secret = credential.get("secret")
        context_kwargs: dict[str, Any] = {}

        if auth_kind == "basic_auth" and isinstance(secret, str) and ":" in secret:
            username, password = secret.split(":", 1)
            context_kwargs["http_credentials"] = {"username": username, "password": password}

        header_overrides = {k: v for k, v in self.headers.items() if k.lower() != "cookie"}
        if header_overrides:
            context_kwargs["extra_http_headers"] = header_overrides

        auth_state = as_dict(self.metadata.get("playwright_auth_state")) or as_dict(
            self.metadata.get("widget_auth_state")
        )
        if auth_state:
            context_kwargs["storage_state"] = auth_state

        self._context = await self._browser.new_context(**context_kwargs)
        self._page = await self._context.new_page()
        self._page.on("request", self._record_request)
        self._page.on("response", self._record_response)

        navigation_url = str(self.manifest.get("entry_url") or self.endpoint_url)
        if auth_kind == "cookie" and isinstance(secret, str) and secret.strip():
            parsed = urlparse(navigation_url)
            cookies = [
                {
                    "name": name,
                    "value": value,
                    "domain": parsed.hostname or "",
                    "path": "/",
                    "secure": parsed.scheme == "https",
                    "httpOnly": False,
                }
                for name, value in _split_cookie_pairs(secret)
            ]
            if cookies:
                await self._context.add_cookies(cookies)

        await self._page.goto(navigation_url, wait_until="domcontentloaded")

    def _record_request(self, request: Any) -> None:
        self._network_events.append(
            {
                "event": "request",
                "method": _request_value(getattr(request, "method", None)),
                "url": _request_value(getattr(request, "url", None)),
                "resource_type": _request_value(getattr(request, "resource_type", None)),
            }
        )

    def _record_response(self, response: Any) -> None:
        request = _request_value(getattr(response, "request", None))
        self._network_events.append(
            {
                "event": "response",
                "status": _request_value(getattr(response, "status", None)),
                "url": _request_value(getattr(response, "url", None)),
                "method": _request_value(getattr(request, "method", None)) if request else None,
            }
        )

    async def _ensure_widget_ready(self) -> None:
        assert self._page is not None
        input_selector = self.manifest.get("input_selector")
        open_widget_selector = self.manifest.get("open_widget_selector")

        if open_widget_selector:
            should_open_widget = False
            ready_selector = self.manifest.get("ready_selector")
            if isinstance(ready_selector, str) and ready_selector:
                should_open_widget = not await self._page.locator(ready_selector).is_visible()
            elif isinstance(input_selector, str) and input_selector:
                should_open_widget = not await self._page.locator(input_selector).is_visible()
            else:
                try:
                    await self._resolve_input_selector()
                except PlaywrightTimeoutError:
                    should_open_widget = True

            if should_open_widget:
                await self._page.locator(open_widget_selector).click()

        input_selector = await self._resolve_input_selector()

        ready_selector = self.manifest["ready_selector"] or input_selector
        await self._page.locator(ready_selector).wait_for(
            state="visible",
            timeout=self.manifest["response_timeout_ms"],
        )

    async def _read_latest_response(self) -> tuple[int, str]:
        count, text, _outer_html = await self._read_latest_response_snapshot()
        return count, text

    async def _read_latest_response_snapshot(self) -> tuple[int, str, str]:
        assert self._page is not None
        response_selector = await self._resolve_response_selector()
        locator = self._page.locator(response_selector)
        count = await locator.count()
        if count <= 0:
            return 0, "", ""
        latest = locator.nth(count - 1)
        text = (await latest.inner_text()).strip()
        outer_html = await latest.evaluate("(el) => el.outerHTML")
        return count, text, outer_html

    async def _wait_for_response(
        self,
        *,
        previous_count: int,
        previous_text: str,
        previous_outer_html: str,
    ) -> tuple[int, str]:
        assert self._page is not None
        wait_strategy = self.manifest.get("wait_for_response") or DEFAULT_WIDGET_WAIT_FOR_RESPONSE
        deadline = time.perf_counter() + (self.manifest["response_timeout_ms"] / 1000)
        last_seen_count = previous_count
        last_seen_text = previous_text
        last_seen_html = previous_outer_html

        if wait_strategy == "network_idle":
            try:
                await self._page.wait_for_load_state(
                    "networkidle",
                    timeout=self.manifest["response_timeout_ms"],
                )
            except Exception:
                pass
            if self.manifest["settle_delay_ms"] > 0:
                await self._page.wait_for_timeout(self.manifest["settle_delay_ms"])
            current_count, current_text, current_html = await self._read_latest_response_snapshot()
            if current_count > previous_count or (
                current_count > 0 and current_html and current_html != previous_outer_html
            ):
                return current_count, current_text
            last_seen_count = current_count
            last_seen_text = current_text
            last_seen_html = current_html

        while time.perf_counter() < deadline:
            current_count, current_text, current_html = await self._read_latest_response_snapshot()
            if wait_strategy == "selector_change":
                response_changed = current_count > previous_count or (
                    current_count > 0 and current_html and current_html != previous_outer_html
                )
            else:
                response_changed = current_count > previous_count or (
                    current_count > 0 and current_text and current_text != previous_text
                )
            if response_changed:
                if self.manifest["settle_delay_ms"] > 0:
                    await self._page.wait_for_timeout(self.manifest["settle_delay_ms"])
                return await self._read_latest_response()
            last_seen_count = current_count
            last_seen_text = current_text
            last_seen_html = current_html
            await self._page.wait_for_timeout(250)

        if last_seen_count > 0 and last_seen_text:
            return last_seen_count, last_seen_text
        raise PlaywrightTimeoutError(
            f"No widget response matched {self.manifest['response_selector']} before timeout"
        )

    async def _send_prompt(self, prompt: str) -> None:
        assert self._page is not None
        input_selector = await self._resolve_input_selector()
        input_locator = self._page.locator(input_selector)
        try:
            await input_locator.fill(prompt)
        except Exception:
            await input_locator.click()
            await self._page.keyboard.press("Meta+A")
            await self._page.keyboard.press("Control+A")
            await self._page.keyboard.type(prompt)

        send_selector = await self._resolve_send_selector()
        if send_selector:
            await self._page.locator(send_selector).click()
        else:
            await input_locator.press("Enter")

    async def send_message(
        self,
        _session: Any,
        *,
        prompt: str,
        probe_id: str,
        session_id: str,
        principal: str | None = None,
        replacements: dict[str, str] | None = None,
    ) -> WidgetConversationExchange:
        started = time.perf_counter()
        try:
            await self._ensure_browser()
            await self._ensure_widget_ready()
            assert self._page is not None

            previous_count, previous_text, previous_outer_html = (
                await self._read_latest_response_snapshot()
            )
            self._network_events.clear()
            await self._send_prompt(prompt)
            current_count, current_text = await self._wait_for_response(
                previous_count=previous_count,
                previous_text=previous_text,
                previous_outer_html=previous_outer_html,
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            response_selector = await self._resolve_response_selector()
            latest_locator = self._page.locator(response_selector).nth(
                max(current_count - 1, 0)
            )
            outer_html = await latest_locator.evaluate("(el) => el.outerHTML")
            screenshot_bytes = await self._page.screenshot(full_page=False)
            network_slice = list(self._network_events)
            browser_state_evidence = await self._capture_browser_state_evidence()
            evidence = {
                "selector_manifest_hash": _sha256_prefixed(
                    json.dumps(self.manifest, sort_keys=True, ensure_ascii=False)
                ),
                "screenshot_hash": _sha256_prefixed(screenshot_bytes),
                "dom_snapshot_hash": _sha256_prefixed(outer_html),
                "network_summary_hash": _sha256_prefixed(
                    json.dumps(network_slice, sort_keys=True, ensure_ascii=False)
                ),
                "input_selector": self.manifest["input_selector"],
                "input_selector_source": "configured"
                if self._configured_input_selector
                else "autodetected",
                "send_selector": self.manifest.get("send_selector"),
                "send_selector_source": "configured"
                if self._configured_send_selector
                else ("autodetected" if self.manifest.get("send_selector") else "enter_key"),
                "response_selector": response_selector,
                "response_selector_source": "configured"
                if self._configured_response_selector
                else "autodetected",
                "wait_for_response": self.manifest["wait_for_response"],
                "response_count": current_count,
                "network_event_count": len(network_slice),
                "probe_id": probe_id,
                "session_id": session_id,
                "browser_safety_policy": self.browser_safety_policy,
                "browser_safety_policy_hash": self.browser_safety_policy_hash,
                **browser_state_evidence,
            }
            return WidgetConversationExchange(
                request_method=self.method,
                status_code=200,
                latency_ms=elapsed_ms,
                prompt=prompt,
                response_excerpt=current_text,
                input_chars=len(prompt),
                output_chars=len(current_text),
                evidence=evidence,
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            if self._context is not None or self._browser is not None or self._playwright is not None:
                await self.close()
            return WidgetConversationExchange(
                request_method=self.method,
                status_code=504 if isinstance(exc, PlaywrightTimeoutError) else None,
                latency_ms=elapsed_ms,
                prompt=prompt,
                error=str(exc),
                input_chars=len(prompt),
                output_chars=0,
                evidence={
                    "selector_manifest_hash": _sha256_prefixed(
                        json.dumps(self.manifest, sort_keys=True, ensure_ascii=False)
                    ),
                    "input_selector": self.manifest.get("input_selector"),
                    "input_selector_source": "configured"
                    if self._configured_input_selector
                    else ("autodetected" if self.manifest.get("input_selector") else "unknown"),
                    "send_selector": self.manifest.get("send_selector"),
                    "send_selector_source": "configured"
                    if self._configured_send_selector
                    else ("autodetected" if self.manifest.get("send_selector") else "enter_key"),
                    "response_selector": self.manifest.get("response_selector"),
                    "response_selector_source": "configured"
                    if self._configured_response_selector
                    else ("autodetected" if self.manifest.get("response_selector") else "unknown"),
                    "wait_for_response": self.manifest.get("wait_for_response"),
                    "probe_id": probe_id,
                    "session_id": session_id,
                    "browser_safety_policy": self.browser_safety_policy,
                    "browser_safety_policy_hash": self.browser_safety_policy_hash,
                },
            )

    async def close(self) -> None:
        if self._page is not None:
            await self._page.close()
            self._page = None
        if self._context is not None:
            await self._context.close()
            self._context = None
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None
