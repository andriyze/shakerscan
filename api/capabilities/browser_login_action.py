"""Canonical, operator-selected browser login QA adapter for Scan and Hunt.

The same operation owns login and all read-only assertions. It exports neither
session state nor request/body observations for downstream attack execution.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace, field
import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from .browser_login import (
    BrowserLoginWorkflow, BrowserReadOnlyCheck, BrowserLoginValues,
    BrowserLoginResponse, BrowserLoginError, run_browser_login_checks, _url,
)
try:
    from runtime.browser_login_contract import (
        BROWSER_LOGIN_BUDGET, BROWSER_LOGIN_CAPABILITY,
        normalize_browser_login_reference, normalize_browser_login_profile,
        require_browser_login_policy,
    )
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.models import TargetBinding
    from runtime.target_bound_socket import FrozenTargetSocketFactory
    from hunt.capability_executor import CapabilityAdapterResult
except ModuleNotFoundError:
    from ..runtime.browser_login_contract import (
        BROWSER_LOGIN_BUDGET, BROWSER_LOGIN_CAPABILITY,
        normalize_browser_login_reference, normalize_browser_login_profile,
        require_browser_login_policy,
    )
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.models import TargetBinding
    from ..runtime.target_bound_socket import FrozenTargetSocketFactory
    from ..hunt.capability_executor import CapabilityAdapterResult


@dataclass(frozen=True, repr=False)
class BrowserLoginMaterial:
    configuration: Mapping[str, Any] = field(repr=False)
    values: BrowserLoginValues = field(repr=False)
    revalidate: Any = field(repr=False)

    def __repr__(self) -> str:
        return "BrowserLoginMaterial(values_visible=False)"


@dataclass(frozen=True)
class PreparedBrowserLogin:
    capability_name: str
    adapter_name: str
    adapter_version: str
    parser_version: str
    target: TargetBinding
    target_url: str
    origin: str
    profile_ref: Mapping[str, Any]
    input_digest: str
    estimated_budget: Mapping[str, int]
    redacted_execution: Mapping[str, Any]
    session_ref: None = None


@asynccontextmanager
async def worker_browser():
    """Use the image's installed Chromium, never download a browser at runtime."""
    from playwright.async_api import async_playwright
    executable = Path("/usr/bin/chromium")
    if not executable.is_file():
        raise ValueError("installed Chromium is unavailable")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            executable_path=str(executable), headless=True,
            args=["--no-sandbox", "--disable-background-networking",
                  "--disable-component-update", "--disable-sync"],
        )
        try:
            yield browser
        finally:
            await asyncio.wait_for(browser.close(), timeout=5)


class BrowserLoginRuntimeTransport:
    """Exact bytes over the existing frozen-address replay transport, no retry.

    This is not an open replay capability: the helper and this boundary both
    restrict traffic to the saved origin and to one saved login POST.
    """
    def __init__(self, *, prepared, workflow, revalidate, heartbeat, cancelled, sender=None):
        try:
            from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
        except ModuleNotFoundError:
            from ..runtime.pinned_http_replay import PinnedAiohttpReplayTransport
        self.prepared, self.workflow = prepared, workflow
        self.revalidate, self.heartbeat, self.cancelled = revalidate, heartbeat, cancelled
        self.sender = sender or PinnedAiohttpReplayTransport(
            verify_tls=True, reject_duplicate_response_headers=True,
        )
        parsed = urlsplit(workflow.origin)
        factory = FrozenTargetSocketFactory(
            hostname=prepared.target.canonical_host,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            frozen_addresses=prepared.target.allowed_addresses,
        )
        # Never retry a login on another address after an ambiguous first send.
        self.target = replace(prepared.target, allowed_addresses=(factory.primary_address,))
        self.attempts = 0
        self.posts = 0

    async def __call__(self, request: Any, phase: str) -> BrowserLoginResponse:
        try:
            from scanner_tools.request_replay import ReplayRequest
        except ModuleNotFoundError:
            from scanner.scanner_tools.request_replay import ReplayRequest
        if self.cancelled():
            raise asyncio.CancelledError()
        url = _url(request.url, self.workflow.origin, fragment=False)
        method = request.method
        if phase not in {"anonymous", "load", "login", "verify", "read_only"}:
            raise ValueError("browser phase is not authorized")
        post = method == "POST"
        if method not in {"GET", "HEAD", "OPTIONS"} and not (
            post and phase == "login" and url == self.workflow.submit_url and not self.posts
        ):
            raise ValueError("browser request is outside the saved workflow")
        if self.attempts >= self.workflow.max_requests:
            raise ValueError("browser request reservation exhausted")
        # Claim the admission before any await; concurrent callbacks cannot share
        # a request unit or the single login slot.
        self.attempts += 1
        if post:
            self.posts += 1
        await self.heartbeat()
        await self.revalidate()
        if self.cancelled():
            raise asyncio.CancelledError()
        raw_headers = await request.all_headers()
        if not isinstance(raw_headers, Mapping) or len(raw_headers) > 100:
            raise ValueError("browser request headers exceeded their boundary")
        headers = []
        total = 0
        for name, value in raw_headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("browser request header is invalid")
            if name.lower() in {"host", "content-length", "connection", "transfer-encoding",
                                 "proxy-authorization", "proxy-connection", "te", "trailer", "upgrade"}:
                continue
            if any(ord(c) < 32 or ord(c) == 127 for c in name + value):
                raise ValueError("browser request header is invalid")
            total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
            if total > 32768:
                raise ValueError("browser request headers exceeded their boundary")
            headers.append((name, value))
        body = request.post_data_buffer or b""
        if not isinstance(body, bytes) or len(body) > 65536 or (body and not post):
            raise ValueError("browser request body is outside the saved login")
        wire = ReplayRequest(
            request_id=f"browser-login-{self.attempts}", ordinal=self.attempts,
            name="browser-login-qa", folder="", method=method, url=url,
            headers=tuple(headers), body=body, body_mode="raw", auth_type="none",
            has_sensitive_material=True,
        )
        result = await self.sender.send(
            wire, target=self.target,
            timeout_seconds=min(30, self.workflow.timeout_ms / 1000),
            follow_redirects=False,
        )
        if (result.error_code or result.status_code is None
                or result.connected_address not in self.target.allowed_addresses
                or result.final_url != url
                or len(result.response_body) > self.workflow.max_response_bytes):
            raise ValueError("browser transport did not complete the bounded request")
        return BrowserLoginResponse(result.status_code, result.response_headers, result.response_body)


class BrowserLoginAdapter:
    capability_name = BROWSER_LOGIN_CAPABILITY
    adapter_name = "playwright.login_check"
    adapter_version = "1"
    parser_version = "browser-login-check/v1"
    manages_cancellation = True

    @classmethod
    def prepare(cls, *, target: TargetBinding, base_url: str, args: Mapping[str, Any],
                profile_ref: Mapping[str, Any] | None = None) -> PreparedBrowserLogin:
        validated = CAPABILITY_REGISTRY.validate_input(cls.capability_name, args)
        reference = normalize_browser_login_reference(profile_ref or validated.get("profile_ref"))
        if reference["principal_slot"] != validated["as_principal"]:
            raise ValueError("browser login principal differs from the saved reference")
        from .browser_login import _origin
        origin = _origin(base_url)
        if (target.target_kind not in {"web", "api"} or origin not in target.allowed_origins
                or urlsplit(origin).hostname != target.canonical_host
                or not target.allowed_addresses):
            raise ValueError("browser login target is not frozen")
        encoded = json.dumps({"target_binding": target.digest, "profile_ref": reference,
                              "capability": cls.capability_name}, sort_keys=True).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        return PreparedBrowserLogin(
            cls.capability_name, cls.adapter_name, cls.adapter_version, cls.parser_version,
            target, base_url, origin, reference, digest, dict(BROWSER_LOGIN_BUDGET),
            {"profile_ref": reference, "input_digest": digest,
             "saved_workflow_only": True, "session_exported": False,
             "verification_basis": "operator_dom_assertion"},
        )

    def __init__(self, prepared, *, credential_loader, policy,
                 browser_factory=worker_browser, sender=None):
        require_browser_login_policy(policy)
        self.prepared, self.credential_loader = prepared, credential_loader
        self.browser_factory, self.sender = browser_factory, sender

    async def execute(self, *, heartbeat, cancelled) -> CapabilityAdapterResult:
        started = time.monotonic()
        transport = None
        receipt = None
        status, error = "blocked", "browser_login_unavailable"
        entered = False
        async def run():
            nonlocal transport, receipt, entered
            await heartbeat()
            async with self.credential_loader() as material:
                config = normalize_browser_login_profile(material.configuration)
                workflow = BrowserLoginWorkflow(**config["workflow"])
                if workflow.origin != self.prepared.origin:
                    raise ValueError("saved browser workflow differs from target origin")
                await material.revalidate()
                transport = BrowserLoginRuntimeTransport(
                    prepared=self.prepared, workflow=workflow,
                    revalidate=material.revalidate, heartbeat=heartbeat,
                    cancelled=cancelled, sender=self.sender,
                )
                checks = tuple(BrowserReadOnlyCheck(**item) for item in config["checks"])
                async with self.browser_factory() as browser:
                    entered = True
                    receipt = await run_browser_login_checks(
                        browser, workflow=workflow, values=material.values,
                        transport=transport, checks=checks,
                    )
                await material.revalidate()
        task = None
        try:
            if cancelled():
                return CapabilityAdapterResult(status="cancelled", errors=("cancelled_before_execution",))
            async with asyncio.timeout(195):
                task = asyncio.create_task(run())
                while not task.done():
                    await asyncio.wait({task}, timeout=0.5)
                    if cancelled():
                        task.cancel()
                        raise asyncio.CancelledError()
                    await heartbeat()
                await task
            status, error = "success", None
        except asyncio.CancelledError:
            status, error = "cancelled", "browser_login_cancelled"
        except BrowserLoginError as exc:
            receipt = exc.receipt
            status, error = "failed", "browser_login_verification_failed"
        except TimeoutError:
            status, error = "failed", "browser_login_timed_out"
        except Exception:
            # Neither credential errors nor Playwright diagnostics may contain
            # values in the public action error/receipt.
            status, error = "failed" if entered else "blocked", "browser_login_unavailable"
        finally:
            if task is not None and not task.done():
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=5)
                except BaseException:
                    pass
            if task is not None and task.done() and not task.cancelled():
                # A concurrent heartbeat failure may win before awaiting run().
                # Retrieve its exception without publishing private diagnostics.
                task.exception()
        # Receipt is produced by the fixed helper; do not expose private config,
        # traffic, browser state or any inferred discovery/proof objects.
        observation = {
            "kind": "browser_login_qa", "profile_ref": dict(self.prepared.profile_ref),
            "status": status, "authentication_verified": status == "success",
            "qa_completed": status == "success", "secret_values_visible": False,
        }
        if receipt is not None:
            for key in ("status", "checks_requested", "checks_completed", "checks",
                        "anonymous_check_verified", "requests_blocked", "cleanup_failed"):
                if key in receipt:
                    observation[key if key != "status" else "verification_status"] = receipt[key]
        return CapabilityAdapterResult(
            status=status, observations=(observation,), errors=(error,) if error else (),
            actual_budget={
                "http_requests": transport.attempts if transport else 0,
                "state_changing_requests": transport.posts if transport else 0,
                # Browser actions are conservatively charged: partial Playwright
                # failure does not establish exactly which commands completed.
                "browser_actions": 32 if entered else 0,
                "tool_wall_seconds": math.ceil(time.monotonic() - started),
            }, execution_started=entered,
            parser_version=self.parser_version,
            redacted_execution={**self.prepared.redacted_execution,
                                "browser_action_accounting": "conservative_reserved_ceiling",
                                "http_accounting": "conservative_admitted_attempts"},
        )
