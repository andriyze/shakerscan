"""Loopback-only synthetic HTTP fixtures. Never connect to real customer data."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import secrets
from typing import Any

from aiohttp import web


class BoundaryFixture:
    def __init__(self, mode: str = "secure", nested: bool = False) -> None:
        self.mode, self.nested = mode, nested
        self.calls: list[tuple[str, str]] = []
        self.chat_bodies: list[dict[str, Any]] = []
        self.chat_started = asyncio.Event()
        self.release_chat = asyncio.Event()
        self.credentials = {"owner": secrets.token_hex(16), "attacker": secrets.token_hex(16)}
        self.rows = {
            f"{role}-record": {"id": f"{role}-record", "owner": f"{role}-subject",
                              "tenant": f"{role}-tenant", "marker": "ssb_" + secrets.token_hex(24)}
            for role in ("owner", "attacker")
        }
        self.base = ""
        self.cleaned = False

    def role(self, request: web.Request) -> str | None:
        value = request.headers.get("Authorization", "").removeprefix("Bearer ")
        for role, credential in self.credentials.items():
            if secrets.compare_digest(value, credential):
                return "attacker" if self.mode == "aliased_identity" else role
        return None

    async def handle(self, request: web.Request) -> web.Response:
        self.calls.append((request.method, request.path))
        role = self.role(request)
        if not role:
            return web.json_response({"error": "unauthorized"}, status=401)
        if request.path.endswith("/identity"):
            if self.mode == "redirect":
                return web.Response(status=302, headers={"Location": self.base + "/sink"})
            if self.mode == "rate_limit":
                return web.json_response({"error": "slow down"}, status=429)
            payload = {"subject": role + "-subject", "tenant": role + "-tenant"}
            return web.json_response({"identity": payload} if self.nested else payload)
        if "/records/" in request.path:
            resource_id = request.match_info["resource_id"]
            row = self.rows.get(resource_id)
            if not row:
                return web.json_response({"error": "not found"}, status=404)
            if row["owner"] != role + "-subject" and self.mode != "backend_leak":
                return web.json_response({"error": "forbidden"}, status=403)
            return web.json_response({"record": row} if self.nested else row)
        if request.path.endswith("/chat"):
            body = await request.json()
            self.chat_bodies.append(body)
            self.chat_started.set()
            if self.mode == "cancel":
                await self.release_chat.wait()
            if self.mode == "server_error":
                return web.json_response({"error": "down"}, status=503)
            if self.mode == "oversize":
                return web.json_response({"answer": "x" * 70000})
            prompt = body["input"]["text"] if self.nested else body["message"]
            row = next((row for rid, row in self.rows.items() if rid in prompt), None)
            if self.mode == "baseline_leak" and role == "attacker":
                answer = self.rows["owner-record"]["marker"]
            elif self.mode == "echo":
                answer = prompt
            elif row and (row["owner"] == role + "-subject" or self.mode == "vulnerable"):
                answer = row["marker"]
            elif self.mode == "hallucination":
                answer = "I accessed the other account and completed the refund. ssb_" + "0" * 48
            else:
                answer = "Access denied."
            if self.mode == "missing_answer":
                return web.json_response({"unrelated": answer})
            payload = {"output": {"text": answer}} if self.nested else {"answer": answer}
            if self.mode == "trace_only" and row:
                payload["tool_calls"] = [{"result": row["marker"], "executed": True}]
            return web.json_response(payload)
        return web.json_response({"error": "unexpected route"}, status=404)

    def options(self) -> dict[str, Any]:
        prefix = "v2/" if self.nested else ""
        contract = {
            "version": 1, "name": "customer-isolation",
            **{role: {"role": role, "subject": role + "-subject", "tenant": role + "-tenant",
                       "resource_id": role + "-record"} for role in ("owner", "attacker")},
            "identity": {"path": f"/{prefix}identity", "subject_field": "identity.subject" if self.nested else "subject",
                         "tenant_field": "identity.tenant" if self.nested else "tenant"},
            "resource": {"path": f"/{prefix}records/" + "{{resource_id}}",
                         **{name: ("record." if self.nested else "") + field
                            for name, field in (("id_field", "id"), ("owner_field", "owner"),
                                                ("tenant_field", "tenant"), ("marker_field", "marker"))}},
            "response_path": "output.text" if self.nested else "answer", "repetitions": 1,
        }
        template = {"input": {"text": "{{prompt}}"}, "thread": "{{session_id}}"} if self.nested else {
            "message": "{{prompt}}", "session_id": "{{session_id}}"}
        return {"run_kind": "ai_api", "ai_probe_pack": "shaker-ai-boundary", "ai_scan_profile": "standard",
                "ai_environment": "preview", "ai_target": {
                    "name": "Loopback boundary fixture", "target_type": "api_chat", "method": "POST",
                    "endpoint_url": self.base + f"/{prefix}chat", "request_template": template,
                    "response_path": contract["response_path"], "request_budget": 64, "token_budget": 32000,
                    "rate_limit_rps": 20, "metadata_json": {"boundary_contract": contract},
                    "principals": [{"role": role, "credential": {"auth_kind": "bearer", "secret": value}}
                                   for role, value in self.credentials.items()],
                }}


@asynccontextmanager
async def boundary_fixture(mode: str = "secure", *, nested: bool = False):
    fixture = BoundaryFixture(mode, nested)
    app = web.Application()
    prefix = "/v2" if nested else ""
    app.router.add_get(prefix + "/identity", fixture.handle)
    app.router.add_get(prefix + "/records/{resource_id}", fixture.handle)
    app.router.add_post(prefix + "/chat", fixture.handle)
    app.router.add_get("/sink", fixture.handle)
    runner = web.AppRunner(app, shutdown_timeout=1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    fixture.base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        yield fixture
    finally:
        fixture.release_chat.set()
        await runner.cleanup()
        fixture.rows.clear()
        fixture.cleaned = True
