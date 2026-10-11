"""``shakerscan knowledge continue|release|releases``, ``authority_for`` and MCP ``kind=continue``.

Unit fixtures: a scripted terminal double, a loopback stub of the operator routes (not an engine)
and a stubbed report behind the real Hunt query route. The PostgreSQL path through the real app is
tests/test_knowledge_continue_postgres.py.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import hunt_approve as approval  # noqa: E402
import v2_cli  # noqa: E402

from tests.test_knowledge_review_cli import Terminal  # noqa: E402

TARGET = "11111111-1111-4111-8111-111111111111"
REAL_TERMINAL = approval.Terminal


def _report(offers: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "kind": "continue", "since": {"kind": "release", "source": "declared", "label": "v2\x1b[2J", "resolved": True,
                                      "at": "2026-10-07T00:00:00+00:00"},
        "changes": {"sections": {"endpoints": {"added": {"count": 1}, "removed": {"count": 0},
                                               "auth_surface": {"significant": True}},
                                 "deployment": {"compared": True, "significant": False, "changes": []}}},
        "knowledge": {"counts": {"needs_revalidation": 1, "not_reobserved_since_release": 0},
                      "reopened_for_review": [{"id": "e-9", "finding_id": "f-1"}]},
        "next_experiments": {
            "items": [{"rank": 1, "rule": "revalidate_changed", "capability": "http.request", "required_retest": True,
                       "input": {"method": "GET", "path": "/api/invoices/17‮\x07"},
                       "basis": {"type": "interpretation", "id": "e-1"}, "authority": {"status": "not_evaluated"}}],
            "required_retests": {"total": 1, "outside_authority": 0}, "outside_authority": [], "truncated": False},
        "freshness": {"refresh": {"offered": bool(offers), "offers": offers}},
    }


PASSIVE = {"kind": "passive_scan", "why": "older than the release", "traffic": "ordinary requests",
           "request": {"method": "POST", "path": "/scans",
                       "body": {"target": "https://app", "target_kind": "web", "policy": {"active_testing": False}}}}


class Stub:
    """Loopback stub of the continue, release and Scan routes (unit fixture)."""

    def __init__(self, offers: list[dict[str, Any]]) -> None:
        self.seen: list[tuple[str, str, Any]] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _reply(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802
                stub.seen.append(("GET", self.path, None))
                if "/knowledge/releases" in self.path:
                    return self._reply(200, {"releases": [{"id": "m-1", "label": "v1\x1b[31m", "released_at": "x",
                                                           "declared_by": "operator:a"}]})
                return self._reply(200, _report(offers))

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                stub.seen.append(("POST", self.path, body))
                return self._reply(201, {"id": "new", "released_at": "now", "scan_id": "s-1"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def posts(self) -> list[tuple[str, Any]]:
        return [(path, body) for method, path, body in self.seen if method == "POST"]

    def __enter__(self) -> "Stub":
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def _run(stub: Stub, terminal: Terminal | None, *argv: str, monkeypatch: pytest.MonkeyPatch) -> int:
    if terminal is not None:
        monkeypatch.setattr(approval, "Terminal", lambda: terminal)
    return v2_cli.main(["--api-url", stub.url, "knowledge", *argv])


def test_continue_prints_the_ranked_report_inert_and_reads_only(monkeypatch, capsys):
    with Stub([PASSIVE]) as stub:
        assert _run(stub, None, "continue", TARGET, monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "REQUIRED RE-TEST" in out and "revalidate_changed" in out and "/api/invoices/17" in out
    assert "reopened dismissal e-9" in out and "--refresh" in out and "nothing was sent" in out
    assert stub.posts() == []
    assert any("since=release" in path for _, path, _ in stub.seen)


def test_refresh_starts_only_a_passive_offer_after_the_keypress(monkeypatch):
    hostile = {**PASSIVE, "request": {**PASSIVE["request"], "body": {"target": "https://app",
                                                                       "policy": {"active_testing": True}}}}
    elsewhere = {**PASSIVE, "kind": "passive_scan", "request": {"method": "POST", "path": "/hunts", "body": {}}}
    batch = {**PASSIVE, "request": {**PASSIVE["request"], "path": "/scans/batch"}}
    extra = {**PASSIVE, "request": {**PASSIVE["request"], "body": {**PASSIVE["request"]["body"],
                                                                     "credential_profile_ids": ["x"]}}}
    with Stub([PASSIVE, hostile, elsewhere, batch, extra]) as stub:
        terminal = Terminal("n")
        assert _run(stub, terminal, "continue", TARGET, "--refresh", monkeypatch=monkeypatch) == 0
        assert stub.posts() == []
        terminal = Terminal("s")
        assert _run(stub, terminal, "continue", TARGET, "--refresh", monkeypatch=monkeypatch) == 0
    assert stub.posts() == [("/scans", PASSIVE["request"]["body"])]  # never the active or foreign one
    text = terminal.stdout.getvalue()
    assert text.count("skipped") == 4 and "passive Scan of https://app" in text


def test_a_pipe_never_starts_a_refresh_or_declares_a_release(monkeypatch, capsys):
    with Stub([PASSIVE]) as stub:
        monkeypatch.setattr(approval, "Terminal", REAL_TERMINAL)
        monkeypatch.setattr(sys, "stdin", io.StringIO("s\n"))
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "continue", TARGET, "--refresh", "--json"]) == 2
        monkeypatch.setattr(sys, "stdin", io.StringIO("r\n"))
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "release", TARGET, "--label", "v2"]) == 2
        assert "interactive terminal" in capsys.readouterr().err
    assert stub.posts() == []


def test_release_is_declared_on_its_own_key(monkeypatch, capsys):
    with Stub([]) as stub:
        terminal = Terminal("n")
        assert _run(stub, terminal, "release", TARGET, "--label", "v2", monkeypatch=monkeypatch) == 0
        assert stub.posts() == []
        terminal = Terminal("r")
        assert _run(stub, terminal, "release", TARGET, "--label", "v2", "--at", "2026-10-07T00:00:00+00:00",
                    monkeypatch=monkeypatch) == 0
        assert _run(stub, None, "releases", TARGET, monkeypatch=monkeypatch) == 0
    assert stub.posts() == [(f"/targets/{TARGET}/knowledge/releases",
                             {"label": "v2", "released_at": "2026-10-07T00:00:00+00:00"})]
    assert "declared release new" in terminal.stdout.getvalue()
    assert "\x1b" not in capsys.readouterr().out


def test_authority_for_follows_the_current_policy():
    from api.hunt.knowledge_continue import authority_for
    run = {"status": "active", "policy_json": {"allowed_capabilities": ["http.request"]},
           "budget_json": {"http_requests": 5}, "budget_used_json": {"http_requests": 1}}
    get = {"capability": "http.request", "input": {"method": "GET", "path": "/a"}}
    post = {"capability": "http.request", "input": {"method": "POST", "path": "/a"}}
    assert authority_for(get, run)["status"] == "allowed"
    assert authority_for(post, run)["status"] == "outside_authority"
    assert authority_for({"capability": "authz.verify"}, run)["status"] == "outside_authority"
    granted = {**run, "policy_json": {"allowed_capabilities": ["authz.verify"]}}
    assert authority_for({"capability": "authz.verify"}, granted)["status"] == "needs_approval"
    assert authority_for(get, {**run, "status": "cancelled"})["status"] == "outside_authority"
    assert authority_for(get, {**run, "budget_used_json": {"http_requests": 5}})["status"] == "outside_authority"
    assert authority_for(get, None)["status"] == "not_evaluated"
    assert authority_for({"capability": None}, run)["status"] == "agent_chooses"


def test_ranking_rules_are_fixed_and_ordered():
    from api.hunt.knowledge_continue import RANKING_RULES
    assert [rule["tier"] for rule in RANKING_RULES] == list(range(1, len(RANKING_RULES) + 1))
    assert [rule["rule"] for rule in RANKING_RULES][:3] == ["revalidate_changed", "new_auth_surface",
                                                            "reobserve_since_release"]
    assert RANKING_RULES[-1]["rule"] == "agent_next_step"


def test_mcp_query_kind_continue_reaches_the_real_route(monkeypatch):
    pytest.importorskip("fastapi")
    from contextlib import asynccontextmanager
    from fastapi.testclient import TestClient
    from api import api as api_module

    spec = importlib.util.spec_from_file_location("shakerscan_mcp_continue", ROOT / "scripts" / "shakerscan_mcp.py")
    mcp = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mcp
    spec.loader.exec_module(mcp)
    target, hunt = uuid.UUID(int=7), uuid.UUID(int=9)
    seen = {}

    async def report(conn, target_id, **kwargs):
        seen.update(target_id=target_id, **kwargs)
        return {"ok": True, "kind": "continue", "since": {"kind": kwargs["since"]}, "next_experiments": {"items": []}}
    for name in ("hunt.knowledge_continue", "api.hunt.knowledge_continue"):
        module = sys.modules.get(name) or importlib.import_module(name)
        monkeypatch.setattr(module, "continue_report", report)

    class Conn:
        async def fetchrow(self, *args):
            return {"id": hunt, "status": "active", "policy_json": {}}

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Conn()

    async def run(*args):
        return {"target_id": target, "device_target_id": None}
    routes = (nested for route in api_module.app.routes
              for nested in getattr(getattr(route, "original_router", None), "routes", (route,)))
    endpoint = next(route.endpoint for route in routes if getattr(route, "path", None) == "/hunts/{hunt_id}/query")
    monkeypatch.setitem(endpoint.__globals__, "_pool", lambda: Pool())
    monkeypatch.setitem(endpoint.__globals__, "_hunt_run_or_404", run)

    class Client(mcp.ArsenalClient):
        def __init__(self, http):
            super().__init__("http://127.0.0.1:8080")
            self.http = http

        def request_json(self, method, path, payload=None):
            response = self.http.request(method, path, json=payload)
            assert response.status_code < 400, response.text
            return response.json()

    tool = next(item for item in mcp.HUNT_TOOLS if item.name == "shakerscan_hunt_query")
    assert "continue" in tool.properties["kind"]["enum"]
    answer = Client(TestClient(api_module.app)).call_tool(
        "shakerscan_hunt_query", {"hunt_id": str(hunt), "kind": "continue", "filter": {}})
    assert answer["structuredContent"]["since"] == {"kind": "release"}
    assert seen["target_id"] == target and seen["audience"] == "hunt" and seen["run"]["id"] == hunt


def _ranked(count: int, required: bool = True) -> list[dict[str, Any]]:
    return [{"rule": "reobserve_since_release", "tier": 3, "basis": {"type": "interpretation", "id": f"{i:04d}"},
             "required_retest": required, "capability": "http.request", "input": None, "rank": i + 1,
             "sort_key": [3, 0, 0.0, f"{i:04d}"]} for i in range(count)]


@pytest.mark.parametrize("run", [None, {"status": "completed", "policy_json": {}}], ids=["operator", "finished-hunt"])
def test_every_required_retest_is_on_some_page(run):
    from api.hunt import knowledge_continue
    seen: list[str] = []
    after = None
    while True:
        report = {"next_experiments": {"ranked": _ranked(300), "complete": {"complete": True, "reasons": []}}}
        nxt = knowledge_continue._with_authority(report, run, 25, after=after)["next_experiments"]
        assert nxt["required_retests"]["total"] == 300 and nxt["changed_since_cursor"] is False
        seen += [item["basis"]["id"] for item in nxt["items"] + nxt["outside_authority"]]
        after = nxt["next_after"]
        if not after:
            break
        assert nxt["unlisted"]["required_runnable"] + nxt["unlisted"]["required_outside_authority"] > 0
    assert sorted(seen) == [f"{i:04d}" for i in range(300)]  # each exactly once


def test_authority_for_origin_and_state_changing_routes():
    from api.hunt.knowledge_continue import authority_for
    run = {"status": "active", "policy_json": {"allowed_capabilities": ["http.request"]},
           "_target_url": "https://app.example.test"}
    same = {"capability": "http.request", "input": {"method": "GET", "path": "/a", "origin": "https://app.example.test:8443"}}
    other = {"capability": "http.request", "input": {"method": "GET", "path": "/a", "origin": "https://evil.example.test"}}
    assert authority_for(same, run)["status"] == "allowed"
    assert authority_for(other, run)["status"] == "outside_authority"
    writing = {"capability": None, "state_changing": True, "route": {"method": "POST", "path": "/x"}}
    assert authority_for(writing, run)["status"] == "outside_authority"
    assert authority_for(writing, None)["status"] == "outside_authority"


def test_cli_all_follows_every_cursor_and_restarts_when_the_set_changes(monkeypatch, capsys):
    pages: list[str] = []

    def answer(handler, body):
        data = json.dumps(body).encode()
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    def do_get(handler):  # unit fixture: a set that changes once between pages, then two stable pages
        pages.append(handler.path)
        body = _report([])
        nxt = body["next_experiments"]
        if "after=c2" in handler.path:
            nxt.update(items=[{**nxt["items"][0], "rank": 101}], next_after=None, changed_since_cursor=False)
        elif "after=c1" in handler.path:
            nxt.update(next_after="c9", changed_since_cursor=sum("after=c1" in p for p in pages) == 1)
            if not nxt["changed_since_cursor"]:
                nxt["next_after"] = "c2"
        else:
            nxt.update(next_after="c1", unlisted={"runnable": 1, "required_runnable": 1})
        return answer(handler, body)

    with Stub([]) as stub:
        monkeypatch.setattr(stub.server.RequestHandlerClass, "do_GET", do_get)
        assert _run(stub, None, "continue", TARGET, "--all", monkeypatch=monkeypatch) == 0
    out = capsys.readouterr().out
    first_pages = [path for path in pages if "after=" not in path]
    assert len(first_pages) == 2  # started again once after the change
    assert any("after=c2" in path for path in pages) and "101." in out


def test_cursors_are_signed_and_count_what_was_listed():
    from api.hunt import knowledge_continue
    report = lambda: {"next_experiments": {"ranked": _ranked(60), "complete": {"complete": True, "reasons": []}}}  # noqa: E731
    first = knowledge_continue._with_authority(report(), None, 25)["next_experiments"]
    assert first["listed_so_far"] == {"runnable": 25, "outside_authority": 0,
                                      "of": {"runnable": 60, "outside_authority": 0}}
    second = knowledge_continue._with_authority(report(), None, 25, after=first["next_after"])["next_experiments"]
    assert second["listed_so_far"]["runnable"] == 50
    payload, mac = first["next_after"].split(".")
    forged = json.loads(__import__("base64").urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    forged["r"] = [9, 0, 0.0, "zzzz"]  # past the end: would silently show nothing
    tampered = __import__("base64").urlsafe_b64encode(json.dumps(forged).encode()).decode().rstrip("=") + "." + mac
    for bad in (tampered, payload, payload + ".AAAA", "x" * 3000):
        with pytest.raises(knowledge_continue.CursorError):
            knowledge_continue._with_authority(report(), None, 25, after=bad)
