"""Conditions checked against the cited action, the continue report's cache flag, the continuation
measures' CLI and the pre-Hunt MCP continue tool.

Unit fixtures: synthetic action rows (not database rows), a loopback stub of the operator routes
(not an engine) and a recording MCP client. The PostgreSQL path through the real app is
tests/test_continuation_measures_postgres.py.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import v2_cli  # noqa: E402

from hunt import knowledge_continue  # noqa: E402
from hunt.condition_receipts import check_action, check_conditions, route_matches  # noqa: E402
from hunt.knowledge_measures import snapshot_of  # noqa: E402

TARGET = "11111111-1111-4111-8111-111111111111"
ORIGIN = "https://app.test"


def _action(path: str = "/api/invoices/17", *, method: str = "GET", capability: str = "http.request",
            session: str | None = "sess-1", principal: str | None = "profile:p@v1/primary/alice",
            origin: str | None = None, **extra: Any) -> dict[str, Any]:
    """Fixture: one cited action row as the condition check reads it."""
    values = {"method": method, "path": path, **({"session_ref": session} if session else {}),
              **({"origin": origin} if origin else {}), **extra}
    return {"id": "a-1", "capability_name": capability, "input_summary": {"input": values},
            "default_origin": ORIGIN, "principal": principal if session else None}


CONDITIONS = {"origin": ORIGIN, "method": "GET", "route": "/api/invoices/{id}", "principals": ["sess-1"],
              "objects": ["invoice:17"], "technique": "http.request cross-tenant read"}


def test_routes_match_by_segment_and_placeholder():
    assert route_matches("/api/invoices/{id}", "/api/invoices/17")
    assert route_matches("api/invoices/{id}", "/api/invoices/17/")
    assert route_matches("/api/users/all", "/api/users/all")
    assert route_matches("/search?q=x", "/search")  # the query string is not compared
    assert not route_matches("/api/invoices/{id}", "/api/orders/17")
    assert not route_matches("/api/invoices/{id}", "/api/invoices/17/items")
    assert not route_matches("/api/invoices/{id}", "/api/invoices/")


def test_the_cited_request_confirms_or_contradicts_each_field():
    assert check_action(CONDITIONS, _action()) == {
        "technique": "matched", "method": "matched", "route": "matched", "origin": "matched", "principals": "matched"}
    assert check_action({**CONDITIONS, "method": "POST"}, _action())["method"] == "contradicted"
    assert check_action({**CONDITIONS, "route": "/api/orders/{id}"}, _action())["route"] == "contradicted"
    assert check_action({**CONDITIONS, "origin": "https://app.test:8443"}, _action())["origin"] == "contradicted"
    assert check_action({**CONDITIONS, "technique": "browser.navigate x"}, _action())["technique"] == "contradicted"
    # A technique that names no capability, and roles or objects, cannot be checked against a request.
    assert check_action({**CONDITIONS, "technique": "manual review"}, _action())["technique"] == "not_checkable"
    # Principals: the session store's identity, its label or slot match; another name is unverified.
    assert check_action({**CONDITIONS, "principals": ["alice"]}, _action())["principals"] == "matched"
    assert check_action({**CONDITIONS, "principals": ["admin"]}, _action())["principals"] == "unverified"
    assert check_action({**CONDITIONS, "principals": ["anonymous"]}, _action())["principals"] == "contradicted"
    anonymous = _action(session=None)
    assert check_action({**CONDITIONS, "principals": ["anonymous"]}, anonymous)["principals"] == "matched"
    assert check_action(CONDITIONS, anonymous)["principals"] == "contradicted"
    # Credentials sent by header without a session: the principal cannot be read from the request.
    headered = _action(session=None, headers={"Authorization": "[redacted]"})
    assert check_action(CONDITIONS, headered)["principals"] == "not_checkable"
    # Another capability: only the technique can be compared.
    other = check_action(CONDITIONS, _action(capability="authz.verify"))
    assert other["technique"] == "contradicted" and other["route"] == "not_checkable"


def test_one_consistent_cited_action_is_enough_and_contradictions_are_named():
    unrelated = {**_action("/api/orders/5"), "id": "a-2"}
    found = check_conditions(CONDITIONS, [unrelated, _action()], ["a-1", "a-2"])
    assert found["consistent"] is True and found["checked_against"] == "a-1"
    refused = check_conditions(CONDITIONS, [unrelated], ["a-2"])
    assert refused["consistent"] is False
    assert refused["contradictions"] == [{"action_id": "a-2", "fields": ["route"]}]
    # Actions that are not the cited testing actions are never used to confirm anything.
    assert check_conditions(CONDITIONS, [_action()], ["a-2"])["consistent"] is True  # nothing comparable


def test_a_snapshot_keeps_identities_of_required_retests_and_changed_routes_only():
    ranked = [
        {"rule": "revalidate_changed", "required_retest": True, "capability": "http.request", "principal": "anonymous",
         "input": {"method": "GET", "path": "/api/invoices/17", "origin": ORIGIN},
         "basis": {"type": "interpretation", "id": "e-1", "caused_by": [{"type": "response"}]}},
        {"rule": "reobserve_since_release", "required_retest": True, "capability": "authz.verify", "input": None,
         "conditions": {"operation": "GET /api/orders/{id}"}, "basis": {"type": "authorization_investigation",
                                                                         "id": "p-1"}},
        {"rule": "new_auth_surface", "required_retest": False, "capability": "http.request",
         "input": {"method": "GET", "path": "/sso/start"}, "basis": {"type": "endpoint", "id": "x"}},
        {"rule": "agent_next_step", "required_retest": False, "capability": None, "input": None,
         "basis": {"type": "interpretation", "id": "n-1", "notice": "a claim"}},
    ]
    required, routes = snapshot_of(ranked)
    assert [item["basis"] for item in required] == [{"type": "interpretation", "id": "e-1"},
                                                    {"type": "authorization_investigation", "id": "p-1"}]
    assert required[0]["path"] == "/api/invoices/17" and required[0]["origin"] == ORIGIN
    assert required[1]["method"] == "GET" and required[1]["path"] == "/api/orders/{id}"
    assert routes == [{"method": "GET", "path": "/sso/start", "rule": "new_auth_surface"}]
    assert "a claim" not in json.dumps([required, routes])


def test_the_continue_report_says_when_it_was_served_from_the_cache(monkeypatch):
    built = []

    async def build(conn, target_id, **kwargs):
        built.append(target_id)
        return {"target_id": target_id, "since": {}, "next_experiments": {
            "ranked": [], "complete": {"complete": True, "reasons": []}}}
    monkeypatch.setattr(knowledge_continue, "_continue_report", build)
    knowledge_continue._cache.clear()

    async def run():
        first = await knowledge_continue.continue_report(None, TARGET, device=True)
        second = await knowledge_continue.continue_report(None, TARGET, device=True)
        return first, second
    first, second = asyncio.run(run())
    assert built == [TARGET]
    assert first["cache"]["cached"] is False and first["cache"]["age_seconds"] == 0.0
    assert second["cache"]["cached"] is True and 0 <= second["cache"]["age_seconds"] < 10
    assert second["cache"]["max_age_seconds"] == knowledge_continue.REPORT_CACHE_SECONDS


class Stub:
    """Loopback stub of the continue, measures and usage routes (unit fixture)."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.seen: list[str] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                stub.seen.append(self.path)
                body = next((value for key, value in answers.items() if key in self.path), {})
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "Stub":
        self.thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"


def test_continue_prints_that_the_report_came_from_the_cache(capsys):
    report = {"kind": "continue", "built_at": "2026-10-15T10:00:00+00:00", "since": {"resolved": True, "at": "x"},
              "cache": {"cached": True, "age_seconds": 4.2, "max_age_seconds": 10.0},
              "next_experiments": {"items": [], "required_retests": {}}, "knowledge": {}, "changes": {}}
    with Stub({"/knowledge/continue": report}) as stub:
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "continue", TARGET]) == 0
        out = capsys.readouterr().out
        assert "Served from the engine's cache: built 4.2 s ago" in out
        fresh = {**report, "cache": {"cached": False, "age_seconds": 0.0, "max_age_seconds": 10.0}}
    with Stub({"/knowledge/continue": fresh}) as stub:
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "continue", TARGET]) == 0
        assert "Served from the engine's cache" not in capsys.readouterr().out


def test_measures_and_usage_print_what_the_engine_measured(capsys):
    measures = {
        "kind": "continue_measures", "since": {"kind": "release", "at": "2026-10-01T00:00:00+00:00"},
        "reads": {"total": 3, "operators": 1, "hunts": 1}, "started_at": "2026-10-02T00:00:00+00:00",
        "started_by": "operator",
        "required_retests": {"listed_at_start": 2, "run": 1, "not_run": 1, "not_run_items": [
            {"rule": "reobserve_since_release", "method": "GET", "path": "/api/orders/{id}\x1b[2J",
             "basis": {"type": "interpretation", "id": "e-2"}}]},
        "first_useful_step": {"seconds": 42.5, "action_id": "a-1"},
        "redundant_requests": {"requests_after_start": 10, "redundant": 2, "share": 0.2},
        "new_results": {"findings_first_seen_total": 1, "changed_outcomes": [
            {"id": "e-3", "outcome": "observation", "earlier_outcome": "experiment_completed_negative"}]},
        "incorrect_suppression": {"skip_advice": 1, "contradicted": 0, "items": []},
    }
    usage = {"items": [{"week": "2026-W41", "operators": 3, "hunts": 4, "targets": 2, "reads": 9}]}
    with Stub({"/continue/measures": measures, "/continue/usage": usage}) as stub:
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "measures", TARGET]) == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "required re-tests listed at the start: 2, run 1, not run 1" in out
        assert "first useful step: 42.5 s after the start" in out
        assert "redundant requests: 2 of 10 (20.0%)" in out
        assert "experiment_completed_negative -> observation" in out
        assert "later contradicted (incorrect suppression, expected 0): 0" in out
        assert v2_cli.main(["--api-url", stub.url, "knowledge", "usage", "--weeks", "4"]) == 0
        assert "2026-W41: operators 3, Hunts 4, targets 2, reads 9" in capsys.readouterr().out
        assert any(path.startswith(f"/targets/{TARGET}/knowledge/continue/measures?since=release")
                   for path in stub.seen)
        assert "/knowledge/continue/usage?weeks=4" in stub.seen


def test_the_pre_hunt_mcp_tool_reads_the_operator_route():
    spec = importlib.util.spec_from_file_location("shakerscan_mcp_measures", ROOT / "scripts" / "shakerscan_mcp.py")
    mcp = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mcp
    spec.loader.exec_module(mcp)
    calls: list[tuple[str, str, Any]] = []

    class Client(mcp.ArsenalClient):
        def __init__(self) -> None:
            super().__init__("http://127.0.0.1:8080")

        def request_json(self, method, path, payload=None):
            calls.append((method, path, payload))
            return {"kind": "continue", "next_experiments": {"items": []}, "cache": {"cached": False}}

    tool = next(item for item in mcp.HUNT_TOOLS if item.name == "shakerscan_knowledge_continue")
    descriptor = tool.descriptor()
    assert descriptor["annotations"]["readOnlyHint"] is True and descriptor["inputSchema"]["required"] == ["target_id"]
    answer = Client().call_tool("shakerscan_knowledge_continue", {"target_id": TARGET, "since": "last_hunt", "limit": 5})
    assert answer["structuredContent"]["kind"] == "continue"
    assert calls == [("GET", f"/targets/{TARGET}/knowledge/continue?since=last_hunt&limit=5", None)]
    with pytest.raises(mcp.MCPError):
        Client().call_tool("shakerscan_knowledge_continue", {"target_id": TARGET, "hunt_id": TARGET})
