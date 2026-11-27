"""MCP -> the actual FastAPI Hunt query route, for kind=changes (the change report itself is stubbed:
unit fixture; the PostgreSQL path is in tests/test_knowledge_changes_postgres.py)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_mcp_query_kind_changes_reaches_the_real_route(monkeypatch):
    pytest.importorskip("fastapi")
    from contextlib import asynccontextmanager
    from fastapi.testclient import TestClient
    from api import api as api_module
    from api.hunt import knowledge_changes

    spec = importlib.util.spec_from_file_location("shakerscan_mcp_changes", ROOT / "scripts" / "shakerscan_mcp.py")
    mcp = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mcp
    spec.loader.exec_module(mcp)
    target, hunt = uuid.UUID(int=7), uuid.UUID(int=9)
    seen = {}

    async def report(conn, target_id, **kwargs):
        seen.update(target_id=target_id, **kwargs)
        return {"ok": True, "kind": "changes", "since": {"kind": kwargs["since"]}, "sections": {},
                "knowledge": {"affected": []}}
    monkeypatch.setattr(knowledge_changes, "target_changes", report)
    for name in ("hunt.knowledge_changes", "api.hunt.knowledge_changes"):
        if name in sys.modules:  # whichever import layout the app module loaded
            monkeypatch.setattr(sys.modules[name], "target_changes", report)

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield object()

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
    assert "changes" in tool.properties["kind"]["enum"]
    answer = Client(TestClient(api_module.app)).call_tool(
        "shakerscan_hunt_query", {"hunt_id": str(hunt), "kind": "changes", "filter": {"since": "release"}})
    assert answer["structuredContent"]["since"] == {"kind": "release"}
    assert seen["target_id"] == target and seen["current_hunt_id"] == str(hunt) and seen["device"] is False
