"""GET /session/capabilities: the open-source engine allows every UI control (session-capabilities/v1)."""
from __future__ import annotations

from pathlib import Path
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import session_capabilities  # noqa: E402

DOC = (ROOT / "docs" / "session-capabilities.md").read_text()


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(session_capabilities.router)
    return TestClient(app)


def test_engine_answers_everything_allowed_and_uncached():
    response = _client().get("/session/capabilities")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["schema_version"] == "session-capabilities/v1"
    assert body["source"] == "engine"
    assert body["role"] is None
    assert body["default"] == "allow"
    assert body["pages"] == {} and body["reasons"] == {}
    assert body["actions"] and all(value is True for value in body["actions"].values())


def test_every_documented_action_is_answered_and_none_other():
    documented = {line.split("`")[1] for line in DOC.splitlines()
                  if line.startswith("| `") and "." in line.split("`")[1]
                  and line.split("`")[1].split(".")[0] in {"targets", "scans", "findings", "hunts", "secrets", "records"}}
    assert documented == set(session_capabilities.ACTIONS)


def test_the_engine_app_serves_the_route():
    source = (ROOT / "api" / "api.py").read_text()
    mounted = source.index("app.include_router(session_capabilities_router)")
    # GET /session/{session_id} (interactive sessions) would otherwise take "capabilities" as an id.
    assert mounted < source.index("app.include_router(interactive_router)")
