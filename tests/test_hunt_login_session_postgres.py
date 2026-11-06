"""A Hunt's own login session, on real PostgreSQL: the capture is sealed on the action row and
read back by a later request, and a signed-in ``artifact.inspect`` is admitted like the
``http.request`` it could have been.

Admission runs through the real ``_execute_hunt_capability_lifecycle`` (the permission-request
harness of test_hunt_permission_requests_postgres: labelled doubles for the approval-receipt
validator, no DNS, no worker). No request leaves the test. Values are synthetic.
"""
from __future__ import annotations

from pathlib import Path as _Path
import sys as _sys

# Collected alone (without the suite runner's PYTHONPATH), the engine's modules import by their
# source-tree names: put api/ and scanner/ on the path as the runner does (appended, so a layout
# that already resolves them is unchanged).
for _root in (_Path(__file__).resolve().parents[1] / "api", _Path(__file__).resolve().parents[1] / "scanner"):
    if str(_root) not in _sys.path:
        _sys.path.append(str(_root))

import json
from types import SimpleNamespace
import uuid

import pytest
from fastapi import HTTPException

from runtime.hunt_http_exchange import HttpWorkflowExchange, captured_binding, sealed_hunt_knowledge
from runtime.models import TargetBinding
from tests.test_hunt_permission_requests_postgres import DSN, permission_environment

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

SESSION = "hs-2c9e7a41f0b84d3e9a6c1b5d7e2f8a03"
ACTIVE = {"active_testing": True, "allow_state_changing_http": True,
          "approval_receipt_id": str(uuid.uuid4()), "authorization_confirmed": True}


@pytest.fixture
def env(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)
    yield from permission_environment(monkeypatch)


def run(env, coroutine):
    return env.loop.run_until_complete(coroutine)


def _binding(action_id):
    return [{"source_action_id": str(action_id), "capture_name": "session", "header": "Cookie"}]


def test_a_login_cookie_is_sealed_on_its_action_and_read_back_by_a_later_request(env):
    async def scenario():
        hunt = await env.hunt(policy=ACTIVE, budget={"max_active_actions": 10, "max_state_changing_requests": 10})
        action_id = await env.conn.fetchval(
            """INSERT INTO hunt_actions(hunt_run_id, capability_name, status) VALUES($1,'http.request','completed')
               RETURNING id""", hunt["id"])
        target = TargetBinding(target_id=str(hunt["target_id"]), target_kind="web",
                               canonical_host="app.example.test", allowed_origins=("https://app.example.test",),
                               allowed_addresses=("203.0.113.10",), allowed_root_domains=("example.test",),
                               environment="production")
        state = HttpWorkflowExchange(str(hunt["id"]), str(action_id), target,
                                     ({"name": "session", "header": "Set-Cookie"},))
        state.capture_response(SimpleNamespace(status_code=303, headers=lambda: {"location": "/hub/"},
            body=lambda: b"", cookies=lambda: {"hub_session": SESSION}))
        await state.persist(env.conn, run=hunt, status="success")
        stored = await env.conn.fetchval("SELECT private_http_result FROM hunt_actions WHERE id=$1", action_id)
        assert stored.startswith("enc:fernet:") and SESSION not in stored
        value, is_cookie = await captured_binding(env.conn, run_id=str(hunt["id"]), target=target,
            binding={"source_action_id": str(action_id), "capture_name": "session"})
        assert (value, is_cookie) == (f"hub_session={SESSION}", True)
        # A later response that echoes the bare cookie value withholds it too.
        knowledge = await sealed_hunt_knowledge(env.conn, run_id=hunt["id"], target=target)
        assert SESSION in knowledge["values"]
        row = await env.conn.fetchrow("SELECT * FROM hunt_actions WHERE id=$1", action_id)
        assert SESSION not in json.dumps(dict(row), default=str).replace(stored, "")
    run(env, scenario())


def test_a_signed_in_artifact_read_is_admitted_like_an_http_request(env):
    async def scenario():
        passive = await env.hunt()
        # Anonymous reads stay passive and need nothing.
        assert await env.call(passive, "inspect-anon-01", name="artifact.inspect",
                              values={"path": "/hub/login"}) == "admitted"
        # Sending a captured cookie is a workflow binding: active testing, refused at no cost.
        with pytest.raises(HTTPException) as refused:
            await env.call(passive, "inspect-bound-01", name="artifact.inspect",
                           values={"path": "/hub/admin", "request_bindings": _binding(uuid.uuid4())})
        assert refused.value.status_code == 403 and "active_testing" in str(refused.value.detail)
        assert await env.action(passive, "inspect-bound-01") is None
        # A session needs the Hunt's approval receipt, as for http.request.
        with pytest.raises(HTTPException):
            await env.call(passive, "inspect-session-01", name="artifact.inspect",
                           values={"path": "/hub/admin", "session_ref": str(uuid.uuid4())})
        active = await env.hunt(policy=ACTIVE, budget={"max_active_actions": 10})
        assert await env.call(active, "inspect-bound-02", name="artifact.inspect",
                              values={"path": "/hub/admin", "request_bindings": _binding(uuid.uuid4())}) == "admitted"
        reserved = await env.conn.fetchval(
            "SELECT requested_json FROM budget_reservations WHERE owner_id=$1", str(active["id"]))
        reserved = json.loads(reserved) if isinstance(reserved, str) else reserved
        assert reserved.get("active_actions") == 1
    run(env, scenario())
