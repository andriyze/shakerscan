"""Signed-in and body-input Hunt verifiers through admission, the queue and the worker.

A Hunt selects a managed principal at start; its ``sqli.verify`` and ``xss.verify`` calls run as
that principal (or as one of the Hunt's sessions), the worker resolves the identity under the
Hunt's approval and hands the scanner the headers, a verified sqlmap signal is proved with the
Scan's deterministic SQLi proof and becomes a finding that records the principal, and a candidate
citing that action records the principal too. A body test needs the state-changing permission and
is not charged to the state-changing ceiling. A call outside scope, and one without approval, are
still refused.

The database comes from db/init.sql plus the installed startup migration, with a real standing
authorization, a real credential profile (encrypted with a per-test key) and the production routes
and worker. Labelled doubles, and only these: Redis (an in-memory dictionary; the queue hands the
job straight to the worker), the per-call active approval check, the scanner process (it records
the payload, builds the real enforced plan for it and reports a fixed sqlmap/dalfox result without
starting the tool), and the proof's pinned transport (a quote in ``id`` answers with a database
error). No traffic leaves the test.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.test_hunt_live_grant_dispatch_postgres import (  # noqa: E402
    DSN, LEDGER, TARGET_URL, FakeRedis, _database,
)

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

TARGET_ADDRESS = "203.0.113.10"
TOKEN = "Bearer fixture-principal-token"
SESSION_COOKIE = "sid=fixture-session"
CAPABILITIES = ["sqli.verify", "xss.verify", "web.browser_crawl", "web.crawl"]


async def _active_hunt(pool, *, state_changing=False, approved=True, signed_in=True):
    from runtime.credential_store import PostgresCredentialProfileStore
    from runtime.credentials import public_credential_configuration
    import secret_store
    from target_authorization import authorize_target
    from hunt.start_contract import HUNT_BUDGET_PROFILES

    async with pool.acquire() as conn:
        target = await conn.fetchval(
            """INSERT INTO targets(url) VALUES($1)
               ON CONFLICT (url) DO UPDATE SET url=EXCLUDED.url RETURNING id""", TARGET_URL)
        standing = await authorize_target(conn, target, approved_by="alice@example.test")
        now = datetime.now(timezone.utc)
        profile = await PostgresCredentialProfileStore().create_profile(
            conn, target_kind="web", target_id=target, name=f"alice-{uuid.uuid4().hex[:8]}",
            auth_kind="authorization_header",
            principal_slot="primary", principal_label="alice",
            configuration=public_credential_configuration({"auth_kind": "authorization_header"}),
            encrypted_secret=secret_store.encrypt_secret(TOKEN),
            encrypted_metadata=secret_store.encrypt_secret(json.dumps(
                {"schema_version": "credential-private-metadata/v1"})),
            expires_at=now + timedelta(days=1), allowed_capabilities=["http.request", *CAPABILITIES],
            created_by="fixture", now=now - timedelta(minutes=1),
        )
        budget = dict(vars(HUNT_BUDGET_PROFILES["balanced"]))
        policy = {
            "schema_version": "hunt-policy/v2", "target_kind": "web", "active_testing": True,
            "credential_access": signed_in, "allow_state_changing_http": state_changing,
            "network_discovery": False, "allow_oob_interactions": False,
            "allow_identity_headers": False, "allow_direct_origin": False,
            "authorization_confirmed": True,
            "approval_receipt_id": str(standing["approval_receipt_id"]) if approved else None,
            "scope_receipt_id": str(standing["scope_receipt_id"]), "budget_profile": "balanced",
            "budget": budget, "allowed_capabilities": CAPABILITIES,
        }
        credential_refs = [{
            "source": "credential_profiles", "principal_slot": "primary",
            "profile_id": profile.profile_id, "profile_version": profile.current_version,
            "auth_kind": "authorization_header", "allowed_capabilities": ["http.request", *CAPABILITIES],
        }] if signed_in else []
        context = {
            "schema_version": "hunt-context/v2",
            "target": {"id": str(target), "kind": "web", "url": TARGET_URL, "origins": [TARGET_URL],
                       "environment": "production"},
            "authorized_target_addresses": [TARGET_ADDRESS], "credential_refs": credential_refs,
            "allowed_capabilities": CAPABILITIES, "hunt_start_contract": {"resolved_budget": budget},
        }
        row = await conn.fetchrow(
            """INSERT INTO hunt_runs(target_kind,target_id,objective,status,budget_profile,policy_json,
                                     budget_json,budget_used_json,context_pack,created_by,approval_receipt_id)
               VALUES('web',$1,'signed-in verifiers','active','balanced',$2::jsonb,$3::jsonb,$4::jsonb,
                      $5::jsonb,'fixture',$6) RETURNING *""",
            target, json.dumps(policy), json.dumps(budget),
            json.dumps({key: 0 for key in LEDGER}), json.dumps(context),
            uuid.UUID(str(standing["approval_receipt_id"])) if approved else None,
        )
    return dict(row), standing, profile


class ErrorOnQuote:
    """Labelled double: the proof's pinned transport."""

    sent: list = []

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        from runtime.request_replay_executor import ReplayTransportResult

        type(self).sent.append(request)
        quoted = "%27" in request.url
        return ReplayTransportResult(
            status_code=500 if quoted else 200, connected_address=TARGET_ADDRESS,
            final_url=request.url, response_body=b"SQLITE_ERROR: unrecognized token" if quoted else b"ok",
            elapsed_ms=4,
        )


@pytest.fixture
def stack(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store

    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)
    import agent_tools as worker_agent_tools
    import worker
    from hunt import interaction_router as router
    from hunt import scanner_sqli_proof

    loop = asyncio.new_event_loop()
    pool, drop = loop.run_until_complete(_database())
    redis = FakeRedis()
    workers: list[asyncio.Task] = []
    processes: list[dict] = []
    records: list[dict] = []

    def enqueue(_redis, _queue, payload):
        workers.append(asyncio.get_running_loop().create_task(
            worker.process_canonical_scanner_capability_job(payload)
        ))

    async def process(payload, *, heartbeat=None):  # labelled double: the scanner process
        plan = worker_agent_tools.build_enforced_scanner_plan(
            payload["tool_name"], payload["execution_target"], dict(payload["scanner_options"]),
            reserved_budget=payload["_reserved_budget"], pinned_address=payload["pinned_address"],
            pinned_proxy_url="socks5://127.0.0.1:41000", trusted_headers=payload.get("trusted_headers"),
            runtime_paths={"sqlmap_output_dir": "/tmp/fixture-sqlmap", "scratch_dir": "/tmp/fixture"},
        )
        processes.append({**{k: v for k, v in payload.items() if k != "_cancelled"},
                          "argv": list(plan.argv)})
        sent = min(432, int(plan.hard_budget_dict.get("http_requests") or 0))
        return {
            "status": "success", "error": None, "partial": False, "timed_out": False,
            "elapsed_seconds": 200, "process_enforcement": plan.enforcement_receipt(),
            "settlement": {"mode": "exact", "actual": sent, "observed_minimum": sent, "source": "wire_log"},
            "typed_output": {"parser_status": "parsed", "records": list(records),
                             "record_count": len(records)},
        }

    async def approval(*_args, **_kwargs):  # labelled double: the per-call active approval
        return {"scope_receipt_id": state["scope_receipt_id"]}

    state: dict = {}
    ErrorOnQuote.sent = []
    monkeypatch.setattr(router, "_pool", lambda: pool)
    monkeypatch.setattr(router, "get_redis", lambda: redis)
    monkeypatch.setattr(router, "enqueue_job", enqueue)
    monkeypatch.setattr(router, "_hunt_redacted_capability_input", lambda _name, values: dict(values))
    monkeypatch.setitem(router._deps, "AGENT_TOOL_QUEUE_NAME", lambda: "agent-tools-fixture")
    monkeypatch.setitem(router._deps, "_validate_approval_receipt_for_action", lambda: approval)
    monkeypatch.setattr(worker, "db_pool", pool)
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "RESULTS_DIR", Path("/tmp"))
    monkeypatch.setattr(worker, "_execute_agent_scanner_process", process)
    monkeypatch.setattr(scanner_sqli_proof, "PinnedAiohttpReplayTransport", ErrorOnQuote)

    class Stack:
        pass

    env = Stack()
    env.pool, env.loop, env.router, env.state = pool, loop, router, state
    env.workers, env.processes, env.records = workers, processes, records
    yield env
    loop.run_until_complete(drop())
    loop.close()


async def _call(stack, hunt, name, key, values):
    from fastapi import HTTPException

    request = stack.router.HuntCapabilityRequest(idempotency_key=key, input=values)
    try:
        return await stack.router.execute_hunt_capability(str(hunt["id"]), name, request)
    except HTTPException as exc:
        return exc
    finally:
        if stack.workers:
            await asyncio.gather(*stack.workers)
            stack.workers.clear()


def _action_id(hunt, key):
    return uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")


def _decode(value):
    return json.loads(value) if isinstance(value, str) else dict(value or {})


def test_a_signed_in_sqli_verify_runs_as_its_principal_and_its_proof_becomes_a_finding(stack):
    stack.records.append({"kind": "sqli_finding", "param": "id", "method": "GET",
                          "message": "GET parameter 'id' is vulnerable", "proof_state": "candidate"})

    async def scenario():
        hunt, standing, profile = await _active_hunt(stack.pool)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        result = await _call(stack, hunt, "sqli.verify", "signed-sqli-0001",
                             {"path": "/item?id=1", "as_principal": "primary"})
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", result
        (process,) = stack.processes
        assert process["trusted_headers"] == {"Authorization": TOKEN}
        assert process["argv"][process["argv"].index("--headers") + 1] == f"Authorization: {TOKEN}"
        # The proof replayed the same request, signed in.
        assert len(ErrorOnQuote.sent) == 4
        assert all(("Authorization", TOKEN) in request.headers for request in ErrorOnQuote.sent)
        action = _action_id(hunt, "signed-sqli-0001")
        async with stack.pool.acquire() as conn:
            finding = await conn.fetchrow("SELECT * FROM findings WHERE hunt_run_id=$1", hunt["id"])
            uses = await conn.fetch("SELECT slot, profile_id FROM hunt_credential_uses WHERE action_id=$1", action)
            summary = _decode(await conn.fetchval("SELECT result_summary FROM hunt_actions WHERE id=$1", action))
            reservation = await conn.fetchrow(
                "SELECT requested_json, actual_json FROM budget_reservations WHERE action_id=$1", str(action))
            archived = await conn.fetch(
                "SELECT principal_slot FROM http_transactions WHERE hunt_action_id=$1", action)
        assert finding is not None and finding["tool"] == "shakerscan_sqli_proof"
        assert (finding["severity"], finding["cwe"]) == ("critical", "CWE-89")
        evidence = _decode(finding["evidence"])
        assert evidence["evidence_principals"] == ["primary"]
        assert evidence["proof_contract"] == "sqli_error_differential/v2" and evidence["param"] == "id"
        assert summary["verified_finding_ids"] == [str(finding["id"])]
        assert summary["as_principal"] == "primary"
        assert [(row["slot"], str(row["profile_id"])) for row in uses] == [("primary", profile.profile_id)]
        # sqlmap's measured requests plus the proof's, inside the action's own hold.
        assert _decode(reservation["actual_json"])["http_requests"] == 432 + 4
        assert "state_changing_requests" not in _decode(reservation["requested_json"])
        assert {row["principal_slot"] for row in archived} == {"primary"}
        assert "fixture-principal-token" not in json.dumps([evidence, summary])

        # A candidate citing the signed-in action records the principal for retests.
        from hunt.interaction_router import HuntCandidateRequest, create_hunt_candidate
        created = await create_hunt_candidate(str(hunt["id"]), HuntCandidateRequest(
            family="sqli", locus={"route": "/item", "parameter": "id"}, title="SQL injection in id",
            claim="id reaches a SQL query", evidence_refs=[f"action:{action}"],
        ))
        async with stack.pool.acquire() as conn:
            context = _decode(await conn.fetchval(
                "SELECT verification_context FROM investigation_candidates WHERE id=$1::uuid",
                created["candidate"]["id"]))
        assert context["evidence_principals"] == ["primary"]

    stack.loop.run_until_complete(scenario())


def test_a_body_sqli_verify_needs_the_state_changing_permission_and_runs_with_its_body(stack):
    body = {"path": "/login", "method": "POST", "body_field_names": ["username", "password"],
            "injection_field": "username"}

    async def scenario():
        hunt, standing, _profile = await _active_hunt(stack.pool, state_changing=False)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        refused = await _call(stack, hunt, "sqli.verify", "body-sqli-0001", body)
        assert isinstance(refused, Exception)
        assert refused.detail["reason_code"] == "state_changing_http_not_allowed"
        assert stack.processes == []

        hunt, standing, _profile = await _active_hunt(stack.pool, state_changing=True)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        result = await _call(stack, hunt, "sqli.verify", "body-sqli-0002", body)
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", (
            result["action_result"].get("errors"), result.get("result"))
        (process,) = stack.processes
        argv = process["argv"]
        assert argv[argv.index("--data") + 1] == "username=shakerscan&password=shakerscan"
        assert argv[argv.index("-p") + 1] == "username,password"
        assert process["trusted_headers"] == {}
        async with stack.pool.acquire() as conn:
            used = _decode(await conn.fetchval("SELECT budget_used_json FROM hunt_runs WHERE id=$1", hunt["id"]))
        # Verifier traffic is counted in its own hold, not in the state-changing ceiling.
        assert used["http_requests"] == 432 and used.get("state_changing_requests", 0) == 0

    stack.loop.run_until_complete(scenario())


def test_an_xss_verify_runs_with_a_session_of_the_hunt(stack):
    async def scenario():
        import secret_store

        hunt, standing, profile = await _active_hunt(stack.pool)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        from hunt.target_binding import web_hunt_target
        from runtime.auth_session_store import session_target_digest

        binding, _url = web_hunt_target(hunt, _decode(hunt["context_pack"]), _decode(hunt["policy_json"]))
        session = uuid.uuid4()
        now = datetime.now(timezone.utc)
        async with stack.pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO auth_sessions (id, owner_kind, owner_id, target_kind, target_id,
                       target_binding_digest, service_origin, profile_id, profile_version, principal_slot,
                       principal_label, auth_kind, compatible_capabilities, encrypted_headers, status,
                       established_at, expires_at, refresh_after, evidence_receipt_digest, source_action_id)
                   VALUES ($1,'hunt',$2,'web',$3,$4,$5,$6,1,'primary','alice','form_login',
                           '["xss.verify"]'::jsonb,$7,'active',$8,$9,$10,$11,$12)""",
                session, hunt["id"], hunt["target_id"], session_target_digest(binding, "hunt"), TARGET_URL,
                uuid.UUID(profile.profile_id),
                secret_store.encrypt_secret(json.dumps({"Cookie": SESSION_COOKIE})),
                now - timedelta(minutes=1), now + timedelta(hours=1), now + timedelta(minutes=30),
                "b" * 64, uuid.uuid4(),
            )
        result = await _call(stack, hunt, "xss.verify", "session-xss-0001",
                             {"path": "/search?q=x", "session_ref": str(session)})
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", (
            result["action_result"].get("errors"), result.get("result"))
        (process,) = stack.processes
        assert process["trusted_headers"] == {"Cookie": SESSION_COOKIE}
        assert f"Cookie: {SESSION_COOKIE}" in process["argv"]
        action = _action_id(hunt, "session-xss-0001")
        async with stack.pool.acquire() as conn:
            summary = _decode(await conn.fetchval("SELECT result_summary FROM hunt_actions WHERE id=$1", action))
        assert summary["as_principal"] == "primary"

    stack.loop.run_until_complete(scenario())


def test_scope_approval_and_uncarriable_sessions_are_still_refused(stack):
    async def scenario():
        hunt, standing, _profile = await _active_hunt(stack.pool)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        browser = await _call(stack, hunt, "web.browser_crawl", "browser-crawl-0001", {"as_principal": "primary"})
        assert browser.status_code == 422 and "as_principal" in str(browser.detail)
        other = await _call(stack, hunt, "sqli.verify", "other-host-0001", {
            "path": "/item?id=1", "as_principal": "primary", "origin": "https://elsewhere.example.net"})
        assert isinstance(other, Exception) and other.detail["reason_code"].startswith("scope_")
        unapproved, standing, _profile = await _active_hunt(stack.pool, approved=False)
        refused = await _call(stack, unapproved, "sqli.verify", "no-approval-0001",
                              {"path": "/item?id=1", "as_principal": "primary"})
        assert isinstance(refused, Exception)
        assert refused.detail["reason_code"] == "approval_receipt_required"
        assert stack.processes == []

    stack.loop.run_until_complete(scenario())


def test_a_signed_in_crawl_holds_the_approval_unit_admission_charged(stack):
    """A read-only scanner is approval-gated once it runs signed in: admission charges one
    active action, and the worker re-derives the same hold, so the action digest matches."""
    async def scenario():
        hunt, standing, _profile = await _active_hunt(stack.pool)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        result = await _call(stack, hunt, "web.crawl", "signed-crawl-0001", {"as_principal": "primary"})
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", (
            result["action_result"].get("errors"), result.get("result"))
        (process,) = stack.processes
        assert process["trusted_headers"] == {"Authorization": TOKEN}
        action = _action_id(hunt, "signed-crawl-0001")
        async with stack.pool.acquire() as conn:
            requested = _decode(await conn.fetchval(
                "SELECT requested_json FROM budget_reservations WHERE action_id=$1", str(action)))
        assert requested["active_actions"] == 1

    stack.loop.run_until_complete(scenario())
