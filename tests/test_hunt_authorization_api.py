"""ASGI + relational persistence tests for the reference-only authorization API.

Only the canonical worker boundary is replaced. Actual routes, services, SQL,
proposal bindings, attempts, attribution and resume projections execute here.
These are not a deployed-worker/PostgreSQL efficacy benchmark.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from api.hunt.authorization_evidence import AuthorizationWorkflowError, canonical_action_id, digest
from api.hunt.authorization_router import authorization_service, router
from api.hunt.authorization_service import AuthorizationInvestigationService


def ident(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"shakerscan:authz-tests:{name}"))


HUNT, OTHER_HUNT, TARGET = ident("hunt"), ident("other-hunt"), ident("target")
OWNER_SESSION, ACTOR_SESSION = ident("owner-session"), ident("actor-session")
CAPTURE, BASELINE = ident("capture"), ident("baseline")
ORIGIN = "https://fixture.example.test"


class RelationalPool:
    """SQLite executes the repository SQL; only PostgreSQL syntax is adapted."""
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.calls = []
        self.lock = asyncio.Lock()
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS hunt_runs(id TEXT PRIMARY KEY,target_id TEXT,device_target_id TEXT,target_kind TEXT,status TEXT,context_pack TEXT);
        CREATE TABLE IF NOT EXISTS auth_sessions(id TEXT PRIMARY KEY,owner_kind TEXT,owner_id TEXT,target_id TEXT,target_kind TEXT,principal_slot TEXT,status TEXT,expires_at TEXT,profile_id TEXT,profile_version INTEGER,refresh_count INTEGER,target_binding_digest TEXT,encrypted_headers TEXT);
        CREATE TABLE IF NOT EXISTS application_graph_nodes(id TEXT PRIMARY KEY,target_id TEXT,node_type TEXT,node_key TEXT,label TEXT,attributes TEXT,first_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(target_id,node_type,node_key));
        CREATE TABLE IF NOT EXISTS hunt_actions(id TEXT PRIMARY KEY,hunt_run_id TEXT,capability_name TEXT,status TEXT,input_summary TEXT,result_summary TEXT,receipt_id TEXT,started_at TEXT DEFAULT CURRENT_TIMESTAMP,completed_at TEXT);
        CREATE TABLE IF NOT EXISTS http_transactions(id TEXT PRIMARY KEY,hunt_run_id TEXT,hunt_action_id TEXT,sequence INTEGER,method TEXT,url TEXT,principal_slot TEXT,request_body_bytes INTEGER,status_code INTEGER,error TEXT,truncated INTEGER);
        """)

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        async with self.lock:
            self.db.execute("BEGIN")
            try:
                yield self
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            else:
                self.db.execute("COMMIT")

    def _query(self, sql, args):
        self.calls.append((sql, args))
        sql = sql.replace("::jsonb", "").replace(" FOR UPDATE", "").replace("NOW()", "CURRENT_TIMESTAMP")
        params = {str(i): str(v) if isinstance(v, uuid.UUID) else v for i, v in enumerate(args, 1)}
        return self.db.execute(sql, params)

    async def fetchrow(self, sql, *args):
        return self._query(sql, args).fetchone()

    async def fetch(self, sql, *args):
        return self._query(sql, args).fetchall()

    async def execute(self, sql, *args):
        self._query(sql, args)

    def seed(self):
        context = json.dumps({"target": {"url": ORIGIN, "origins": [ORIGIN]}, "authorized_target_addresses": ["192.0.2.1"]})
        for hid in (HUNT, OTHER_HUNT):
            self.db.execute("INSERT INTO hunt_runs VALUES(?,?,NULL,'web','active',?)", (hid, TARGET, context))
        for session, slot in ((OWNER_SESSION, "primary"), (ACTOR_SESSION, "secondary")):
            self.db.execute("INSERT INTO auth_sessions VALUES(?,'hunt',?,?,'web',?,'active','2099-01-01',?,1,0,?,?)",
                            (session, HUNT, TARGET, slot, ident(slot), "a" * 64, "MUST_NOT_READ_SECRET"))
        for cid, path, slot, session in ((CAPTURE, "/orders/1001", "primary", OWNER_SESSION),
                                          (BASELINE, "/orders", "secondary", ACTOR_SESSION)):
            source = ident("source:" + cid)
            self.db.execute("INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary) VALUES(?,?,'http.request','completed',?)",
                            (source, HUNT, json.dumps({"input": {"method": "GET", "path": path, "session_ref": session}})))
            self.capture(cid, path, slot, hunt_action_id=source)

    def capture(self, cid, path, slot, **overrides):
        values = dict(id=cid, hunt_run_id=HUNT, hunt_action_id=None, sequence=1, method="GET",
                      url=ORIGIN + path, principal_slot=slot, request_body_bytes=0,
                      status_code=200, error=None, truncated=0)
        values.update(overrides)
        self.db.execute(f"INSERT INTO http_transactions ({','.join(values)}) VALUES({','.join('?' for _ in values)})", tuple(values.values()))


def proof_url(value, *, base_origin, object_id=None):
    # Controlled test data only. Production injects the existing authz._public_proof_url,
    # which additionally applies ShakerScan's canonical path/query redactor.
    parts = urlsplit(value)
    path = "/".join("<owner-object>" if segment == object_id else segment for segment in parts.path.split("/"))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


class CanonicalWorkerBoundary:
    """Persist canonical-shaped records; never give the workflow a trusted return flag."""
    def __init__(self, pool, mode="verified"):
        self.pool, self.mode = pool, mode
        self.calls = []
        self.executions = 0
        self.raise_before = False
        self.raise_after = False

    async def __call__(self, hunt_id, key, inputs):
        self.calls.append((hunt_id, key, dict(inputs)))
        if self.raise_before:
            self.raise_before = False
            raise RuntimeError("simulated failure before canonical admission")
        action_id = str(canonical_action_id(hunt_id, key))
        if self.pool.db.execute("SELECT id FROM hunt_actions WHERE id=?", (action_id,)).fetchone():
            return {"action_id": action_id}
        self.executions += 1
        baseline, selected = inputs["routes"]
        selected_id = urlsplit(selected).path.rstrip("/").rsplit("/", 1)[-1]
        observed_id = "9999" if self.mode == "other_object" else selected_id
        observed_baseline = ORIGIN + "/other" if self.mode == "other_collection" else baseline
        observed_object = observed_baseline.rstrip("/") + "/" + observed_id
        observation = dict(kind="authz_differential", proof_state="verified", proof_type="cross_principal_replay",
                           method="GET", principal_contexts_distinct=True,
                           object_absent_from_secondary_listing=True, responses_equivalent=True,
                           resource_id_sha256=hashlib.sha256(observed_id.encode()).hexdigest(),
                           producer_url=proof_url(observed_baseline, base_origin=ORIGIN),
                           consumer_url=proof_url(observed_object, base_origin=ORIGIN, object_id=observed_id),
                           owner_status=200, attacker_status=200)
        summary = {"observation": observation}
        if self.mode in {"denied", "error", "expired", "shared", "aggregate_only"}:
            summary = {"replays_completed": 1, "vulnerable": False}
        if self.mode == "contradictory":
            observation["object_absent_from_secondary_listing"] = False
        status = "blocked" if self.mode == "blocked" else "completed"
        receipt_id = None if self.mode == "missing_receipt" else ident("receipt:" + action_id)
        self.pool.db.execute("INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary,result_summary,receipt_id,completed_at) VALUES(?,?,'authz.verify',?,?,?,?,?)",
                             (action_id, hunt_id, status,
                              json.dumps({"input_digest": digest(inputs), "idempotency_key_sha256": hashlib.sha256(key.encode()).hexdigest()}),
                              json.dumps(summary), receipt_id, "2026-09-07T23:00:00+00:00"))
        if self.mode in {"denied", "error", "expired", "shared"}:
            actor_status = {"denied": 403, "error": 500, "expired": 401, "shared": 200}[self.mode]
            for sequence, slot, code in ((2, "primary", 200), (3, "secondary", actor_status)):
                self.pool.capture(ident(action_id + slot), urlsplit(selected).path, slot,
                                  hunt_action_id=action_id, sequence=sequence, status_code=code)
        if self.raise_after:
            self.raise_after = False
            raise RuntimeError("simulated failure after canonical settlement")
        # A caller-visible return is deliberately untrustworthy; code must reread DB.
        return {"action_id": action_id, "proven": True, "outcome": "supported"}


def make_service(pool, executor=None):
    executor = executor or CanonicalWorkerBoundary(pool)
    return AuthorizationInvestigationService(pool, executor, proof_url), executor


def refs():
    return dict(capture_id=CAPTURE, baseline_capture_id=BASELINE,
                primary_session_ref=OWNER_SESSION, secondary_session_ref=ACTOR_SESSION)


def run(awaitable):
    return asyncio.run(awaitable)


@pytest.fixture
def setup():
    pool = RelationalPool()
    pool.seed()
    service, worker = make_service(pool)
    yield pool, service, worker
    pool.db.close()


def propose(service):
    return run(service.propose(HUNT, **refs()))


def approve(service, proposal, **kwargs):
    return run(service.approve(HUNT, proposal["proposal_id"], proposal_digest=proposal["proposal_digest"], confirm=True, **kwargs))


def test_propose_and_skip_never_send_traffic_or_claim_an_experiment(setup):
    pool, service, worker = setup
    result = propose(service)
    assert not result["settled"] and not result["attempts"]
    assert result["resume"]["experiments_run"] == 0
    skipped = run(service.skip(HUNT, result["proposal_id"]))
    assert skipped["deferred"] and not skipped["attempts"]
    assert worker.calls == []
    assert not pool.db.execute("SELECT * FROM hunt_actions WHERE capability_name='authz.verify'").fetchall()


def test_positive_path_reuses_canonical_execution_and_receipt(setup):
    pool, service, worker = setup
    proposal = propose(service)
    result = approve(service, proposal)
    assert result["settled"] and result["attempts"][0]["outcome"] == "supported"
    assert result["attempts"][0]["receipt_id"] and result["selected_request_examined"]
    assert worker.calls[0][2] == {"primary_session_ref": OWNER_SESSION, "secondary_session_ref": ACTOR_SESSION,
                                  "routes": [ORIGIN + "/orders", ORIGIN + "/orders/1001"]}
    assert result["resume"]["attempts_run"] == 1
    stored = " ".join(r[0] for r in pool.db.execute("SELECT attributes FROM application_graph_nodes"))
    assert "/orders/1001" not in stored and "MUST_NOT_READ_SECRET" not in stored
    assert all("encrypted_headers" not in sql for sql, _ in pool.calls)


def test_repeat_approval_and_propose_are_idempotent(setup):
    pool, service, worker = setup
    first = propose(service)
    assert propose(service)["proposal_id"] == first["proposal_id"]
    approve(service, first)
    second = approve(service, first)
    assert worker.executions == len(worker.calls) == 1
    assert len(second["attempts"]) == 1 and second["resume"]["attempts_run"] == 1


@pytest.mark.parametrize("mode", ["other_object", "other_collection", "aggregate_only", "contradictory", "missing_receipt", "blocked"])
def test_no_aggregate_wrong_object_or_unbacked_return_can_promote(setup, mode):
    _, service, worker = setup
    worker.mode = mode
    result = approve(service, propose(service))
    assert result["attempts"][0]["outcome"] == "inconclusive"
    assert not result["settled"]
    assert result["attempts"][0]["proof_state"] != "verified"


@pytest.mark.parametrize("mode", ["error", "expired", "shared"])
def test_execution_or_authentication_errors_are_not_enforcement(setup, mode):
    _, service, worker = setup
    worker.mode = mode
    result = approve(service, propose(service))
    assert result["attempts"][0]["outcome"] == "inconclusive"
    assert not result["settled"]


def test_refutation_needs_exact_same_action_selected_request_denial(setup):
    _, service, worker = setup
    worker.mode = "denied"
    result = approve(service, propose(service))
    assert result["attempts"][0]["outcome"] == "refuted"
    assert len(result["attempts"][0]["transaction_ids"]) == 2
    assert "other objects" in result["explanation"]
    assert result["selected_request_examined"]


def test_inconclusive_retry_accumulates_and_definite_retest_is_explicit(setup):
    _, service, worker = setup
    proposal = propose(service)
    worker.mode = "error"
    approve(service, proposal)
    worker.mode = "verified"
    result = approve(service, proposal, attempt=2)
    assert [a["outcome"] for a in result["attempts"]] == ["inconclusive", "supported"]
    assert result["resume"]["attempts_run"] == 2
    with pytest.raises(AuthorizationWorkflowError, match="settled"):
        approve(service, proposal, attempt=3)
    worker.mode = "denied"
    result = approve(service, proposal, attempt=3, retry_settled=True)
    assert [a["outcome"] for a in result["attempts"]] == ["inconclusive", "supported", "refuted"]


def test_restart_reads_persistent_rows_without_executing(tmp_path):
    database = str(tmp_path / "state.db")
    first = RelationalPool(database)
    first.seed()
    service, worker = make_service(first)
    proposal = propose(service)
    before = approve(service, proposal)
    first.db.close()
    second = RelationalPool(database)
    new_service, new_worker = make_service(second)
    after = run(new_service.read(HUNT, proposal["proposal_id"]))
    assert before == after
    assert not new_worker.calls
    second.db.close()


def test_crash_after_dispatch_recovers_without_another_execution(setup):
    _, service, worker = setup
    proposal = propose(service)
    worker.raise_after = True
    with pytest.raises(RuntimeError):
        approve(service, proposal)
    result = approve(service, proposal)
    assert result["settled"] and worker.executions == len(worker.calls) == 1


def test_crash_before_dispatch_reuses_same_attempt_and_action_identity(setup):
    _, service, worker = setup
    proposal = propose(service)
    worker.raise_before = True
    with pytest.raises(RuntimeError):
        approve(service, proposal)
    pending = run(service.read(HUNT, proposal["proposal_id"]))
    assert pending["attempts"][0]["execution_status"] == "not_dispatched"
    with pytest.raises(AuthorizationWorkflowError, match="preceding attempt"):
        approve(service, proposal, attempt=2)
    result = approve(service, proposal)
    assert result["settled"] and worker.executions == 1
    assert worker.calls[0][1] == worker.calls[1][1]


@pytest.mark.parametrize("field,value", [("method", "DELETE"), ("request_body_bytes", 5),
                                          ("url", ORIGIN + "/orders/1001?x=1"),
                                          ("url", ORIGIN + "/orders/1001#tab"),
                                          ("url", "https://elsewhere.test/orders/1001"),
                                          ("url", ORIGIN + "/orders/<redacted>"),
                                          ("url", "https://fixture.example.test:444/orders/1001")])
def test_unsupported_or_out_of_scope_captures_fail_before_execution(setup, field, value):
    pool, service, worker = setup
    pool.db.execute(f"UPDATE http_transactions SET {field}=? WHERE id=?", (value, CAPTURE))
    with pytest.raises(AuthorizationWorkflowError):
        propose(service)
    assert not worker.calls


def test_same_target_other_hunt_capture_is_not_authority(setup):
    pool, service, _ = setup
    pool.db.execute("UPDATE http_transactions SET hunt_run_id=? WHERE id=?", (OTHER_HUNT, CAPTURE))
    with pytest.raises(AuthorizationWorkflowError, match="unavailable"):
        propose(service)


def test_baseline_must_be_same_collection(setup):
    pool, service, _ = setup
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?", (ORIGIN + "/invoices", BASELINE))
    with pytest.raises(AuthorizationWorkflowError, match="same origin and resource"):
        propose(service)


@pytest.mark.parametrize("change", ["expired", "other_hunt", "same_profile", "wrong_slot"])
def test_session_metadata_is_scoped_without_decrypting(setup, change):
    pool, service, worker = setup
    if change == "expired":
        pool.db.execute("UPDATE auth_sessions SET expires_at='2000-01-01' WHERE id=?", (ACTOR_SESSION,))
    elif change == "other_hunt":
        pool.db.execute("UPDATE auth_sessions SET owner_id=? WHERE id=?", (OTHER_HUNT, ACTOR_SESSION))
    elif change == "same_profile":
        pool.db.execute("UPDATE auth_sessions SET profile_id=? WHERE id=?", (ident("primary"), ACTOR_SESSION))
    else:
        pool.db.execute("UPDATE auth_sessions SET principal_slot='primary' WHERE id=?", (ACTOR_SESSION,))
    with pytest.raises(AuthorizationWorkflowError):
        propose(service)
    assert not worker.calls


def test_refresh_requires_new_proposal_and_read_does_not_need_live_session(setup):
    pool, service, worker = setup
    proposal = propose(service)
    pool.db.execute("UPDATE auth_sessions SET refresh_count=1 WHERE id=?", (OWNER_SESSION,))
    with pytest.raises(AuthorizationWorkflowError, match="changed"):
        approve(service, proposal)
    assert propose(service)["proposal_id"] != proposal["proposal_id"]
    assert not worker.calls
    pool.db.execute("UPDATE auth_sessions SET expires_at='2000-01-01'")
    assert run(service.read(HUNT, proposal["proposal_id"]))["attempts"] == []


def test_tampered_binding_fails_explicitly(setup):
    pool, service, worker = setup
    proposal = propose(service)
    row = pool.db.execute("SELECT attributes FROM application_graph_nodes WHERE id=?", (proposal["proposal_id"],)).fetchone()
    value = json.loads(row[0]); value["capture_sha256"] = "0" * 64
    pool.db.execute("UPDATE application_graph_nodes SET attributes=? WHERE id=?", (json.dumps(value), proposal["proposal_id"]))
    with pytest.raises(AuthorizationWorkflowError, match="inconsistent"):
        approve(service, proposal)
    assert not worker.calls


def test_old_state_remains_readable_after_hunt_finishes(setup):
    pool, service, worker = setup
    proposal = propose(service)
    approve(service, proposal)
    pool.db.execute("UPDATE hunt_runs SET status='completed' WHERE id=?", (HUNT,))
    assert approve(service, proposal)["settled"]
    with pytest.raises(AuthorizationWorkflowError, match="not active"):
        approve(service, proposal, attempt=2, retry_settled=True)
    assert worker.executions == 1


def test_api_verbs_use_strict_references_and_restartable_service(setup):
    _, service, worker = setup
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[authorization_service] = lambda: service
    with TestClient(app) as client:
        root = f"/hunts/{HUNT}/authorization-investigations"
        response = client.post(root, json=refs()); assert response.status_code == 200
        proposal = response.json(); location = root + "/" + proposal["proposal_id"]
        assert client.get(location).json()["attempts"] == []
        assert client.post(location + "/skip").status_code == 200
        payload = {"proposal_digest": proposal["proposal_digest"], "confirm": True}
        assert client.post(location + "/approve", json=payload).json()["settled"]
        assert client.get(location + "/reproduction").json()["reproduction_is_plan"] is True
        assert client.get(f"/hunts/{OTHER_HUNT}/authorization-investigations/{proposal['proposal_id']}").status_code == 404
        assert worker.executions == 1


@pytest.mark.parametrize("extra", [{"url": "https://evil.test"}, {"headers": {"Authorization": "secret"}},
                                   {"proven": True}, {"outcome": "supported"}])
def test_api_cannot_receive_target_overrides_or_proof(setup, extra):
    _, service, worker = setup
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[authorization_service] = lambda: service
    with TestClient(app) as client:
        response = client.post(f"/hunts/{HUNT}/authorization-investigations", json={**refs(), **extra})
        assert response.status_code == 422
    assert not worker.calls


@pytest.mark.parametrize("bad", [{"confirm": False}, {"confirm": "true"}, {"confirm": 1},
                                 {"attempt": True}, {"attempt": 0}, {"attempt": 21},
                                 {"routes": ["https://evil.test"]}, {"primary_session_ref": OWNER_SESSION}])
def test_approval_cannot_change_execution_or_use_truthy_confirmation(setup, bad):
    _, service, worker = setup
    proposal = propose(service)
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[authorization_service] = lambda: service
    with TestClient(app) as client:
        response = client.post(f"/hunts/{HUNT}/authorization-investigations/{proposal['proposal_id']}/approve",
                               json={"proposal_digest": proposal["proposal_digest"], "confirm": True, **bad})
        assert response.status_code == 422
    assert not worker.calls


@pytest.mark.parametrize("extra", [{"headers": {"X-Tenant": "another"}}, {"body": "value"},
                                   {"request_collection_id": ident("collection")}, {"follow_redirects": True}])
def test_unreplayed_source_options_are_declined_not_discarded(setup, extra):
    pool, service, worker = setup
    source = ident("source:" + CAPTURE)
    summary = {"input": {"method": "GET", "path": "/orders/1001", "session_ref": OWNER_SESSION, **extra}}
    pool.db.execute("UPDATE hunt_actions SET input_summary=? WHERE id=?", (json.dumps(summary), source))
    with pytest.raises(AuthorizationWorkflowError, match="custom headers"):
        propose(service)
    assert not worker.calls


def test_another_sessions_capture_cannot_be_attributed_to_the_current_pair(setup):
    pool, service, _ = setup
    source = ident("source:" + CAPTURE)
    summary = {"input": {"method": "GET", "path": "/orders/1001", "session_ref": ident("old-session")}}
    pool.db.execute("UPDATE hunt_actions SET input_summary=? WHERE id=?", (json.dumps(summary), source))
    with pytest.raises(AuthorizationWorkflowError):
        propose(service)


def test_another_actions_denial_does_not_refute_this_selection(setup):
    pool, service, worker = setup
    worker.mode = "denied"
    proposal = propose(service)
    result = approve(service, proposal)
    action = result["attempts"][0]["action_id"]
    pool.db.execute("UPDATE http_transactions SET hunt_action_id=? WHERE hunt_action_id=? AND principal_slot='secondary'", (ident("unrelated-action"), action))
    again = run(service.read(HUNT, proposal["proposal_id"]))
    assert again["attempts"][0]["outcome"] == "inconclusive"


def test_a_changed_action_input_cannot_supply_proof(setup):
    pool, service, _ = setup
    proposal = propose(service)
    result = approve(service, proposal)
    pool.db.execute("UPDATE hunt_actions SET input_summary='{}' WHERE id=?", (result["attempts"][0]["action_id"],))
    with pytest.raises(AuthorizationWorkflowError, match="does not match"):
        run(service.read(HUNT, proposal["proposal_id"]))


def test_pending_canonical_state_does_not_allow_a_second_attempt(setup):
    pool, service, _ = setup
    proposal = propose(service)
    result = approve(service, proposal)
    pool.db.execute("UPDATE hunt_actions SET status='queued' WHERE id=?", (result["attempts"][0]["action_id"],))
    state = run(service.read(HUNT, proposal["proposal_id"]))
    assert state["resume"]["experiments_run"] == 0 and not state["settled"]
    with pytest.raises(AuthorizationWorkflowError, match="preceding attempt"):
        approve(service, proposal, attempt=2)
