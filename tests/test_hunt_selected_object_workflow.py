"""No-listing API path over real comparison/HTTP and relational persistence.

Routes, proposal binding, SQL, approval, the authz wrapper and comparison execute.
The queue and frozen-address transport are replaced with a loopback-only HTTP
adapter. SQLite adapts PostgreSQL SQL; these tests do not validate its locks.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
import capabilities.authz as authz
from capabilities.http import WorkerPrivateHTTPResponse
from runtime.models import TargetBinding
from hunt.authorization_evidence import AuthorizationWorkflowError, attributed_outcome, canonical_action_id, digest
from hunt.authorization_router import authorization_service, router
from hunt.authorization_service import AuthorizationInvestigationService


def uid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "selected-object-fixture:" + name))

HUNT, OTHER_HUNT, TARGET = uid("hunt"), uid("other-hunt"), uid("target")
A_SESSION, B_SESSION = uid("a-session"), uid("b-session")
CAPTURE, BASELINE = uid("capture"), uid("baseline")
AUTH = {"primary": {"Authorization": "Bearer test-a"},
        "secondary": {"Authorization": "Bearer test-b"}}


class RelationalPool:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = asyncio.Lock()
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS hunt_runs(id TEXT PRIMARY KEY,target_id TEXT,device_target_id TEXT,target_kind TEXT,status TEXT,context_pack TEXT);
        CREATE TABLE IF NOT EXISTS auth_sessions(id TEXT PRIMARY KEY,owner_kind TEXT,owner_id TEXT,target_id TEXT,target_kind TEXT,principal_slot TEXT,status TEXT,expires_at TEXT,profile_id TEXT,profile_version INTEGER,refresh_count INTEGER,target_binding_digest TEXT);
        CREATE TABLE IF NOT EXISTS application_graph_nodes(id TEXT PRIMARY KEY,target_id TEXT,node_type TEXT,node_key TEXT,label TEXT,attributes TEXT,UNIQUE(target_id,node_type,node_key));
        CREATE TABLE IF NOT EXISTS hunt_actions(id TEXT PRIMARY KEY,hunt_run_id TEXT,capability_name TEXT,status TEXT,input_summary TEXT,result_summary TEXT,receipt_id TEXT,started_at TEXT,completed_at TEXT);
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
        sql = sql.replace("::jsonb", "").replace(" FOR UPDATE", "").replace("NOW()", "CURRENT_TIMESTAMP")
        return self.db.execute(sql, {str(i): str(v) if isinstance(v, uuid.UUID) else v for i, v in enumerate(args, 1)})
    async def fetchrow(self, sql, *args):
        return self._query(sql, args).fetchone()
    async def fetch(self, sql, *args):
        return self._query(sql, args).fetchall()
    async def execute(self, sql, *args):
        self._query(sql, args)
    def seed(self, origin, mode="vulnerable", selected="101", own="202"):
        context = json.dumps({"target": {"origins": [origin], "url": origin}, "authorized_target_addresses": ["127.0.0.1"]})
        for hid in (HUNT, OTHER_HUNT):
            self.db.execute("INSERT INTO hunt_runs VALUES(?,?,NULL,'web','active',?)", (hid, TARGET, context))
        for sid, slot in ((A_SESSION, "primary"), (B_SESSION, "secondary")):
            self.db.execute("INSERT INTO auth_sessions VALUES(?,'hunt',?,?,'web',?,'active','2099-01-01',?,1,0,?)", (sid, HUNT, TARGET, slot, uid(slot), "a" * 64))
        for cid, slot, sid, obj in ((CAPTURE, "primary", A_SESSION, selected), (BASELINE, "secondary", B_SESSION, own)):
            path = f"/{mode}/{obj}"
            action = uid("source:" + cid)
            inputs = json.dumps({"input": {"method": "GET", "path": path, "session_ref": sid}})
            self.db.execute("INSERT INTO hunt_actions(id,hunt_run_id,capability_name,status,input_summary) VALUES(?,?,'http.request','completed',?)", (action, HUNT, inputs))
            self.db.execute("INSERT INTO http_transactions VALUES(?,?,?,1,'GET',?,?,0,200,NULL,0)", (cid, HUNT, action, origin + path, slot))


class LoopbackFixture:
    def __init__(self):
        fixture = self
        self.trace = []
        self.actor_error = None
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                principal = "primary" if self.headers.get("Authorization") == AUTH["primary"]["Authorization"] else "secondary"
                fixture.trace.append((principal, self.path))
                mode, _, obj = self.path.strip("/").partition("/")
                if not obj:
                    status, body = 500, {"error": "collection does not exist"}
                elif fixture.actor_error and principal == "secondary":
                    status, body = fixture.actor_error, {"error": "temporary failure"}
                elif obj not in {"101", "102", "202"}:
                    status, body = 404, {"error": "not found"}
                elif obj != "202" and principal == "secondary" and (mode == "protected" or obj == "102"):
                    status, body = 403, {"error": "forbidden"}
                else:
                    status, body = 200, {"data": {"id": obj, "items": ["sensitive fixture value"], "public": mode == "shared"}}
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
    async def transport(self, origin, args, **kwargs):
        assert origin == self.origin  # Fixture adapter must never leave loopback.
        assert tuple(kwargs["target"].allowed_origins) == (self.origin,)
        assert kwargs["allow_write"] is False and args["method"] == "GET"
        assert args["follow_redirects"] is False
        slot = kwargs["principal_slot"]
        assert kwargs["trusted_headers"] == AUTH[slot]
        url = origin + args["path"]
        request = urllib.request.Request(url, headers=AUTH[slot], method="GET")
        try:
            response = urllib.request.urlopen(request, timeout=kwargs["timeout_seconds"])
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            body = response.read()
            headers = {k.lower(): v for k, v in response.headers.items()}
            kwargs["private_response_sink"](WorkerPrivateHTTPResponse(response.code, url, body, headers, {}))
            kwargs["transaction_recorder"]({"method": "GET", "url": url, "principal_slot": slot,
                "status_code": response.code, "request_body": None, "response_body": body,
                "response_digest_scope": "complete", "response_body_truncated": False})
            return {"ok": True, "request": {"method": "GET", "path": args["path"]}}


class WorkerBoundary:
    """Substitute only queue/session resolution; call the actual capability wrapper."""
    def __init__(self, pool, fixture):
        self.pool, self.fixture = pool, fixture
        self.calls = []
        self.results = []
        self.target = TargetBinding(target_id=TARGET, target_kind="web", canonical_host="127.0.0.1",
            allowed_origins=(fixture.origin,), allowed_addresses=("127.0.0.1",), scope_receipt_id="fixture-scope")
    async def __call__(self, hunt_id, key, inputs):
        action = str(canonical_action_id(hunt_id, key))
        if self.pool.db.execute("SELECT id FROM hunt_actions WHERE id=?", (action,)).fetchone():
            return {"action_id": action}
        assert inputs["primary_session_ref"] == A_SESSION and inputs["secondary_session_ref"] == B_SESSION
        self.calls.append(dict(inputs))
        events = []
        result = await authz.verify_target_bound_object_authorization(self.fixture.origin, inputs["routes"],
            target=self.target, primary_headers=AUTH["primary"], secondary_headers=AUTH["secondary"],
            transaction_recorder=events.append)
        self.results.append(result)
        self.pool.db.execute("INSERT INTO hunt_actions VALUES(?,?,'authz.verify','completed',?,?,?,NULL,?)",
            (action, hunt_id, json.dumps({"input_digest": digest(inputs), "idempotency_key_sha256": hashlib.sha256(key.encode()).hexdigest()}),
             json.dumps(result), uid("receipt:" + action), datetime.now(timezone.utc).isoformat()))
        for sequence, event in enumerate(events, 1):
            self.pool.db.execute("INSERT INTO http_transactions VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                uid(f"{action}:{sequence}"), hunt_id, action, sequence, event["method"], event["url"],
                event["principal_slot"], 0, event["status_code"], None, int(event["response_body_truncated"])))
        # Return value is not trusted by the workflow; evidence is reread from SQL.
        return {"action_id": action, "proven": True, "outcome": "supported"}


def proof_url(value, *, base_origin, object_id=None):
    parts = urlsplit(value)
    path = "/".join("<owner-object>" if s == object_id else s for s in parts.path.split("/"))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def refs(**changes):
    values = dict(capture_id=CAPTURE, baseline_capture_id=BASELINE, primary_session_ref=A_SESSION,
                  secondary_session_ref=B_SESSION, baseline_kind="own_object", expected_access="denied")
    return {**values, **changes}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def setup(monkeypatch):
    fixture = LoopbackFixture()
    monkeypatch.setattr(authz, "execute_bound_http_request", fixture.transport)
    pool = RelationalPool(); pool.seed(fixture.origin)
    boundary = WorkerBoundary(pool, fixture)
    service = AuthorizationInvestigationService(pool, boundary, proof_url)
    try:
        yield pool, fixture, boundary, service
    finally:
        pool.db.close(); fixture.close()


def approve(service, proposal, **changes):
    return run(service.approve(HUNT, proposal["proposal_id"], proposal_digest=proposal["proposal_digest"], confirm=True, **changes))


def test_api_approval_runs_no_listing_selected_object_and_retains_evidence(setup):
    pool, fixture, boundary, service = setup
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[authorization_service] = lambda: service
    with TestClient(app) as client:
        root = f"/hunts/{HUNT}/authorization-investigations"
        response = client.post(root, json=refs())
        assert response.status_code == 200, response.text
        proposal = response.json()
        assert fixture.trace == [] and proposal["authorization_assessment"] == "not_examined"
        assert len(proposal["reproduction"]) == 4 and proposal["reproduction_is_plan"]
        url = root + "/" + proposal["proposal_id"]
        wrong = client.post(url + "/approve", json={"proposal_digest": "0" * 64, "confirm": True})
        assert wrong.status_code == 409 and not fixture.trace
        unconfirmed = client.post(url + "/approve", json={"proposal_digest": proposal["proposal_digest"], "confirm": False})
        assert unconfirmed.status_code == 422 and not fixture.trace
        result = client.post(url + "/approve", json={"proposal_digest": proposal["proposal_digest"], "confirm": True})
        assert result.status_code == 200, result.text
        state = result.json()
        assert state["cross_access_observed"] is True
        assert state["authorization_assessment"] == "potential_violation"
        assert state["attempts"][0]["proof_state"] == "inconclusive"
        assert state["attempts"][0]["outcome"] == "inconclusive"
        assert len(state["attempts"][0]["transaction_ids"]) == 4
        assert state["resume"]["attempts_run"] == 1 and state["resume"]["open_questions"]
        assert not state["settled"]
        assert client.get(url).json() == state
        assert client.post(url + "/approve", json={"proposal_digest": proposal["proposal_digest"], "confirm": True}).json() == state
    assert len(boundary.calls) == 1
    assert fixture.trace == [("secondary", "/vulnerable/202"), ("primary", "/vulnerable/101"),
                             ("secondary", "/vulnerable/101"), ("primary", "/vulnerable/101")]
    assert boundary.results[0]["budget_consumed"]["http_requests"] == 4
    assert "sensitive fixture value" not in json.dumps(state)
    assert "test-a" not in json.dumps(state) and "test-b" not in json.dumps(state)


@pytest.mark.parametrize("expected,assessment", [("unknown", "entitlement_unknown"), ("allowed", "shared_access_as_declared"), ("denied", "potential_violation")])
def test_operator_expectation_never_becomes_proof(setup, expected, assessment):
    pool, fixture, boundary, service = setup
    # Explicit shared object, even when an operator wrongly declares it private.
    pool.db.execute("UPDATE http_transactions SET url=replace(url,'/vulnerable/','/shared/')")
    proposal = run(service.propose(HUNT, **refs(expected_access=expected)))
    state = approve(service, proposal)
    assert state["authorization_assessment"] == assessment
    assert state["cross_access_observed"] and not state["settled"]
    assert state["attempts"][0]["proof_state"] != "verified"
    assert state["expectation_source"] == "operator_declared_not_proof"


@pytest.mark.parametrize("mode,selection", [("protected", "101"), ("vulnerable", "102")])
def test_exact_denial_is_refuted_not_sibling_proof(setup, mode, selection):
    pool, fixture, boundary, service = setup
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?", (f"{fixture.origin}/{mode}/{selection}", CAPTURE))
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?", (f"{fixture.origin}/{mode}/202", BASELINE))
    state = approve(service, run(service.propose(HUNT, **refs())))
    assert state["authorization_assessment"] == "access_denied"
    assert state["attempts"][0]["outcome"] == "refuted" and state["settled"]
    assert not state["cross_access_observed"]
    assert len(fixture.trace) == 3
    if selection == "102":
        assert all(not p.endswith("/101") for _, p in fixture.trace)
    with pytest.raises(AuthorizationWorkflowError, match="retest"):
        approve(service, state, attempt=2)


@pytest.mark.parametrize("field,value", [("status_code", 500), ("status_code", 401), ("truncated", 1), ("error", "timeout")])
def test_invalid_reference_is_rejected_before_proposal_or_approval(setup, field, value):
    pool, fixture, _, service = setup
    proposal = run(service.propose(HUNT, **refs()))
    pool.db.execute(f"UPDATE http_transactions SET {field}=? WHERE id=?", (value, BASELINE))
    with pytest.raises(AuthorizationWorkflowError):
        run(service.propose(HUNT, **refs()))
    with pytest.raises(AuthorizationWorkflowError):
        approve(service, proposal)
    assert not fixture.trace


@pytest.mark.parametrize("suffix", ["/vulnerable", "/other/202", "/vulnerable/101", "/vulnerable/202?x=1"])
def test_baseline_must_be_a_distinct_object_in_same_collection(setup, suffix):
    pool, fixture, _, service = setup
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?", (fixture.origin + suffix, BASELINE))
    with pytest.raises(AuthorizationWorkflowError):
        run(service.propose(HUNT, **refs()))
    assert not fixture.trace


def test_expectation_is_bound_into_review_digest(setup):
    _, fixture, _, service = setup
    a = run(service.propose(HUNT, **refs(expected_access="denied")))
    b = run(service.propose(HUNT, **refs(expected_access="allowed")))
    assert a["proposal_id"] != b["proposal_id"] and a["proposal_digest"] != b["proposal_digest"]
    with pytest.raises(AuthorizationWorkflowError, match="digest"):
        run(service.approve(HUNT, b["proposal_id"], proposal_digest=a["proposal_digest"], confirm=True))
    assert not fixture.trace


def test_resume_after_database_reopen_does_not_execute(monkeypatch, tmp_path):
    fixture = LoopbackFixture(); monkeypatch.setattr(authz, "execute_bound_http_request", fixture.transport)
    path = str(tmp_path / "investigation.db")
    pool = RelationalPool(path); pool.seed(fixture.origin)
    try:
        boundary = WorkerBoundary(pool, fixture)
        service = AuthorizationInvestigationService(pool, boundary, proof_url)
        before = approve(service, run(service.propose(HUNT, **refs())))
        pool.db.close()
        pool = RelationalPool(path)
        new_boundary = WorkerBoundary(pool, fixture)
        after = run(AuthorizationInvestigationService(pool, new_boundary, proof_url).read(HUNT, before["proposal_id"]))
        assert before == after and not new_boundary.calls
        assert len(fixture.trace) == 4
    finally:
        pool.db.close(); fixture.close()


def test_expired_session_result_can_retry_without_losing_history(setup):
    _, fixture, _, service = setup
    proposal = run(service.propose(HUNT, **refs()))
    fixture.actor_error = 401
    first = approve(service, proposal)
    assert first["authorization_assessment"] == "inconclusive" and not first["settled"]
    fixture.actor_error = None
    second = approve(service, proposal, attempt=2)
    assert second["cross_access_observed"] and second["resume"]["attempts_run"] == 2
    assert len(second["attempts"]) == 2


def test_cross_hunt_proposal_and_capture_are_rejected(setup):
    _, fixture, _, service = setup
    proposal = run(service.propose(HUNT, **refs()))
    with pytest.raises(AuthorizationWorkflowError):
        run(service.read(OTHER_HUNT, proposal["proposal_id"]))
    with pytest.raises(AuthorizationWorkflowError):
        run(service.propose(OTHER_HUNT, **refs()))
    assert not fixture.trace


def test_collection_mode_keeps_existing_input_and_proposal_shape(setup):
    pool, fixture, boundary, service = setup
    pool.db.execute("UPDATE http_transactions SET url=? WHERE id=?", (fixture.origin + "/vulnerable", BASELINE))
    proposal = run(service.propose(HUNT, **refs(baseline_kind="collection", expected_access="unknown")))
    document = json.loads(pool.db.execute("SELECT attributes FROM application_graph_nodes WHERE id=?", (proposal["proposal_id"],)).fetchone()[0])
    assert "baseline_kind" not in document and "expected_access" not in document
    expected_input = {"primary_session_ref": A_SESSION, "secondary_session_ref": B_SESSION,
                      "routes": [fixture.origin + "/vulnerable", fixture.origin + "/vulnerable/101"]}
    assert document["capability_input_sha256"] == digest(expected_input)
    assert len(proposal["reproduction"]) == 3 and not fixture.trace


@pytest.mark.parametrize("change", ["resource", "selected_url", "baseline", "action", "receipt", "missing_transaction", "contradiction", "fake_verified"])
def test_unattributable_or_incomplete_evidence_never_creates_lead(setup, change):
    pool, _, _, service = setup
    state = approve(service, run(service.propose(HUNT, **refs())))
    proposal = json.loads(pool.db.execute("SELECT attributes FROM application_graph_nodes WHERE id=?", (state["proposal_id"],)).fetchone()[0])
    attempt = run(service.repo.attempts(pool, {"id": HUNT, "target_id": TARGET}, state["proposal_id"]))[0]
    action = run(service.repo.action(pool, {"id": HUNT}, attempt["action_id"]))
    transactions = run(service.repo.transactions(pool, {"id": HUNT}, attempt["action_id"]))
    summary = json.loads(action["result_summary"])
    observation = summary["observation"]
    if change == "resource": observation["resource_id_sha256"] = "0" * 64
    if change == "selected_url": observation["selected_request_sha256"] = "0" * 64
    if change == "baseline": observation["baseline_request_sha256"] = "0" * 64
    if change == "action":
        for item in transactions: item["hunt_action_id"] = OTHER_HUNT
    if change == "receipt": action["receipt_id"] = None
    if change == "missing_transaction": transactions.pop()
    if change == "contradiction": summary["observations"] = [{**observation, "responses_equivalent": False}]
    if change == "fake_verified": observation["proof_state"] = "verified"
    action["result_summary"] = summary
    outcome = attributed_outcome(proposal, attempt, action, transactions)
    assert not outcome.get("cross_access_observed")
    assert outcome["proof_state"] != "verified" and outcome["outcome"] == "inconclusive"


@pytest.mark.parametrize("extra", [{"baseline_kind": "auto"}, {"expected_access": "verified"},
                                    {"proven": True}, {"method": "DELETE"}, {"expected_access": True}])
def test_api_rejects_unsupported_modes_and_proof_claims(setup, extra):
    _, fixture, _, service = setup
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[authorization_service] = lambda: service
    with TestClient(app) as client:
        response = client.post(f"/hunts/{HUNT}/authorization-investigations", json=refs(**extra))
        assert response.status_code == 422
    assert not fixture.trace


def test_skip_is_a_durable_deferral_not_a_run(setup):
    _, fixture, _, service = setup
    proposal = run(service.propose(HUNT, **refs()))
    skipped = run(service.skip(HUNT, proposal["proposal_id"]))
    assert skipped["deferred"] and skipped["deferral_recorded"]
    assert skipped["resume"]["attempts_run"] == 0 and fixture.trace == []


def test_new_mode_explains_review_not_an_endless_repeat(setup):
    _, _, _, service = setup
    state = approve(service, run(service.propose(HUNT, **refs())))
    assert state["evidence_gathering_complete"] and not state["settled"]
    assert state["next_step"] == "review_access_expectation_without_repeating_the_same_requests"


def test_literal_collection_input_still_uses_legacy_differential(setup, monkeypatch):
    _, fixture, boundary, _ = setup
    from scanner_tools import access_control_checks
    calls = []
    async def legacy(base, routes, primary, secondary, **kwargs):
        calls.append((base, routes))
        return {"findings": [], "reason": "fixture did not find anything"}
    monkeypatch.setattr(access_control_checks, "authz_resource_replay_test", legacy)
    result = run(authz.verify_target_bound_object_authorization(fixture.origin,
        [fixture.origin + "/objects", fixture.origin + "/objects/101"], target=boundary.target,
        primary_headers=AUTH["primary"], secondary_headers=AUTH["secondary"]))
    assert len(calls) == 1 and not fixture.trace
    assert result["observation"].get("mode") != "selected_object"


def test_wrapper_refuses_changed_destination_at_transport_boundary(setup, monkeypatch):
    _, fixture, boundary, _ = setup
    async def denied(origin, args, **kwargs):
        return {"ok": False, "request": dict(args), "error": "scope: changed destination"}
    monkeypatch.setattr(authz, "execute_bound_http_request", denied)
    with pytest.raises(authz.AuthzVerificationContractError, match="frozen target"):
        run(authz.verify_target_bound_object_authorization(fixture.origin,
            [fixture.origin + "/objects/101", fixture.origin + "/objects/202"], target=boundary.target,
            primary_headers=AUTH["primary"], secondary_headers=AUTH["secondary"]))
    assert not fixture.trace


def test_wrapper_never_probes_same_principal_pair(setup):
    _, fixture, boundary, _ = setup
    result = run(authz.verify_target_bound_object_authorization(fixture.origin,
        [fixture.origin + "/objects/101", fixture.origin + "/objects/202"], target=boundary.target,
        primary_headers=AUTH["primary"], secondary_headers=AUTH["primary"]))
    assert result["observation"]["reason"] == "principal_contexts_not_distinct"
    assert result["budget_consumed"]["http_requests"] == 0 and not fixture.trace


def test_missing_completeness_event_prevents_claiming_a_crossing(setup, monkeypatch):
    _, fixture, boundary, _ = setup
    async def incomplete(origin, args, **kwargs):
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(200, origin + args["path"],
            b'{"id":"202","private":true}', {"content-type": "application/json"}, {}))
        # Deliberately omit a complete wire observation; fail closed on fidelity.
        return {"ok": True, "request": dict(args)}
    monkeypatch.setattr(authz, "execute_bound_http_request", incomplete)
    result = run(authz.verify_target_bound_object_authorization(fixture.origin,
        [fixture.origin + "/objects/101", fixture.origin + "/objects/202"], target=boundary.target,
        primary_headers=AUTH["primary"], secondary_headers=AUTH["secondary"]))
    assert result["budget_consumed"]["http_requests"] == 1
    assert not result["observation"]["secondary_baseline_valid"]
