"""A finding found by a signed-in Scan is never retested anonymously.

An authenticated Scan stores only content-free references to its credential profiles
(``credential_profile_refs``), so a retest of its finding holds no identity of its own. Sent
anonymously, the proof's request meets the guest page (HTTP 200, no refusal) and a flaw that is
still there for the signed-in user would read as "likely fixed". Such a retest sends nothing and is
inconclusive, in the proof's own check, the legacy ladder and the AI-driven tier alike.

Unit/provider fixtures: a local HTTP server on 127.0.0.1 whose ``/product?id=N`` is SQL-injectable
only for a signed-in session (a fixture bearer value, not a credential); without the session it
answers HTTP 200 with a guest page. Nothing leaves the machine.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import dataclasses
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import sys
import threading
import types
import urllib.parse
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402
from worker_handlers.retest_identity import (  # noqa: E402
    IDENTITY_UNRESOLVED_REASON, retest_identity_unresolved,
)

FIXTURE_SESSION = "Bearer fixture-session-value"  # unit fixture, not a credential
FINDING = uuid.UUID("77777777-7777-4777-8777-777777777777")
SCAN = uuid.UUID("88888888-8888-4888-8888-888888888888")
TARGET = uuid.UUID("99999999-9999-4999-8999-999999999999")

# What a Scan run with a managed credential profile keeps in scans.options: references only.
MANAGED_SCAN_OPTIONS = {
    "scan_type": "full", "exploit_depth": True,
    "credential_profile_refs": [{
        "profile_id": str(uuid.UUID(int=1)), "profile_version": 1, "credential_record_version": 1,
        "target_kind": "web", "principal_slot": "primary", "scan_lane": "primary",
        "auth_kind": "authorization_header", "principal_label": "fixture user",
        "allowed_capabilities": ["scan.execute"], "credential_resolution_capability": "scan.execute",
        "source": "credential_profiles", "secret_values_visible": False,
    }],
    "credential_target_kind": "web", "credential_action_name": "scan.execute",
}
ANONYMOUS_SCAN_OPTIONS = {"scan_type": "full", "exploit_depth": True}


class _SignedInShop(BaseHTTPRequestHandler):
    """Unit fixture: injectable for the signed-in session, a 200 guest page for everyone else."""

    log: list = []

    def log_message(self, *_args):
        return None

    def _send(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 - http.server API
        signed_in = self.headers.get("Authorization") == FIXTURE_SESSION
        type(self).log.append((self.path, signed_in))
        parsed = urllib.parse.urlsplit(self.path)
        value = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)).get("id", "")
        if parsed.path != "/product":
            return self._send(404, "not found")
        if not signed_in:
            return self._send(200, "<h1>Welcome, guest</h1><p>Sign in to see products.</p>")
        if "'" in value:
            return self._send(500, "<pre>sqlite3.OperationalError: unrecognized token: \"'\"</pre>")
        if not value.isdigit():
            return self._send(404, "<p>No such product</p>")
        return self._send(200, f"<h1>Product {value}</h1>")


@pytest.fixture
def shop(monkeypatch):
    if shutil.which("curl") is None:
        pytest.skip("the retest's HTTP client is curl")
    from scanner_tools import proof_of_exploit

    monkeypatch.setattr(proof_of_exploit, "_poe_config",
                        dataclasses.replace(proof_of_exploit._poe_config, rate_limit_ms=0))
    handler = type("SignedInShop", (_SignedInShop,), {"log": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _proven(origin: str) -> dict:
    """The row a Scan stores for a verified ``sqli.prove_batch`` observation (unit fixture)."""
    return {
        "id": FINDING, "scan_id": SCAN, "target_id": TARGET, "tool": "shakerscan_sqli_proof",
        "title": "Verified SQL injection", "severity": "critical", "status": "active", "source": "dast",
        "target_url": origin, "url": "/product",
        "evidence": {"method": "GET", "field_path": "id", "request_ref_id": None, "origin": origin,
                     "request_class": "safe_read", "candidate_id": "8eeb6fab21745777e07db6e1",
                     "proof_contract": "sqli_error_differential/v1", "repetitions": 2,
                     "proof_state": "verified"},
    }


def _sqlmap(origin: str) -> dict:
    """A sqlmap candidate row (URL and parameter): retested by the legacy ladder (unit fixture)."""
    return {
        "id": FINDING, "scan_id": SCAN, "target_id": TARGET, "tool": "sqlmap",
        "title": "Potential SQL injection", "severity": "high", "status": "active", "source": "dast",
        "target_url": origin, "url": f"{origin}/product?id=1", "param": "id",
        "evidence": {"url": f"{origin}/product?id=1", "method": "GET", "param": "id"},
    }


class _EnqueueConn:
    """Unit fixture connection: answers the Scan's stored options and records the INSERT."""

    def __init__(self, options):
        self.options, self.inserts = options, []

    async def fetchrow(self, query, *_args):
        if "FROM scans" in query:
            return {"options": json.dumps(self.options)}
        return None

    async def execute(self, query, *args):
        if "INSERT INTO finding_verifications" in query:
            self.inserts.append(args)


def _enqueue(monkeypatch, finding: dict, options: dict) -> tuple[dict, tuple]:
    async def admitted(*_a, **_k):
        return {"fixture": True}, None

    async def no_campaign(*_a, **_k):
        return None

    monkeypatch.setattr(findings_router, "admit_retest", admitted)
    monkeypatch.setattr(findings_router, "admitted_authority_json", lambda _a: "{}")
    monkeypatch.setattr(findings_router.asm_inventory, "create_campaign", no_campaign)
    inputs = findings_router.extract_retest_inputs(finding)
    conn = _EnqueueConn(options)
    asyncio.run(findings_router._enqueue_finding_retest_unlocked(conn, finding, inputs))
    return inputs, conn.inserts[0]


def _verification(finding: dict, inputs: dict, *, options: dict, auth_context=None) -> dict:
    """The retest row as ``process_finding_retest_job`` reads it, joined with its Scan."""
    return {
        "id": uuid.uuid4(), "finding_id": FINDING, "scan_id": SCAN, "target_id": TARGET,
        "candidate_id": None, "tool": finding["tool"], "title": finding["title"],
        "severity": finding["severity"], "evidence": finding["evidence"],
        "finding_url": finding["url"], "target_url": inputs["target_url"],
        "finding_type": inputs["finding_type"], "original_url": inputs["original_url"],
        "param": inputs.get("param"), "method": inputs.get("method") or "GET",
        "source_scan_target_url": finding["target_url"], "source_scan_type": "full",
        "source_scan_options": json.dumps(options), "auth_context": auth_context,
    }


@pytest.mark.parametrize("make", [_proven, _sqlmap], ids=["proof", "ladder"])
def test_a_signed_in_findings_retest_without_its_identity_sends_nothing_and_is_inconclusive(
        monkeypatch, shop, make):
    import worker

    handler, origin = shop
    finding = make(origin)
    inputs = findings_router.extract_retest_inputs(finding)
    # A retest an earlier release queued for such a finding: no identity, no secret.
    verification = _verification(finding, inputs, options=MANAGED_SCAN_OPTIONS, auth_context=None)
    assert retest_identity_unresolved(verification)

    result = asyncio.run(worker.run_finding_retest(verification))
    assert (result["verdict"], result["result_status"]) == ("inconclusive", "inconclusive"), result["verdict_reason"]
    assert result["verdict_reason"] == IDENTITY_UNRESOLVED_REASON
    assert result["has_ai_step"] is False and result["artifacts"]["skipped_reason"] == "identity_unresolved"
    assert handler.log == []


def test_the_same_retest_with_the_identity_applied_still_finds_the_flaw(monkeypatch, shop):
    """Control: the guard does not stand in the way of a retest that runs signed in."""
    import worker

    handler, origin = shop
    finding = _proven(origin)
    inputs = findings_router.extract_retest_inputs(finding)
    verification = _verification(finding, inputs, options=MANAGED_SCAN_OPTIONS,
                                 auth_context={"auth_header": FIXTURE_SESSION})
    assert not retest_identity_unresolved(verification)
    result = asyncio.run(worker.run_finding_retest(verification))
    assert (result["verdict"], result["result_status"]) == ("exploited", "still_vulnerable")
    assert handler.log and all(signed_in for _path, signed_in in handler.log)


def test_an_anonymous_scans_finding_is_retested_as_before(monkeypatch, shop):
    """Control: a finding from a Scan without credential profiles is retested anonymously."""
    import worker

    handler, origin = shop
    finding = _proven(origin)
    inputs, inserted = _enqueue(monkeypatch, finding, ANONYMOUS_SCAN_OPTIONS)
    verification = _verification(finding, inputs, options=ANONYMOUS_SCAN_OPTIONS, auth_context=inserted[14])
    assert not retest_identity_unresolved(verification)
    asyncio.run(worker.run_finding_retest(verification))
    assert handler.log


# --- the queued job: no tier runs, the AI tier included -------------------------------------------

class _JobConn:
    """Unit fixture connection for ``process_finding_retest_job``: the claim succeeds and every
    write is recorded."""

    def __init__(self, verification):
        self.verification, self.executed = verification, []

    async def fetchrow(self, query, *args):
        if "FROM finding_verifications fv" in query:
            return self.verification
        if "UPDATE finding_verifications" in query and "status = 'queued'" in query:
            return {"id": self.verification["id"]}
        return None

    async def fetchval(self, query, *args):
        return None

    async def fetch(self, query, *args):
        return []

    async def execute(self, query, *args):
        self.executed.append((query, args))


class _JobPool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


class _JobRedis:
    def __init__(self):
        self.hashes = []

    def hset(self, key, mapping=None, **_kwargs):
        self.hashes.append((key, dict(mapping or {})))

    def expire(self, *_args):
        return None

    def __getattr__(self, _name):
        return lambda *_a, **_k: None


@pytest.mark.parametrize("mode", ["ai", "tiered"])
def test_a_queued_retest_without_the_identity_runs_no_tier_the_ai_tier_included(monkeypatch, mode):
    import worker

    finding = _proven("http://shop.fixture.invalid")
    inputs = findings_router.extract_retest_inputs(finding)
    verification = _verification(finding, inputs, options=MANAGED_SCAN_OPTIONS)
    job_id = str(uuid.uuid4())
    verification.update({"job_id": job_id, "created_at": datetime.now(timezone.utc)})
    payload = worker.build_retest_job_payload(
        job_id=job_id, verification_id=str(verification["id"]), finding_id=str(FINDING),
        submitted_at=datetime.now(timezone.utc).isoformat(), trigger="unit_test")
    payload["mode"] = mode
    calls = {"deterministic": 0, "ai": 0}

    async def deterministic(_verification):
        calls["deterministic"] += 1
        return {"status": "completed", "result_status": "inconclusive", "verdict": "inconclusive",
                "has_ai_step": True, "deterministic_exhausted": True}

    async def ai_verify_finding(**_kwargs):
        calls["ai"] += 1
        return {"verdict": "likely_fixed", "confidence": 0.9, "reasoning": "fixture"}

    class _Watch:
        reason = None
        refused: list = []
        incidents: list = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

    async def watch(*_args, **_kwargs):
        return _Watch()

    async def no_candidate(*_args, **_kwargs):
        return None

    ai_module = types.ModuleType("ai_verifier")
    ai_module.ai_verify_finding = ai_verify_finding
    ai_module.AI_VERIFIABLE_TYPES = {"sqli"}
    monkeypatch.setitem(sys.modules, "ai_verifier", ai_module)
    conn = _JobConn(verification)
    redis = _JobRedis()
    monkeypatch.setattr(worker, "db_pool", _JobPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_try_acquire_retest_slot", lambda _redis: True)
    monkeypatch.setattr(worker, "_release_retest_slot", lambda _redis: None)
    monkeypatch.setattr(worker, "open_retest_authority", watch)
    monkeypatch.setattr(worker, "find_retest_candidate", no_candidate)
    monkeypatch.setattr(worker, "run_finding_retest", deterministic)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {
        "ai_verify_enabled": True, "ai_verify_url": "http://ai.fixture.invalid", "ai_verify_api_key": "fixture"})

    asyncio.run(worker.process_finding_retest_job(payload))

    assert calls == {"deterministic": 0, "ai": 0}
    stored = [args for query, args in conn.executed
              if "UPDATE finding_verifications" in query and "result_status = $1" in query]
    assert stored and stored[0][:3] == ("inconclusive", "inconclusive", IDENTITY_UNRESOLVED_REASON)
    persisted = [args for query, args in conn.executed
                 if "UPDATE findings" in query and "last_verification_verdict = $2" in query]
    assert persisted and persisted[0][1] == "inconclusive"


# --- Scans an earlier release signed in another way ----------------------------------------------
# Option rows a database upgraded from a supported base can still hold: managed profiles (written
# by 0.8.18 through 1.x), a form login, OAuth, a sign-in scenario and an older token key. None
# leaves an identity a retest can send. Fixture values, not credentials.
LEGACY_SIGNED_IN_OPTIONS = {
    "managed_credential_profiles": {"scan_type": "full", "managed_credential_profiles": [
        {"profile_id": str(uuid.UUID(int=2)), "principal_slot": "primary"}]},
    "form_login": {"scan_type": "full", "login_url": "/login", "login_username": "fixture-user",
                   "login_password": "fixture-password", "auto_auth": True},
    "oauth": {"scan_type": "full", "oauth_client_id": "fixture-client",
              "oauth_token_url": "https://idp.fixture.invalid/token", "oauth_client_secret": "fixture-secret"},
    "scenario": {"scan_type": "full", "auth_scenario_json": json.dumps({"steps": [{"goto": "/login"}]})},
    "auth_token": {"scan_type": "full", "auth_token": "fixture-token"},
}


@pytest.mark.parametrize("options", LEGACY_SIGNED_IN_OPTIONS.values(), ids=LEGACY_SIGNED_IN_OPTIONS.keys())
@pytest.mark.parametrize("make", [_proven, _sqlmap], ids=["proof", "ladder"])
def test_a_finding_of_a_scan_signed_in_the_older_ways_is_never_retested_anonymously(
        monkeypatch, shop, make, options):
    import worker
    from retest_contract import RETEST_REASON_IDENTITY, extract_auth_context

    handler, origin = shop
    finding = make(origin)
    with pytest.raises(findings_router.HTTPException) as refused:
        _enqueue(monkeypatch, finding, options)
    assert refused.value.status_code == 400 and refused.value.detail["reason"] == RETEST_REASON_IDENTITY
    inputs = findings_router.extract_retest_inputs(finding)
    # As an earlier release queued it: the Scan-level identity it could carry, which is none.
    verification = _verification(finding, inputs, options=options, auth_context=extract_auth_context(options))
    assert retest_identity_unresolved(verification)
    result = asyncio.run(worker.run_finding_retest(verification))
    assert (result["verdict"], result["verdict_reason"]) == ("inconclusive", IDENTITY_UNRESOLVED_REASON)
    assert handler.log == []


def test_a_scan_signed_in_with_a_raw_header_is_retested_as_that_identity(monkeypatch, shop):
    """Control: an older Scan's raw header travels with its retest, which then runs signed in."""
    import worker

    handler, origin = shop
    finding = _proven(origin)
    options = {"scan_type": "full", "auth_header": FIXTURE_SESSION}
    inputs, inserted = _enqueue(monkeypatch, finding, options)
    verification = _verification(finding, inputs, options=options, auth_context=inserted[14])
    assert not retest_identity_unresolved(verification)
    result = asyncio.run(worker.run_finding_retest(verification))
    assert (result["verdict"], result["result_status"]) == ("exploited", "still_vulnerable")
    assert handler.log and all(signed_in for _path, signed_in in handler.log)


# --- such a finding is not offered a retest, and none is queued for it ---------------------------

class _DetailConn:
    """Unit fixture connection for the finding detail: the source Scan's stored options."""

    def __init__(self, options):
        self.options = options

    async def fetchrow(self, query, *_args):
        if "FROM scans" in query:
            return {"options": json.dumps(self.options)}
        return None

    async def fetch(self, *_args):
        return []


def _detail(monkeypatch, row: dict, options: dict) -> dict:
    @asynccontextmanager
    async def acquire():
        yield _DetailConn(options)

    class _Pool:
        def acquire(self):
            return acquire()

    async def record(_conn, _finding_id):
        return dict(row)

    async def no_exposures(_conn, _finding):
        return []

    monkeypatch.setattr(findings_router, "_pool_provider", lambda: _Pool())
    monkeypatch.setattr(findings_router, "get_finding_record", record)
    monkeypatch.setattr(findings_router, "related_exposures", no_exposures)
    monkeypatch.setattr(findings_router, "_load_effective_ai_settings", lambda: {})
    return asyncio.run(findings_router.get_finding(str(FINDING)))


def _passive(tool: str, title: str) -> dict:
    return {"id": FINDING, "scan_id": SCAN, "target_id": None, "tool": tool, "title": title,
            "severity": "medium", "status": "active", "source": "dast",
            "target_url": "https://app.fixture.invalid", "url": "https://app.fixture.invalid/",
            "evidence": {}}


DETAIL_ROWS = {
    "proof": lambda: _proven("http://shop.fixture.invalid"),
    "ladder": lambda: _sqlmap("http://shop.fixture.invalid"),
    "exposed_file": lambda: _passive("exposed_files", "Exposed file: /.git/config"),
    "cors": lambda: _passive("cors_check", "CORS misconfiguration: credentials with reflected origin"),
}


@pytest.mark.parametrize("make", DETAIL_ROWS.values(), ids=DETAIL_ROWS.keys())
def test_a_signed_in_scans_finding_of_any_type_is_not_offered_a_retest(monkeypatch, make):
    from retest_contract import RETEST_IDENTITY_MESSAGE, RETEST_REASON_IDENTITY

    offered = _detail(monkeypatch, make(), ANONYMOUS_SCAN_OPTIONS)
    assert offered["retest_supported"] is True  # control: the same row from an anonymous Scan
    for options in (MANAGED_SCAN_OPTIONS, *LEGACY_SIGNED_IN_OPTIONS.values()):
        result = _detail(monkeypatch, make(), options)
        assert (result["retest_supported"], result["retest_modes"]) == (False, [])
        assert result["retest_unsupported_reason"] == RETEST_REASON_IDENTITY
        assert result["retest_unsupported_message"] == RETEST_IDENTITY_MESSAGE
        # The options decide the hint and are never returned.
        assert "fixture-password" not in json.dumps(result, default=str)
        assert "credential_profile_refs" not in json.dumps(result, default=str)


def test_a_bulk_retest_skips_a_signed_in_scans_finding_and_queues_nothing(monkeypatch):
    from retest_contract import RETEST_REASON_IDENTITY

    class _BulkConn(_EnqueueConn):
        async def fetchval(self, *_args):
            return None

    conn = _BulkConn(MANAGED_SCAN_OPTIONS)

    @asynccontextmanager
    async def acquire():
        yield conn

    class _Pool:
        def acquire(self):
            return acquire()

    class _Redis:
        def ping(self):
            return True

    async def record(_conn, _finding_id):
        return dict(_proven("http://shop.fixture.invalid"))

    async def no_receipt(*_a, **_k):
        return None

    async def admitted(*_a, **_k):
        raise AssertionError("a refused retest is never admitted")

    monkeypatch.setattr(findings_router, "_pool_provider", lambda: _Pool())
    monkeypatch.setattr(findings_router, "get_redis", lambda: _Redis())
    monkeypatch.setattr(findings_router, "get_finding_record", record)
    monkeypatch.setattr(findings_router, "_require_approval_receipt_if_policy_enabled", no_receipt)
    monkeypatch.setattr(findings_router, "_validate_approval_receipt_for_action", no_receipt)
    monkeypatch.setattr(findings_router, "admit_retest", admitted)
    monkeypatch.setattr(findings_router, "_record_blocked_command_result", no_receipt)
    result = asyncio.run(findings_router.bulk_retest_findings(
        findings_router.FindingsBulkRetestRequest(finding_ids=[str(FINDING)])))
    assert (result["status"], result["queued"]) == ("blocked", [])
    assert result["skipped"] == [{"finding_id": str(FINDING), "reason": RETEST_REASON_IDENTITY}]
    assert conn.inserts == []


@pytest.mark.parametrize("options", [MANAGED_SCAN_OPTIONS, *LEGACY_SIGNED_IN_OPTIONS.values()])
def test_no_automatic_retest_is_queued_for_a_signed_in_scans_findings(monkeypatch, options):
    import worker

    rows = [{**_proven("http://shop.fixture.invalid"), "id": uuid.uuid4(), "verification_count": 0,
             "last_verification_verdict": None},
            {**_passive("exposed_files", "Exposed file: /.git/config"), "id": uuid.uuid4(),
             "verification_count": 0, "last_verification_verdict": None, "severity": "high"}]
    admitted: list = []
    counts = _auto_queue(monkeypatch, worker, rows, options, admitted)
    assert counts == {"queued": 0, "skipped": 2} and admitted == []
    # Control: the same findings of an anonymous Scan reach admission.
    counts = _auto_queue(monkeypatch, worker, rows, ANONYMOUS_SCAN_OPTIONS, admitted)
    assert len(admitted) == 2


def _auto_queue(monkeypatch, worker, rows, options, admitted) -> dict:
    class Conn:
        async def fetchrow(self, _query, *_args):
            return {"options": json.dumps(options)}

        async def fetch(self, _query, *_args):
            return [dict(row) for row in rows]

        async def fetchval(self, _query, *_args):
            return None

        async def execute(self, query, *_args):
            raise AssertionError(f"nothing is queued: {query[:40]}")

    class Pool:
        def acquire(self):
            class _Acquire:
                async def __aenter__(self):
                    return Conn()

                async def __aexit__(self, *_exc):
                    return False
            return _Acquire()

    async def admit(_conn, **kwargs):
        admitted.append(kwargs["destination"])
        return None, "outside the fixture scope"

    async def running(_conn, _scan_id):
        return False

    policy = dataclasses.replace(
        worker.VerificationPolicy.from_env(overrides={}), auto_retest_enabled=True,
        auto_retest_max_per_scan=5, verification_min_severity="low")
    monkeypatch.setattr(worker.VerificationPolicy, "from_env", classmethod(lambda cls, overrides=None: policy))
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})
    monkeypatch.setattr(worker, "db_pool", Pool())
    monkeypatch.setattr(worker, "get_redis", lambda: object())
    monkeypatch.setattr(worker, "scan_stopped_by_authority", running)
    monkeypatch.setattr(worker, "admit_retest", admit)
    return asyncio.run(worker.queue_auto_retests_for_scan(str(SCAN), None, "http://shop.fixture.invalid"))


# --- a Hunt claim whose evidence was sent signed in ----------------------------------------------
# The autonomous agent queues deterministic retests of its own candidates. A claim proven with
# ``http_request`` as a signed-in principal (``as_principal``) has no identity a retest can send,
# so it is never queued for one, and a retest that reaches the worker sends nothing. Unit fixtures.
CANDIDATE = uuid.UUID("66666666-6666-4666-8666-666666666666")


def _agent_router():
    from agent_routes import router as agent_router

    return agent_router


def _http_result(principal: str) -> dict:
    return {"ok": True, "provenance": "tool",
            "request": {"method": "GET", "origin": "http://shop.fixture.invalid", "path": "/product",
                        "query_keys": ["id"], "as_principal": principal},
            "response": {"status": 500, "body_excerpt": "sqlite3.OperationalError: unrecognized token"}}


def test_the_gate_records_the_principals_a_claims_own_evidence_was_sent_as():
    agent_router = _agent_router()
    tools = agent_router.agent_tools
    signed, guest = _http_result("user1"), _http_result("anonymous")
    state = {
        "findings": [
            {"title": "SQL injection", "family": "sqli", "severity": "high", "evidence_refs": ["resp_1"]},
            {"title": "SQL injection", "family": "sqli", "severity": "high", "evidence_refs": ["resp_2"]},
            {"title": "SQL injection", "family": "sqli", "severity": "high",
             "evidence_refs": ["resp_2", "resp_1", "resp_9"]},
        ],
        "evidence_by_ref": {ref: tools.http_evidence_item(item["request"], item["response"])
                            for ref, item in (("resp_1", signed), ("resp_2", guest))},
        "results_store": {"resp_1": signed, "resp_2": guest},
    }
    entries = agent_router._agent_finalize_gate(state)
    assert [entry["evidence_principals"] for entry in entries] == [["user1"], [], ["user1"]]


def test_a_candidate_records_the_signed_in_principals_behind_its_claim(monkeypatch):
    agent_router = _agent_router()
    tools = agent_router.agent_tools
    executed: list = []

    class Conn:
        async def execute(self, query, *args):
            executed.append((query, args))

    async def upsert(_conn, _candidate, **_kwargs):
        return {"id": str(CANDIDATE), "inserted": True, "status": "new"}

    monkeypatch.setattr(agent_router.investigation_candidates, "upsert_candidate", upsert)
    monkeypatch.setattr(agent_router, "_provision_same_origin_url", lambda base, path: base.rstrip("/") + path)
    signed = _http_result("user1")
    finding = {"title": "SQL injection", "family": "sqli", "severity": "high", "param": "id", "payload": "'",
               "details": "error-based", "evidence_refs": ["resp_1"],
               "evidence": [tools.http_evidence_item(signed["request"], signed["response"])]}
    for principals, expected in ((["user1"], ["user1"]), ((), None)):
        executed.clear()
        asyncio.run(agent_router._persist_agent_suspected_finding(
            Conn(), TARGET, "http://shop.fixture.invalid", dict(finding), {"provenance": "tool"},
            run_receipt_id=None, research_episode_id=None, agent_hunt_run_id=None, known_keys=set(),
            evidence_principals=principals))
        (context,) = [json.loads(args[1]) for query, args in executed if "UPDATE investigation_candidates" in query]
        # Merged into the stored context: an anonymous claim never clears an earlier signed-in one.
        assert context.get("evidence_principals") == expected


def test_a_signed_in_claim_is_not_queued_for_a_retest(monkeypatch):
    agent_router = _agent_router()
    inserted: list = []
    context = {"retest_type": "sqli", "parameter": "id", "payload": "'", "method": "GET",
               "target_url": "http://shop.fixture.invalid/product?id=1"}

    class Conn:
        def __init__(self, row):
            self.row = row

        async def fetchrow(self, query, *_args):
            return self.row if "FROM investigation_candidates" in query else None

        async def execute(self, query, *args):
            if "INSERT INTO finding_verifications" in query:
                inserted.append(args)

    def run(candidate_context):
        row = {"id": CANDIDATE, "family": "sqli", "verifier_contract_id": "web.sqli",
               "verification_context": json.dumps(candidate_context)}

        @asynccontextmanager
        async def acquire():
            yield Conn(row)

        class _Pool:
            def acquire(self):
                return acquire()

        class _Redis:
            def ping(self):
                return True

        async def approval(*_a, **_k):
            return {}

        async def admitted(*_a, **_k):
            return {"fixture": True}, None

        monkeypatch.setattr(agent_router, "_pool_provider", lambda: _Pool())
        monkeypatch.setattr(agent_router, "get_redis", lambda: _Redis())
        monkeypatch.setattr(agent_router, "_validate_approval_receipt_for_action", approval)
        monkeypatch.setattr(agent_router, "admit_retest", admitted)
        monkeypatch.setattr(agent_router, "admitted_authority_json", lambda _a: "{}")
        monkeypatch.setattr(agent_router, "enqueue_job", lambda *_a, **_k: None)
        return asyncio.run(agent_router._agent_auto_queue_dast_retests(
            [{"id": str(CANDIDATE), "persisted": "created", "existing_status": None}],
            target_uuid=TARGET, approval_receipt_id=str(uuid.UUID(int=5)), created_by="unit-test"))

    assert run({**context, "evidence_principals": ["user1"]}) == [] and inserted == []
    # Control: the same claim gathered anonymously is queued for its deterministic retest.
    queued = run(context)
    assert len(queued) == 1 and len(inserted) == 1


def _candidate_verification(origin: str, principals) -> dict:
    """A candidate retest row as ``process_finding_retest_job`` reads it: no finding is linked, so
    its ``evidence`` is the candidate's ``verification_context``."""
    url = f"{origin}/product?id=1"
    context = {"target_url": url, "method": "GET", "parameter": "id", "retest_type": "sqli",
               **({"evidence_principals": principals} if principals else {})}
    return {
        "id": uuid.uuid4(), "finding_id": None, "candidate_id": CANDIDATE, "scan_id": None,
        "target_id": TARGET, "tool": "investigation_candidate", "title": "SQL injection",
        "severity": "high", "evidence": json.dumps(context), "finding_url": url, "target_url": url,
        "finding_type": "sqli", "original_url": url, "param": "id", "method": "GET",
        "candidate_family": "sqli", "source_scan_target_url": None, "source_scan_type": None,
        "source_scan_options": None, "auth_context": None,
    }


def test_a_candidate_whose_evidence_was_sent_signed_in_is_never_retested_anonymously(shop):
    import worker
    from worker_handlers.retest_identity import CANDIDATE_IDENTITY_UNRESOLVED_REASON

    handler, origin = shop
    verification = _candidate_verification(origin, ["user1"])
    assert retest_identity_unresolved(verification)
    result = asyncio.run(worker.run_finding_retest(verification))
    assert (result["verdict"], result["verdict_reason"]) == ("inconclusive", CANDIDATE_IDENTITY_UNRESOLVED_REASON)
    assert handler.log == []
    # Control: a claim gathered anonymously is retested, and meets the guest page this rule is for.
    verification = _candidate_verification(origin, None)
    assert not retest_identity_unresolved(verification)
    asyncio.run(worker.run_finding_retest(verification))
    assert handler.log and not any(signed_in for _path, signed_in in handler.log)
