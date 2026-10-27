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
    inputs, inserted = _enqueue(monkeypatch, finding, MANAGED_SCAN_OPTIONS)
    # The queued retest carries no identity and no secret.
    assert FIXTURE_SESSION not in json.dumps([str(item) for item in inserted])
    verification = _verification(finding, inputs, options=MANAGED_SCAN_OPTIONS, auth_context=inserted[14])
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
    inputs, _inserted = _enqueue(monkeypatch, finding, MANAGED_SCAN_OPTIONS)
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
