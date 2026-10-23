"""Every way a finding retest can start is bound to what admitted it and watched while it runs.

The live behaviour (admission, a revoke mid-run, expiry, scope change, an unreachable database,
upgrade and requeue) is exercised against PostgreSQL in
``tests/test_retest_running_authority_postgres.py``. This module holds the inventory: each entry
point either reaches a queued ``finding_verifications`` row that records ``admitted_authority``
and is executed only by ``process_finding_retest_job`` (which opens the running authority before
any prover), or is shown not to start a finding retest at all.
"""
from __future__ import annotations

import ast
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import re
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

import worker  # noqa: E402
import worker_queue_policy  # noqa: E402

API = ROOT / "api"
_INSERT = re.compile(r"INSERT INTO finding_verifications\s*\((.*?)\)\s*VALUES\s*\((.*?)\)", re.S | re.I)


def _queued_inserts() -> list[tuple[str, str]]:
    found = []
    for path in sorted(API.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in _INSERT.finditer(text):
            if "'queued'" in match.group(2):
                found.append((str(path.relative_to(ROOT)), match.group(1)))
    return found


def test_every_queued_retest_records_what_admitted_it():
    """The UI/API routes (single and bulk, and through them Arsenal, the refuter executor and
    research episodes), automatic retests after a Scan, and candidate retests."""
    inserts = _queued_inserts()
    files = {path for path, _columns in inserts}
    # An AI Gate finding replay (POST /ai/findings/{id}/retest) records its verification row and
    # runs as an AI scan, watched by that scan's running authority (the receipt is in its options).
    assert files == {"api/finding_routes/router.py", "api/worker.py", "api/agent_routes/router.py",
                     "api/ai_targets/router.py"}, files
    for path, columns in inserts:
        if path != "api/ai_targets/router.py":
            assert "admitted_authority" in columns, path


def _calls(path: Path, function: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function:
            return {ast.unparse(call.func) for call in ast.walk(node) if isinstance(call, ast.Call)}
    raise AssertionError(f"{function} not found in {path}")


def test_an_ai_gate_replay_runs_as_a_watched_ai_scan():
    ai = API / "ai_targets" / "router.py"
    text = ai.read_text(encoding="utf-8")
    assert 'worker_options["ai_finding_retest"] = replay_plan' in text
    # The approval the replay was admitted with travels in the scan options, which
    # running_scan_authority watches for AI run kinds.
    import inspect
    from scan import running_scan_authority as running
    assert "approval_receipt_id" in inspect.getsource(running.running_scan_authority)


def test_arsenal_refuter_and_research_retests_go_through_the_findings_route():
    arsenal = API / "arsenal_routes" / "router.py"
    assert "_finding_routes.retest_finding" in _calls(arsenal, "_arsenal_dispatch_finding_retest")
    assert "_finding_routes.retest_finding" in _calls(arsenal, "_execute_refuter_review_plan")
    # Research episodes dispatch finding.retest through the Arsenal adapter table.
    text = arsenal.read_text(encoding="utf-8")
    assert '"finding.retest": _arsenal_dispatch_finding_retest' in text


def test_the_worker_opens_the_running_authority_before_any_prover():
    source = (API / "worker.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    body = next(node for node in ast.walk(tree)
                if isinstance(node, ast.AsyncFunctionDef) and node.name == "process_finding_retest_job")
    lines: dict[str, list[int]] = {}
    for node in ast.walk(body):
        if isinstance(node, ast.Call):
            lines.setdefault(ast.unparse(node.func), []).append(node.lineno)
    opened = min(lines["open_retest_authority"])
    assert opened < min(lines["run_finding_retest"])
    assert opened < min(lines["ai_verify_finding"])
    # The watch is entered as a context around both tiers.
    withs = [node for node in ast.walk(body) if isinstance(node, ast.AsyncWith)
             and ast.unparse(node.items[0].context_expr) == "run_authority"]
    assert len(withs) == 1
    inner = {ast.unparse(call.func) for call in ast.walk(withs[0]) if isinstance(call, ast.Call)}
    assert {"run_finding_retest", "ai_verify_finding"} <= inner


def test_retest_jobs_reach_only_the_watched_handler_on_every_worker_including_fleet_nodes():
    # A fleet node runs this worker; every general worker consumes the retest queue.
    selected = worker_queue_policy.base_worker_queue_keys(
        device_only=False, agent_tool_only=False, device_queue_enabled=True,
        scan_queue="scan_jobs", retest_queue="retest_jobs", broker_queue="broker_jobs",
        device_queue="device_jobs", agent_tool_queue="agent_tool_jobs")
    assert "retest_jobs" in selected
    source = (API / "worker.py").read_text(encoding="utf-8")
    assert source.count("await process_finding_retest_job(") == 1


def test_no_hunt_capability_or_mcp_tool_queues_a_finding_retest():
    """A Hunt verifies its own candidates with ``candidate.verify``, an inline workflow checked at
    each dispatch like every Hunt action (not a queued finding retest). Candidate retests the
    agent routes queue are bound (see the insert inventory). MCP runs Arsenal read-only."""
    registry = (API / "runtime" / "capability_registry.py").read_text(encoding="utf-8")
    assert '"finding.retest"' not in registry
    mcp = (ROOT / "scripts" / "shakerscan_mcp.py").read_text(encoding="utf-8")
    assert '"execute": False' in mcp or "'execute': False" in mcp


def test_the_installed_cli_has_no_retest_command():
    cli = (ROOT / "client" / "src" / "shakerscan").rglob("*.py")
    assert not any("/retest" in path.read_text(encoding="utf-8") for path in cli)


def test_a_slot_wait_requeue_keeps_the_approval_an_earlier_engine_put_in_the_message(monkeypatch):
    queued = []

    class Redis:
        def hset(self, *_a, **_k):
            return None

        def expire(self, *_a):
            return None

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(worker, "get_redis", lambda: Redis())
    monkeypatch.setattr(worker, "_try_acquire_retest_slot", lambda _r: False)
    monkeypatch.setattr(worker, "enqueue_job", lambda _r, _q, payload: queued.append(payload))
    monkeypatch.setattr(worker.asyncio, "sleep", no_sleep)
    approval, scope = str(uuid.uuid4()), "scope-" + uuid.uuid4().hex
    payload = worker.build_retest_job_payload(
        job_id=str(uuid.uuid4()), verification_id=str(uuid.uuid4()), finding_id=str(uuid.uuid4()),
        submitted_at=datetime.now(timezone.utc).isoformat(), trigger="api")
    payload.update({"approval_receipt_id": approval, "scope_receipt_id": scope})
    asyncio.run(worker.process_finding_retest_job(payload))
    assert queued and queued[0]["approval_receipt_id"] == approval and queued[0]["scope_receipt_id"] == scope


def test_automatic_retests_after_a_scan_skip_findings_only_the_ai_tier_could_answer(monkeypatch):
    """Unit fixtures: a Deep Hunt promotion (generic_http) and an earlier scanner's 2FA bypass have
    no deterministic prover, so their automatic retest could never conclude; a reflected XSS
    still reaches admission."""
    import dataclasses

    def row(title, tool):
        return {"id": uuid.uuid4(), "title": title, "tool": tool, "severity": "high", "status": "active",
                "url": "https://app.fixture.invalid/search?q=1", "target_url": "https://app.fixture.invalid",
                "evidence": {}, "target_id": None, "scan_id": None, "verification_count": 0,
                "last_verification_verdict": None}

    hunt = row("Verified stored cross-site scripting", "autonomous_workflow")
    twofa = row("2FA bypass via OTP reuse", "")
    xss = row("Verified cross-site scripting", "dalfox")

    class Conn:
        async def fetchrow(self, _query, *_args):
            return {"options": "{}"}

        async def fetch(self, _query, *_args):
            return [hunt, twofa, xss]

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

    admitted = []

    async def admit(_conn, **kwargs):
        admitted.append(kwargs["destination"])
        return None, {"error": "outside the fixture scope"}

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
    counts = asyncio.run(worker.queue_auto_retests_for_scan(
        str(uuid.uuid4()), None, "https://app.fixture.invalid"))
    assert counts == {"queued": 0, "skipped": 3}
    assert admitted == ["https://app.fixture.invalid/search?q=1"]
