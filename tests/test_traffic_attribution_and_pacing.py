"""Declared run identification on every sender, and pacing that follows the target's health.

Fixtures only: no network. ``tests/test_target_pacing_postgres.py`` covers the archive queries.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import agent_tools  # noqa: E402
from runtime import target_pacing  # noqa: E402
from runtime.target_pacing import assess  # noqa: E402
from scanner_tools import credential_redirects, traffic_attribution as ta  # noqa: E402

SCAN = str(uuid.uuid4())
LABEL = f"scan:{SCAN}"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (ta.ENABLED_ENV, ta.USER_AGENT_ENV, ta.RUN_ENV):
        monkeypatch.delenv(name, raising=False)


# --- attribution ---------------------------------------------------------------------------

def test_a_run_label_names_only_a_scan_or_hunt_record_id():
    assert ta.run_label("scan", SCAN) == LABEL
    assert ta.run_label("HUNT", SCAN.upper()) == f"hunt:{SCAN}"
    for kind, value in (("scan", "not-a-uuid"), ("token", SCAN), ("scan", f"{SCAN}\r\nX: y")):
        assert ta.run_label(kind, value) is None


def test_the_header_follows_the_bound_run_and_its_switches(monkeypatch):
    assert ta.headers() == {}
    with ta.bound_run("scan", SCAN):
        assert ta.headers() == {ta.HEADER: LABEL}
        with ta.bound_run("scan", SCAN, enabled=False):  # the Scan's own switch
            assert ta.headers() == {}
        monkeypatch.setenv(ta.ENABLED_ENV, "off")  # the install's switch
        assert ta.headers() == {}
    monkeypatch.delenv(ta.ENABLED_ENV)
    monkeypatch.setenv(ta.RUN_ENV, LABEL)  # a child process
    assert ta.headers() == {ta.HEADER: LABEL}


def test_concurrent_runs_in_one_worker_never_mix_labels():
    other = str(uuid.uuid4())

    async def one(run_id, seen):
        with ta.bound_run("scan", run_id):
            await asyncio.sleep(0)
            seen.append(ta.headers()[ta.HEADER])

    async def both():
        seen_a, seen_b = [], []
        await asyncio.gather(one(SCAN, seen_a), one(other, seen_b))
        return seen_a, seen_b

    seen_a, seen_b = asyncio.run(both())
    assert seen_a == [LABEL] and seen_b == [f"scan:{other}"]


def test_curl_gets_the_header_and_the_user_agent_token(monkeypatch):
    with ta.bound_run("scan", SCAN):
        out = ta.curl_arguments(["curl", "-sS", "-H", "User-Agent: Mozilla/5.0", "https://t.test/"])
        assert out[1:3] == ["-H", f"{ta.HEADER}: {LABEL}"]
        assert "User-Agent: Mozilla/5.0 ShakerScan" in out
        assert ta.curl_arguments(out) == out  # idempotent
        bare = ta.curl_arguments(["curl", "-sS", "https://t.test/"])
        assert "-A" in bare and bare[bare.index("-A") + 1] == "curl ShakerScan"
    monkeypatch.setenv(ta.USER_AGENT_ENV, "")
    assert ta.curl_arguments(["curl", "https://t.test/"]) == ["curl", "https://t.test/"]
    assert ta.curl_arguments(["nuclei", "-u", "https://t.test/"]) == ["nuclei", "-u", "https://t.test/"]


def test_the_header_is_not_session_material_so_redirects_follow_as_before():
    cmd = ["curl", "-sS", "-L", "-H", f"{ta.HEADER}: {LABEL}", "https://t.test/"]
    assert not credential_redirects.curl_follows_with_credentials(cmd)


@pytest.mark.parametrize("tool,flag", [("nuclei", "-H"), ("katana", "-H"), ("ffuf", "-H"),
                                       ("dalfox", "--header"), ("httpx", "-H")])
def test_every_external_http_tool_carries_the_header(tool, flag):
    with ta.bound_run("scan", SCAN):
        _binary, argv, _timeout = agent_tools.build_scanner_argv(tool, "https://app.example.test/", {})
    assert f"{ta.HEADER}: {LABEL}" in argv
    assert argv[argv.index(f"{ta.HEADER}: {LABEL}") - 1] == flag
    _binary, argv, _timeout = agent_tools.build_scanner_argv(tool, "https://app.example.test/", {})
    assert not any(ta.HEADER in str(value) for value in argv)


def test_sqlmap_takes_the_header_inside_its_one_headers_value():
    with ta.bound_run("hunt", SCAN):
        _binary, argv, _timeout = agent_tools.build_scanner_argv(
            "sqlmap", "https://app.example.test/?q=1", {"technique": "B"},
            trusted_headers={"Cookie": "session=abcdef123456"})
    assert argv.count("--headers") == 1
    value = argv[argv.index("--headers") + 1]
    assert "Cookie: session=abcdef123456" in value and f"{ta.HEADER}: hunt:{SCAN}" in value


# --- pacing --------------------------------------------------------------------------------

def _rows(ok, bad=0, *, status=503, elapsed=40):
    return ([{"status_code": 200, "elapsed_ms": elapsed, "error": None}] * ok
            + [{"status_code": status, "elapsed_ms": elapsed, "error": None}] * bad)


def test_pacing_follows_the_share_of_degraded_answers():
    assert assess(_rows(5, 2)).state == "normal"  # too few answers to judge
    assert assess(_rows(20)).factor == 1.0
    assert assess(_rows(17, 3)).factor == 1.0
    assert assess(_rows(16, 4)).factor == 0.5
    assert assess(_rows(10, 10)).factor == 0.25
    paused = assess(_rows(2, 18))
    assert paused.state == "paused" and paused.factor == 0.0 and "18 of the last 20" in paused.reason
    # A host answering 503 on every path pauses; it is not a failed Scan.
    assert assess(_rows(0, 30)).state == "paused"
    # 501 (not implemented) is an answer, not a struggling target.
    assert assess(_rows(0, 20, status=501)).factor == 1.0
    errors = [{"status_code": None, "elapsed_ms": None, "error": "ConnectTimeout"}] * 20
    assert assess(errors).state == "paused"


def test_throttling_and_slowness_slow_the_scan():
    assert assess(_rows(13, 7, status=429)).factor == 0.25
    slow = assess(_rows(20, elapsed=400), baseline_ms=50)
    assert slow.factor == 0.5 and "8.0x" in slow.reason
    assert assess(_rows(20, elapsed=120), baseline_ms=50).factor == 1.0


def _plan(tool, factor=None):
    options = {"_batch_attempt": True}
    if tool == "nuclei":
        options.update({"template_profile": "active", "template_ids": "a,b", "severity": "high"})
    if factor is not None:
        options["_pacing_factor"] = factor
    paths = {"sqlmap_output_dir": "/tmp/sqlmap-scratch"} if tool == "sqlmap" else None
    return agent_tools.build_enforced_scanner_plan(
        tool, "https://app.example.test/search?q=1", options,
        reserved_budget={"http_requests": 400, "tool_wall_seconds": 60}, runtime_paths=paths)


def test_the_pacing_factor_lowers_each_tools_rate_and_never_raises_it():
    def rate(plan):
        argv = list(plan.argv)
        return float(argv[argv.index("-rate-limit") + 1])

    def delay(plan):
        argv = list(plan.argv)
        return float(argv[argv.index("--delay") + 1])

    assert rate(_plan("nuclei", 0.25)) < rate(_plan("nuclei"))
    assert delay(_plan("sqlmap", 0.5)) == pytest.approx(delay(_plan("sqlmap")) * 2, rel=0.01)
    assert delay(_plan("dalfox", 0.5)) >= delay(_plan("dalfox")) * 2 - 1
    for bad in (0, 0.0, 1.5, -1, True, "0.5"):
        with pytest.raises(agent_tools.AgentToolError):
            _plan("nuclei", bad)


class _FakePool:
    """Answers the two pacing reads from a scripted list of decisions' rows."""

    def __init__(self, batches):
        self.batches, self.recorded = list(batches), []

    def acquire(self):
        pool = self

        class _Conn:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def fetch(self, _sql, *args):
                return pool.batches.pop(0) if len(pool.batches) > 1 else pool.batches[0]

            async def fetchval(self, _sql, *args):
                return None

            async def execute(self, _sql, *args):
                pool.recorded.append(args[3])

        return _Conn()


def test_a_paused_attempt_waits_then_runs_slower_or_stops_without_failing_the_scan():
    async def no_sleep(_seconds):
        return None

    recovered = _FakePool([_rows(0, 20), _rows(0, 20), _rows(16, 4)])
    decision = asyncio.run(target_pacing.pace_attempt(
        recovered, SCAN, "https://app.example.test/x", wall_seconds=60, sleep=no_sleep))
    assert decision.factor == 0.5 and recovered.recorded == ["attempts_paused"]

    down = _FakePool([_rows(0, 20)])
    with pytest.raises(target_pacing.TargetDegraded, match="target_degraded"):
        asyncio.run(target_pacing.pace_attempt(
            down, SCAN, "https://app.example.test/x", wall_seconds=60, sleep=no_sleep))
    assert down.recorded == ["attempts_paused", "attempts_stopped"]

    options = asyncio.run(target_pacing.pace_scanner_options(
        _FakePool([_rows(10, 10)]), {"scan_id": SCAN}, {"a": 1}, "https://app.example.test/",
        tool="nuclei", wall_seconds=60))
    assert options == {"a": 1, "_pacing_factor": 0.25}
    # A Hunt job or a posture tool is not paced here; a broken database paces nothing.
    assert asyncio.run(target_pacing.pace_scanner_options(
        None, {"scan_id": SCAN}, {"a": 1}, "https://x.test/", tool="nmap", wall_seconds=60)) == {"a": 1}

    class _Broken:
        def acquire(self):
            raise ConnectionError("database unavailable")

    assert asyncio.run(target_pacing.pace_attempt(
        _Broken(), SCAN, "https://x.test/", wall_seconds=60)).factor == 1.0
