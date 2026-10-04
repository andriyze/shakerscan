"""The benchmark must wait as long as the scan it submitted is allowed to run.

All three fixtures run the thorough profile, whose server ceiling is 10,800 seconds, but the runner
stopped polling after a fixed 2,400. It then fetched ``/result`` for a still-running scan, got a
404, and wrote ``{"error": "HTTP Error 404..."}`` -- an opaque failure for a scan that was simply not
finished, which nobody cancelled. The wait now comes from the scan's own resolved ceiling (read from
the server) plus a margin, ``--timeout`` still overrides it, and an unfinished scan yields an
explicit ``timed_out_waiting`` card, cancelled only on ``--cancel-on-timeout``.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import time as real_time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCAN_ID = "11111111-2222-3333-4444-555555555555"
THOROUGH_SECONDS = 10_800


def _benchmark():
    path = ROOT / "scripts" / "benchmark_targets.py"
    spec = importlib.util.spec_from_file_location("benchmark_wait_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


b = _benchmark()


class FakeClock:
    """Simulated time, so a three-hour wait runs instantly."""

    def __init__(self):
        self.now = 1_000_000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.now += seconds

    def __getattr__(self, name):  # strftime, gmtime, ... for main()
        return getattr(real_time, name)


class FakeServer:
    """The read/write surface the runner uses, with a scan that finishes at a chosen time."""

    def __init__(self, clock, *, finishes_after=None, submit_budget=THOROUGH_SECONDS,
                 budget_json=None, contract_seconds=None):
        self.clock = clock
        self.started = clock.now
        self.finishes_after = finishes_after
        self.submit_budget = submit_budget
        self.budget_json = budget_json
        self.contract_seconds = contract_seconds
        self.cancelled = False
        self.result_fetches = 0
        self.posts = []

    def status(self):
        if self.cancelled:
            return "cancelled"
        if self.finishes_after is not None and self.clock.now - self.started >= self.finishes_after:
            return "completed"
        return "running"

    def get(self, url, timeout=30):
        if url.endswith("/result"):
            self.result_fetches += 1
            assert self.status() in b.TERMINAL_SCAN_STATUSES, "fetched /result of an unfinished scan"
            return {"findings": []}
        if url.endswith(f"/scans/{SCAN_ID}"):
            row = {"id": SCAN_ID, "status": self.status()}
            if self.budget_json is not None:
                row["budget_json"] = self.budget_json
            return row
        if url.endswith("/scan/contracts"):
            if self.contract_seconds is None:
                raise OSError("contract unavailable")
            return {"budget_profiles": {"thorough": {"max_duration_seconds": self.contract_seconds}}}
        raise AssertionError(f"unexpected GET {url}")

    def post(self, url, body, timeout=30):
        self.posts.append(url)
        assert url.endswith(f"/scans/{SCAN_ID}/cancel")
        self.cancelled = True
        return {"status": "cancelled"}

    def submit(self, *_args, **_kwargs):
        return {
            "scan_id": SCAN_ID, "two_user": False, "principal_validation": None,
            "budget_profile": "thorough", "max_duration_seconds": self.submit_budget,
        }


@pytest.fixture
def fixture_dir(tmp_path, monkeypatch):
    (tmp_path / "unit.yaml").write_text(
        "target_url: http://target.test\nexpected: []\ngates:\n  require_reliable_grade: false\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(b, "FIXTURE_DIR", str(tmp_path))
    return tmp_path


def _install(monkeypatch, server, clock):
    monkeypatch.setattr(b, "time", clock)
    monkeypatch.setattr(b, "_get", server.get)
    monkeypatch.setattr(b, "_post", server.post)
    monkeypatch.setattr(b, "submit_target", server.submit)


def test_a_thorough_scan_finishing_after_forty_minutes_is_waited_for_and_scored(
    monkeypatch, fixture_dir,
):
    clock = FakeClock()
    server = FakeServer(clock, finishes_after=5_000)  # past the old 2,400 s, inside the ceiling
    _install(monkeypatch, server, clock)

    out = b.run_target("unit", "http://api.test", None, False)

    assert "gates" in out and out.get("status") != "timed_out_waiting"
    assert server.result_fetches == 1
    assert out["wait"] == {
        "limit_seconds": THOROUGH_SECONDS + 1_080,
        "source": "scan_resolved_budget",
        "scan_duration_ceiling_seconds": THOROUGH_SECONDS,
        "margin_seconds": 1_080,
    }


def test_an_explicit_timeout_still_overrides_the_derived_wait(monkeypatch, fixture_dir):
    clock = FakeClock()
    server = FakeServer(clock, finishes_after=5_000)
    _install(monkeypatch, server, clock)

    out = b.run_target("unit", "http://api.test", 2_400, False)

    assert out["status"] == "timed_out_waiting"
    assert out["wait"] == {"limit_seconds": 2_400, "source": "explicit_timeout"}
    assert 2_400 <= out["waited_seconds"] < 2_400 + b.WAIT_POLL_SECONDS


def test_an_unfinished_scan_yields_an_explicit_card_not_a_404(monkeypatch, fixture_dir):
    clock = FakeClock()
    server = FakeServer(clock, finishes_after=None)
    _install(monkeypatch, server, clock)

    out = b.run_target("unit", "http://api.test", None, False)

    assert server.result_fetches == 0, "the result of a running scan must not be fetched"
    assert server.posts == [], "the scan is left running unless cancellation was asked for"
    assert out["status"] == "timed_out_waiting"
    assert out["scan_id"] == SCAN_ID
    assert out["scan_status"] == "running"
    assert out["scan_still_running"] is True
    assert out["passed"] is False
    assert out["cancellation"] is None
    assert "error" not in out
    assert out["waited_seconds"] >= THOROUGH_SECONDS + 1_080
    assert SCAN_ID in out["detail"]


def test_cancel_on_timeout_cancels_through_the_canonical_route(monkeypatch, fixture_dir):
    clock = FakeClock()
    server = FakeServer(clock, finishes_after=None)
    _install(monkeypatch, server, clock)

    out = b.run_target("unit", "http://api.test", 600, False, cancel_on_timeout=True)

    assert server.posts == [f"http://api.test/scans/{SCAN_ID}/cancel"]
    assert server.result_fetches == 0
    assert out["status"] == "timed_out_waiting"
    assert out["cancel_on_timeout"] is True
    assert out["cancellation"] == {
        "requested": True, "accepted": True, "error": None, "scan_status_after": "cancelled",
    }
    assert out["scan_status"] == "cancelled"
    assert out["scan_still_running"] is False


def test_the_ceiling_falls_back_to_the_scan_row_then_the_public_contract(monkeypatch):
    clock = FakeClock()
    server = FakeServer(clock, submit_budget=None, budget_json=json.dumps({"max_duration_seconds": 3_600}))
    monkeypatch.setattr(b, "_get", server.get)
    assert b.scan_duration_ceiling("http://api.test", SCAN_ID) == (3_600, "scan_resolved_budget")

    server.budget_json = None
    server.contract_seconds = 10_800
    assert b.scan_duration_ceiling("http://api.test", SCAN_ID, budget_profile="thorough") == (
        10_800, "scan_contract_profile:thorough",
    )

    server.contract_seconds = None
    with pytest.raises(RuntimeError, match="--timeout"):
        b.scan_duration_ceiling("http://api.test", SCAN_ID)


def test_the_margin_has_a_floor_for_short_ceilings():
    wait = b.resolve_wait("http://unused", SCAN_ID, submitted_seconds=1_800)
    assert wait["limit_seconds"] == 1_800 + b.WAIT_MARGIN_MIN_SECONDS


def test_scoring_an_unfinished_existing_scan_reports_it_instead_of_failing(
    monkeypatch, fixture_dir,
):
    clock = FakeClock()
    server = FakeServer(clock, finishes_after=None)
    _install(monkeypatch, server, clock)

    out = b.run_target("unit", "http://api.test", None, False, preset_scan_id=SCAN_ID)

    assert server.result_fetches == 0
    assert out["status"] == "scan_not_finished"
    assert out["scan_still_running"] is True
    assert out["waited_seconds"] == 0


def _smoke_benchmark_arguments():
    """The benchmark invocation exactly as installed_stack_smoke.sh (and so certify) runs it."""
    text = (ROOT / "scripts" / "installed_stack_smoke.sh").read_text(encoding="utf-8")
    match = re.search(
        r'python3 "\$ROOT_DIR/scripts/benchmark_targets.py" (.*?)\|\| benchmark_status', text, re.S,
    )
    assert match, "installed_stack_smoke.sh no longer invokes the benchmark"
    words = match.group(1).replace("\\\n", " ").split()
    substitutions = {"$API_PORT": "38001", "$JUICE_PORT": "44001"}
    arguments = []
    for word in words:
        word = word.strip('"')
        for name, value in substitutions.items():
            word = word.replace(name, value)
        arguments.append(word)
    return arguments


def test_the_installed_stack_smoke_invocation_uses_the_derived_wait(monkeypatch, tmp_path):
    arguments = _smoke_benchmark_arguments()
    assert "--timeout" not in arguments, "the smoke must inherit the scan's own ceiling"
    captured = {}

    def fake_run_target(name, api, timeout, do_auth, scan_id, **kwargs):
        captured.update(name=name, api=api, timeout=timeout, auth=do_auth, **kwargs)
        return {"target": name, "passed": True, "gates": []}

    monkeypatch.setattr(b, "OUT_DIR", str(tmp_path))
    monkeypatch.setattr(b, "check_fleet", lambda api: (True, {"count": 1, "stale": 0}))
    monkeypatch.setattr(b, "run_target", fake_run_target)
    monkeypatch.setattr(b, "_get", lambda url, timeout=30: {"source_revision": "a" * 40})
    monkeypatch.setattr(sys, "argv", ["benchmark_targets.py", *arguments])

    b.main()

    assert captured["name"] == "juice_shop"
    assert captured["api"] == "http://127.0.0.1:38001"
    assert captured["timeout"] is None
    assert captured["cancel_on_timeout"] is False
    assert captured["target_url_override"] == "http://juice-shop:3000"
    assert captured["auth_target_url_override"] == "http://127.0.0.1:44001"
