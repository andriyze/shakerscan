"""The Model Intake worker pool is consumed by the control plane, not just registered.

The dedicated worker registers in ``shakerscan:model_intake_worker_build`` (worker_queue_policy),
but until 2.2.0 nothing read it: a missing, stale, or tool-less Model Intake worker coexisted with a
successful startup while Model Intake jobs stayed queued. These tests exercise the readiness helper
against a fake registry and pin the /health and startup wiring.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FP = "f" * 64


class _Redis:
    def __init__(self, reports):
        self.reports = reports

    def hgetall(self, key):
        assert key == "shakerscan:model_intake_worker_build"
        return {host.encode(): json.dumps(report).encode() for host, report in self.reports.items()}


def _report(*, fingerprint=FP, tools=None, age_seconds=5):
    from api.worker_queue_policy import MODEL_INTAKE_WORKER_TOOL_COMMANDS

    reported = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    return {
        "build_fingerprint": fingerprint,
        "scanner_version": "2.2.0",
        "worker_kind": "model_intake",
        "tools": sorted(MODEL_INTAKE_WORKER_TOOL_COMMANDS) if tools is None else tools,
        "reported_at": reported.isoformat().replace("+00:00", "Z"),
    }


@pytest.fixture
def router():
    module = importlib.import_module("api.model_intake.router")
    yield module


def _configure(router, reports):
    router.configure_model_intake_router(
        lambda: None,
        get_redis=lambda: _Redis(reports),
        expected_build_fingerprint=lambda: FP,
        current_scanner_version=lambda: "2.2.0",
        worker_build_current=lambda *, reported_fingerprint, reported_version, expected_fingerprint, expected_version: (
            None if not reported_fingerprint else reported_fingerprint == expected_fingerprint
        ),
    )


def test_a_fresh_current_tool_complete_worker_is_ready(router):
    _configure(router, {"mi-1": _report()})
    state = router._model_intake_worker_readiness()
    assert state["status"] == "ready" and state["reason"] is None
    assert state["worker_count"] == state["capable_worker_count"] == 1
    assert state["queue_name"] == router.MODEL_INTAKE_QUEUE_NAME
    assert state["workers"][0]["missing_tools"] == []


def test_a_worker_from_the_plain_scanner_image_is_not_ready(router):
    # Registered, current build, but none of the toolchain paths the dedicated image installs.
    _configure(router, {"mi-1": _report(tools=["nuclei", "sqlmap"])})
    state = router._model_intake_worker_readiness()
    assert state["status"] == "not_ready"
    assert state["reason"] == "model_intake_worker_missing_toolchain"
    assert "trivy" in state["workers"][0]["missing_tools"]


def test_a_stale_build_or_an_old_report_is_not_ready(router):
    _configure(router, {"mi-1": _report(fingerprint="0" * 64)})
    assert router._model_intake_worker_readiness()["reason"] == "model_intake_worker_build_stale"
    _configure(router, {"mi-1": _report(age_seconds=100_000)})
    state = router._model_intake_worker_readiness()
    assert state["worker_count"] == 0
    assert state["reason"] == "no_fresh_model_intake_worker"


def test_health_and_startup_consume_the_pool():
    api = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    assert '"model_intake_worker": _model_intake_worker_readiness(),' in api
    assert "expected_build_fingerprint=lambda *a, **k: expected_build_fingerprint(*a, **k)," in api
    scanner_sh = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    verify = scanner_sh.split("verify_specialized_worker_identity() {", 1)[1].split("\n}", 1)[0]
    assert ".model_intake_worker.status" in verify


def test_the_model_intake_worker_reports_its_toolchain(monkeypatch, tmp_path):
    """The report is what readiness judges; the dedicated worker must list the toolchain paths."""
    monkeypatch.setenv("MODEL_INTAKE_ONLY_WORKER", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    import shutil
    from api import worker_queue_policy

    present = {"/opt/tools/trivy", "/opt/tools/semgrep", "nuclei"}
    monkeypatch.setattr(shutil, "which", lambda command: command if command in present else None)
    worker = importlib.import_module("api.worker")
    worker = importlib.reload(worker)
    _host, payload = worker._worker_build_report_payload()
    report = json.loads(payload)
    assert report["worker_kind"] == "model_intake"
    assert {"trivy", "semgrep", "nuclei"} <= set(report["tools"])
    assert "osv-scanner" not in report["tools"]
    assert set(worker_queue_policy.MODEL_INTAKE_WORKER_REQUIRED_TOOLS) == set(
        worker_queue_policy.MODEL_INTAKE_WORKER_TOOL_COMMANDS
    )


def test_worker_identity_is_heartbeated_while_the_main_loop_is_busy(monkeypatch):
    from api import worker_queue_policy

    reports = []
    sleeps = []

    async def one_interval_then_cancel(delay):
        sleeps.append(delay)
        if len(sleeps) > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(worker_queue_policy.asyncio, "sleep", one_interval_then_cancel)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker_queue_policy.heartbeat_worker_build_report(
            lambda: reports.append(True), interval_seconds=30,
        ))

    assert reports == [True]
    assert sleeps[0] == 30
