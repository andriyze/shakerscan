from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_digestless_deterministic_scan_execution_is_absent_from_workers():
    worker = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    broker = (ROOT / "api" / "broker_worker.py").read_text(encoding="utf-8")

    assert not (ROOT / "api" / "scan" / "migration.py").exists()
    assert "require_legacy_scan_execution_window" not in worker
    assert "require_legacy_scan_execution_window" not in broker
    assert worker.count("digest-less deterministic Scan execution has been removed") == 2
    assert broker.count("digest-less deterministic Scan execution has been removed") == 1
    assert "canonical_action_authority is not None" in broker


def test_parallel_scan_documentation_names_the_canonical_action_graph():
    source = (ROOT / "api" / "parallel_scan.py").read_text(encoding="utf-8")

    assert "each shard executes its persisted canonical action graph" in source
    assert "each shard runs run_scan()" not in source


def test_normal_scheduler_has_no_digestless_queue_fallback():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    scheduler = source[
        source.index("async def run_due_schedules"):
        source.index("async def schedule_runner")
    ]

    assert '"normal schedule did not compile canonical Scan authority"' in scheduler
    assert "canonical_job.queue_payload(" in scheduler
    assert "'scheduled': True" not in scheduler
    assert '"v2" if canonical_schedule else "legacy"' not in scheduler
