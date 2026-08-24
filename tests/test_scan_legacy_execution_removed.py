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
