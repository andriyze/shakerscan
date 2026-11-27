from __future__ import annotations

from pathlib import Path

from api.scan.orchestrator import ScanOrchestrator


ROOT = Path(__file__).resolve().parents[1]


def test_local_and_broker_execute_the_same_persisted_action_plan():
    local = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    broker = (ROOT / "api" / "broker_worker.py").read_text(encoding="utf-8")

    assert "ScanOrchestrator" in local
    assert "ScanOrchestrator" in broker
    assert "_execute_reserved_deterministic_scan" in local
    assert "_execute_broker_action_plan" in broker
    assert ScanOrchestrator.plan_schema_version == "scan-action-plan/v1"
