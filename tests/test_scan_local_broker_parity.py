from __future__ import annotations

import inspect

def test_local_and_broker_execute_the_same_persisted_action_plan():
    from scan.orchestrator import ScanOrchestrator
    import broker_worker
    import worker

    local = inspect.getsource(worker._execute_reserved_deterministic_scan)
    broker = (
        inspect.getsource(broker_worker.execute_lease)
        + inspect.getsource(broker_worker._execute_broker_action_plan)
    )
    assert "ScanOrchestrator" in local
    assert "ScanOrchestrator" in broker
    assert ScanOrchestrator.plan_schema_version == "scan-action-plan/v1"
