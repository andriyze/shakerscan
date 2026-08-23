from __future__ import annotations

import pytest


@pytest.mark.xfail(
    strict=True,
    reason="V2-P0-02: external adapter argv is not yet derived from the durable hold",
)
def test_external_execution_contract_requires_a_hard_reserved_wire_limit():
    from scan.capability_execution import ExternalExecutionContract

    contract = ExternalExecutionContract.from_reservation(
        capability_name="web.probe",
        reserved_budget={"http_requests": 3, "wall_time_seconds": 5},
    )
    assert contract.max_wire_requests == 3
    assert contract.argv_enforces_wire_limit is True
