"""Real frozen-socket HTTP -> canonical authz proof -> existing finding bridge.

The queue/database boundary is a double; this is not full-stack or blind recall.
"""
import asyncio
import uuid

import pytest

from tests.test_authz_investigation_acceptance import base_url, USER_A, USER_B, EXPIRED
from tests.test_hunt_authz_findings import DB
from api.hunt.deterministic_findings import materialize_verified_hunt_findings
from capabilities.authz import verify_target_bound_object_authorization
from runtime.models import TargetBinding


@pytest.mark.parametrize("route,primary,secondary,expected", [
    ("/authz/vuln/orders", USER_A, USER_B, 1),
    ("/authz/safe/orders", USER_A, USER_B, 0),
    ("/authz/public/notices", USER_A, USER_B, 0),
    ("/authz/public/directory", USER_A, USER_B, 0),
    ("/authz/vuln/orders", USER_A, EXPIRED, 0),
    ("/authz/vuln/orders", USER_A, USER_A, 0),
])
def test_real_transport_controls_reach_materialization(base_url, route, primary, secondary, expected):
    target_id, hunt_id, action_id, receipt_id = (uuid.uuid4() for _ in range(4))
    target = TargetBinding(target_id=str(target_id), target_kind="web", canonical_host="127.0.0.1",
                           allowed_origins=(base_url,), allowed_addresses=("127.0.0.1",),
                           scope_receipt_id="loopback-fixture-only")
    captures = []
    async def run():
        outcome = await verify_target_bound_object_authorization(
            base_url, [route], target=target, primary_headers=primary,
            secondary_headers=secondary, transaction_recorder=captures.append,
        )
        db = DB()
        ids = await materialize_verified_hunt_findings(
            db, hunt_id, action_id, target_id, base_url, "authz.verify", receipt_id,
            {"routes": [route]}, [outcome["observation"]],
        )
        return outcome, ids, db
    outcome, ids, db = asyncio.run(run())
    assert len(ids) == expected, outcome
    assert outcome["budget_consumed"]["http_requests"] == len(captures)
    assert len(captures) <= 4
    if expected:
        assert outcome["observation"]["proof_state"] == "verified"
        assert len(captures) == 4
        assert any("finding_verifications" in sql for sql, _ in db.writes)
    else:
        assert outcome["observation"]["proof_state"] != "verified"
        assert not db.writes
