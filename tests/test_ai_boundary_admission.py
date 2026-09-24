"""Real API model/catalog imports; run with scanner/requirements.lock installed."""

from __future__ import annotations

from pathlib import Path
import json

import pytest

from ai_gate.boundary import PACK
from ai_gate.boundary.contract import BoundaryContract
from ai_targets import router


def test_api_admission_includes_the_canonical_boundary_pack():
    assert PACK in router.AI_PROBE_PACKS
    request = router.AITargetScanRequest(probe_pack=PACK, scan_profile="standard", environment="staging")
    assert request.probe_pack == PACK


def test_shipped_example_uses_existing_principal_roles():
    raw = json.loads((Path(__file__).resolve().parents[1] / "examples/ai-boundary/customer-read-contract.json").read_text())
    contract = BoundaryContract.parse(raw)
    assert {contract.owner.role, contract.attacker.role} <= router.AI_PRINCIPAL_ROLES


@pytest.mark.asyncio
async def test_api_boundary_admission_does_not_bypass_normal_submission(monkeypatch):
    class ReachedNormalSubmission(Exception):
        pass

    def get_redis():
        # This is immediately after enum validation and before durable lookup.
        raise ReachedNormalSubmission

    monkeypatch.setattr(router, "get_redis", get_redis)
    with pytest.raises(ReachedNormalSubmission):
        await router._queue_ai_target_scan(
            "00000000-0000-0000-0000-000000000001",
            router.AITargetScanRequest(probe_pack=PACK, scan_profile="standard", environment="preview"))
