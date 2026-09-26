"""The Command Arsenal bridge preserves the AI Boundary route contracts."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

import api.arsenal_routes.router as arsenal


@pytest.mark.asyncio
async def test_boundary_commands_dispatch_to_canonical_handlers(monkeypatch):
    calls = []

    async def compile_handler(request):
        calls.append(("compile", request))
        return {"proposal": {"status": "needs_context"}, "execution_enabled": False}

    async def materialize_handler(request):
        calls.append(("materialize", request))
        return {"materialization": {}, "execution_enabled": False}

    async def verify_handler(target_id, request):
        calls.append(("verify", target_id, request))
        return {"status": "queued", "scan_id": "scan-id"}

    monkeypatch.setattr(arsenal._ai_targets, "compile_ai_boundary_hypothesis", compile_handler)
    monkeypatch.setattr(arsenal._ai_targets, "materialize_ai_boundary_proposal", materialize_handler)
    monkeypatch.setattr(arsenal._ai_targets, "verify_ai_boundary_proposal", verify_handler)

    readonly = arsenal._arsenal_readonly_adapters()
    gated = arsenal._arsenal_gated_adapters()
    assert (await readonly["ai.boundary.hypothesis.compile"]({"hypothesis": {"version": 1}}))[
        "execution_enabled"
    ] is False
    assert (await readonly["ai.boundary.proposal.materialize"]({
        "proposal": {"status": "ready"}, "boundary_base": {"contract": "base"},
    }))["execution_enabled"] is False
    assert (await gated["ai.boundary.verify"]({
        "target_id": "target-id", "proposal": {"status": "ready"},
        "boundary_base": {"contract": "base"}, "approval_receipt_id": "stale",
    }, "approved"))["status"] == "queued"

    assert calls[0][1].hypothesis == {"version": 1}
    assert calls[1][1].boundary_base == {"contract": "base"}
    assert calls[2][1] == "target-id"
    assert calls[2][2].approval_receipt_id == "approved"
    assert calls[2][2].environment == "preview"
    assert calls[2][2].scan_profile == "standard"


@pytest.mark.asyncio
async def test_boundary_commands_reject_missing_required_objects_before_dispatch():
    readonly = arsenal._arsenal_readonly_adapters()
    gated = arsenal._arsenal_gated_adapters()
    with pytest.raises(HTTPException) as compile_error:
        await readonly["ai.boundary.hypothesis.compile"]({})
    assert compile_error.value.status_code == 422
    with pytest.raises(HTTPException) as materialize_error:
        await readonly["ai.boundary.proposal.materialize"]({"proposal": {}})
    assert materialize_error.value.status_code == 422
    with pytest.raises(HTTPException) as verify_error:
        await gated["ai.boundary.verify"]({"target_id": "target-id"}, None)
    assert verify_error.value.status_code == 422
